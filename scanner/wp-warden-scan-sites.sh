#!/bin/bash
set -u
set -o pipefail

WRAPPER_VERSION="0.1.60"

REPO_ROOT="${WP_WARDEN_REPO_ROOT:-/root/wp-warden}"
INTEL_ROOT="${WP_WARDEN_INTEL_ROOT:-${REPO_ROOT}/wp-warden-intel}"
WARDEN=""
VIRTUAL_ROOT="${WP_WARDEN_VIRTUAL_ROOT:-/home/virtual}"
CWP_HOME_ROOT="${WP_WARDEN_CWP_HOME_ROOT:-/home}"
LOG_ROOT="${WP_WARDEN_LOG_ROOT:-/root/wp-warden/logs}"
LOG_RETENTION_DAYS=30
UPDATE_CHECK_INTERVAL="${WP_WARDEN_UPDATE_CHECK_INTERVAL:-21600}"
RUN_DATE="$(date +%Y-%m-%d)"
RUN_TIME="$(date +%H%M%S)"
RUN_LOG_DIR="${LOG_ROOT}/${RUN_DATE}"
RECENT_PHP_OPTION=""
RECOVER_MISSING_INTEL="${WP_WARDEN_RECOVER_MISSING_INTEL:-1}"
mkdir -p "$RUN_LOG_DIR"

usage(){ echo "Usage: $0 [--recent-php-days=N] (domain.com.au | --all) | --check-updates | --self-update"; exit 1; }
line(){ echo "======================================================================"; }
scan_scope_label(){
    if [ -n "$RECENT_PHP_OPTION" ]; then
        echo "recent PHP quick sweep (${RECENT_PHP_OPTION#*=} day(s); incomplete scan)"
    else
        echo "full file scan"
    fi
}
find_warden(){
    if [ -f "${REPO_ROOT}/scanner/wp-warden-pef.php" ]; then
        echo "${REPO_ROOT}/scanner/wp-warden-pef.php"
    else
        find "${REPO_ROOT}/scanner" -maxdepth 1 -type f -name 'wp-warden-pef-*.php' -printf '%f\n' 2>/dev/null | sort -V | tail -n 1 | sed "s#^#${REPO_ROOT}/scanner/#"
    fi
}
scanner_version_from_file(){
    sed -nE "s/^const WP_WARDEN_VERSION = ['\"]([^'\"]+)['\"];$/\1/p" "$1" 2>/dev/null | head -n 1
}
repo_git(){ (cd "$REPO_ROOT" && git "$@"); }
fetch_main(){ repo_git fetch "$@" origin main:refs/remotes/origin/main; }
github_scanner_file(){ repo_git ls-tree -r --name-only origin/main -- scanner/wp-warden-pef.php 2>/dev/null | head -n 1; }
github_scanner_version(){ repo_git show "origin/main:$1" 2>/dev/null | sed -nE "s/^const WP_WARDEN_VERSION = ['\"]([^'\"]+)['\"];$/\1/p" | head -n 1; }
site_root(){
    local PLATFORM="$1" SITE_ID="$2" ROOT="${3:-}"
    case "$PLATFORM" in
        apiscp)
            [ -n "$ROOT" ] && [ -f "$ROOT/wp-config.php" ] && { echo "$ROOT"; return 0; }
            [ -f "${VIRTUAL_ROOT}/${SITE_ID}/var/www/html/wp-config.php" ] && echo "${VIRTUAL_ROOT}/${SITE_ID}/var/www/html"
            ;;
        cwp)
            [ -n "$ROOT" ] && [ -f "$ROOT/wp-config.php" ] && { echo "$ROOT"; return 0; }
            [ -f "${CWP_HOME_ROOT}/${SITE_ID}/public_html/wp-config.php" ] && echo "${CWP_HOME_ROOT}/${SITE_ID}/public_html"
            ;;
    esac
}

quarantine_root(){
    local PLATFORM="$1" SITE_ID="$2" SITE_ROOT="${3:-}"
    case "$PLATFORM" in
        apiscp) echo "${VIRTUAL_ROOT}/${SITE_ID}/var/www/q" ;;
        cwp)
            if [ -n "$SITE_ROOT" ]; then
                echo "$(dirname "$SITE_ROOT")/q"
            else
                echo "${CWP_HOME_ROOT}/${SITE_ID}/q"
            fi
            ;;
    esac
}

cwp_domain_from_owner_map(){
    local SITE_ID="$1" MAP DOMAIN OWNER
    for MAP in /etc/trueuserdomains /etc/userdomains /etc/virtual/domainowners; do
        [ -r "$MAP" ] || continue
        while IFS=: read -r DOMAIN OWNER; do
            DOMAIN="$(printf '%s' "$DOMAIN" | tr -d '[:space:]')"
            OWNER="$(printf '%s' "$OWNER" | tr -d '[:space:]')"
            if [ "$OWNER" = "$SITE_ID" ] && [ -n "$DOMAIN" ]; then
                echo "$DOMAIN"
                return 0
            fi
        done < "$MAP"
    done
    return 1
}

cwp_owner_for_domain(){
    local REQUESTED="${1,,}" MAP DOMAIN OWNER
    for MAP in /etc/trueuserdomains /etc/userdomains /etc/virtual/domainowners; do
        [ -r "$MAP" ] || continue
        while IFS=: read -r DOMAIN OWNER; do
            DOMAIN="$(printf '%s' "$DOMAIN" | tr -d '[:space:]')"
            OWNER="$(printf '%s' "$OWNER" | tr -d '[:space:]')"
            if [ "${DOMAIN,,}" = "$REQUESTED" ] && [ -n "$OWNER" ]; then
                echo "$OWNER"
                return 0
            fi
        done < "$MAP"
    done
    return 1
}

cwp_root_from_domain_vhost(){
    local REQUESTED="${1,,}" CONF DOMAIN DOCROOT ALIASES
    for CONF in \
        /usr/local/apache/conf.d/vhosts/*.conf \
        /usr/local/apache/conf.d/vhosts-ssl/*.conf \
        /etc/httpd/conf.d/vhosts/*.conf \
        /etc/nginx/conf.d/vhosts/*.conf; do
        [ -r "$CONF" ] || continue
        DOMAIN=$(awk 'tolower($1)=="servername" || tolower($1)=="server_name" {gsub(/;/, "", $2); print tolower($2); exit}' "$CONF" 2>/dev/null)
        ALIASES=$(awk 'tolower($1)=="serveralias" || tolower($1)=="server_name" {$1=""; gsub(/;/, ""); print tolower($0)}' "$CONF" 2>/dev/null)
        if [ "$DOMAIN" != "$REQUESTED" ] && ! printf ' %s ' "$ALIASES" | grep -Fqi " $REQUESTED "; then
            continue
        fi
        DOCROOT=$(awk 'tolower($1)=="documentroot" || tolower($1)=="root" {gsub(/[";]/, "", $2); print $2; exit}' "$CONF" 2>/dev/null)
        if [ -n "$DOCROOT" ] && [ -f "${DOCROOT%/}/wp-config.php" ]; then
            printf '%s\n' "${DOCROOT%/}"
            return 0
        fi
    done
    return 1
}

resolve_requested_cwp_site(){
    local REQUESTED="$1" OWNER ROOT
    ROOT="$(cwp_root_from_domain_vhost "$REQUESTED" || true)"
    OWNER="$(cwp_owner_for_domain "$REQUESTED" || true)"

    if [ -n "$ROOT" ]; then
        [ -n "$OWNER" ] || OWNER="$(basename "$(dirname "$ROOT")")"
        printf 'cwp|%s|%s|%s\n' "$OWNER" "$ROOT" "$REQUESTED"
        return 0
    fi

    # CWP's primary domain normally maps to /home/USER/public_html. This
    # fallback is useful when the generated vhost layout differs by release.
    if [ -n "$OWNER" ]; then
        ROOT="${CWP_HOME_ROOT}/${OWNER}/public_html"
        if [ -f "$ROOT/wp-config.php" ]; then
            printf 'cwp|%s|%s|%s\n' "$OWNER" "$ROOT" "$REQUESTED"
            return 0
        fi
    fi
    return 1
}

cwp_domain_from_vhost(){
    local SITE_ROOT="$1" CONF DOMAIN DOCROOT
    for CONF in \
        /usr/local/apache/conf.d/vhosts/*.conf \
        /usr/local/apache/conf.d/vhosts-ssl/*.conf \
        /etc/httpd/conf.d/vhosts/*.conf \
        /etc/nginx/conf.d/vhosts/*.conf; do
        [ -r "$CONF" ] || continue
        DOMAIN=$(awk 'tolower($1)=="servername" {print $2; exit}' "$CONF" 2>/dev/null)
        DOCROOT=$(awk 'tolower($1)=="documentroot" {gsub(/\"/, "", $2); print $2; exit}' "$CONF" 2>/dev/null)
        if [ -n "$DOMAIN" ] && [ "${DOCROOT%/}" = "${SITE_ROOT%/}" ]; then
            echo "$DOMAIN"
            return 0
        fi
    done
    return 1
}

site_domain(){
    local PLATFORM="$1" SITE_ID="$2" SITE_ROOT="$3" URL
    if [ "$PLATFORM" = "apiscp" ]; then
        echo "$SITE_ID"
        return 0
    fi

    URL=$(cwp_domain_from_owner_map "$SITE_ID" || true)
    if [ -n "$URL" ]; then
        echo "$URL"
        return 0
    fi

    URL=$(cwp_domain_from_vhost "$SITE_ROOT" || true)
    if [ -n "$URL" ]; then
        echo "$URL"
        return 0
    fi

    if command -v wp >/dev/null 2>&1; then
        URL=$(wp option get siteurl --path="$SITE_ROOT" --allow-root --skip-plugins --skip-themes 2>/dev/null || true)
        if [ -n "$URL" ]; then
            printf '%s\n' "$URL" | sed -E 's#^https?://##; s#/.*$##'
            return 0
        fi
    fi

    # Fallback: read WP_HOME/WP_SITEURL if defined directly in wp-config.php.
    URL=$(grep -E "define\([[:space:]]*['\"]WP_(HOME|SITEURL)['\"]" "$SITE_ROOT/wp-config.php" 2>/dev/null | \
          sed -nE "s#.*['\"]https?://([^/'\"]+).*#\1#p" | head -n 1)
    [ -n "$URL" ] && echo "$URL"
}
cleanup_old_logs(){ [ -d "$LOG_ROOT" ] && find "$LOG_ROOT" -mindepth 1 -maxdepth 1 -type d -mtime +"$LOG_RETENTION_DAYS" -exec rm -rf {} \; 2>/dev/null; }

tree_needs_update(){
    local SOURCE="$1" TARGET="$2" FILE RELATIVE
    [ -d "$TARGET" ] || return 0
    while IFS= read -r -d '' FILE; do
        RELATIVE="${FILE#${SOURCE}/}"
        [ -f "${TARGET}/${RELATIVE}" ] && cmp -s "$FILE" "${TARGET}/${RELATIVE}" || return 0
    done < <(find "$SOURCE" -type f -print0)
    return 1
}

check_updates(){
    local FORCE="${1:-0}" STATE_DIR STATE_FILE NOW LAST=0 TMP REMOTE_DIFF CATEGORY SOURCE TARGET
    local INSTALLED_SCANNER GITHUB_SCANNER INSTALLED_VERSION GITHUB_VERSION LOCAL_COMMIT GITHUB_COMMIT HAS_UPDATES=0
    STATE_DIR="${LOG_ROOT}/update-state"
    STATE_FILE="${STATE_DIR}/last-check"
    mkdir -p "$STATE_DIR"
    NOW=$(date +%s)
    [ -s "$STATE_FILE" ] && read -r LAST < "$STATE_FILE"
    if [ "$FORCE" -ne 1 ] && [[ "$LAST" =~ ^[0-9]+$ ]] && [ $((NOW-LAST)) -lt "$UPDATE_CHECK_INTERVAL" ]; then
        return 0
    fi

    echo
    echo ">>> WP-WARDEN UPDATE CHECK"
    if ! command -v git >/dev/null 2>&1 || [ ! -d "${REPO_ROOT}/.git" ]; then
        echo "  [WARNING] Update check unavailable: ${REPO_ROOT} is not a Git checkout."
        return 0
    fi
    if ! fetch_main --quiet; then
        echo "  [WARNING] Update check failed; continuing with installed files."
        return 0
    fi
    printf '%s\n' "$NOW" > "$STATE_FILE"

    INSTALLED_SCANNER=$(find_warden)
    INSTALLED_VERSION=$(scanner_version_from_file "$INSTALLED_SCANNER")
    GITHUB_SCANNER=$(github_scanner_file)
    GITHUB_VERSION=$(github_scanner_version "$GITHUB_SCANNER")
    LOCAL_COMMIT=$(repo_git rev-parse --short HEAD 2>/dev/null || echo unknown)
    GITHUB_COMMIT=$(repo_git rev-parse --short origin/main 2>/dev/null || echo unknown)
    echo "  Installed scanner: ${INSTALLED_VERSION:-unknown} (commit $LOCAL_COMMIT)"
    echo "  GitHub scanner:    ${GITHUB_VERSION:-unknown} (main $GITHUB_COMMIT)"

    REMOTE_DIFF=$(repo_git diff --name-only HEAD..origin/main -- scanner intel/patterns intel/clean-zips intel/checksums 2>/dev/null || true)
    if printf '%s\n' "$REMOTE_DIFF" | grep -q '^scanner/'; then
        echo "  [UPDATE] scanner (${INSTALLED_VERSION:-unknown} -> ${GITHUB_VERSION:-unknown})"
        HAS_UPDATES=1
    else
        echo "  [CURRENT] scanner (${INSTALLED_VERSION:-unknown})"
    fi

    for CATEGORY in patterns clean-zips checksums; do
        TMP=$(mktemp -d)
        SOURCE="${TMP}/intel/${CATEGORY}"
        TARGET="${INTEL_ROOT}/${CATEGORY}"
        if ! repo_git cat-file -e "origin/main:intel/${CATEGORY}" 2>/dev/null; then
            echo "  [NOT PUBLISHED] wp-warden-intel/${CATEGORY}"
        elif ! repo_git archive origin/main -- "intel/${CATEGORY}" 2>/dev/null | tar -x -C "$TMP" 2>/dev/null; then
            echo "  [WARNING] Could not compare wp-warden-intel/${CATEGORY}."
        elif tree_needs_update "$SOURCE" "$TARGET"; then
            echo "  [UPDATE] wp-warden-intel/${CATEGORY}"
            HAS_UPDATES=1
        else
            echo "  [CURRENT] wp-warden-intel/${CATEGORY}"
        fi
        rm -rf "$TMP"
    done
    if [ "$HAS_UPDATES" -eq 1 ]; then
        echo "  Run $0 --self-update to install available updates."
    else
        echo "  WP Warden and published intel are current."
    fi
}

self_update(){
    local CATEGORY SOURCE TARGET
    echo ">>> UPDATING WP-WARDEN"
    command -v git >/dev/null 2>&1 || { echo "ERROR: git is required for --self-update"; return 1; }
    [ -d "${REPO_ROOT}/.git" ] || { echo "ERROR: ${REPO_ROOT} is not a Git checkout"; return 1; }
    repo_git diff --quiet && repo_git diff --cached --quiet || {
        echo "ERROR: Local repository changes detected; nothing was overwritten."
        return 1
    }
    fetch_main || return 1
    repo_git merge --ff-only origin/main || {
        echo "ERROR: Update is not a clean fast-forward; local changes were preserved."
        return 1
    }

    for CATEGORY in patterns clean-zips checksums; do
        SOURCE="${REPO_ROOT}/intel/${CATEGORY}"
        TARGET="${INTEL_ROOT}/${CATEGORY}"
        if [ -d "$SOURCE" ]; then
            mkdir -p "$TARGET"
            cp -a "${SOURCE}/." "$TARGET/"
            echo "  [UPDATED] wp-warden-intel/${CATEGORY}"
        else
            echo "  [NOT PUBLISHED] wp-warden-intel/${CATEGORY}"
        fi
    done
    WARDEN=$(find_warden)
    [ -n "$WARDEN" ] || { echo "ERROR: Scanner not found after update"; return 1; }
    echo "  [UPDATED] scanner: $WARDEN"
    echo "Update complete. Local-only intel files were preserved."
}
write_summary(){ printf "%s  %-12s %-45s critical=%s high=%s medium=%s low=%s total=%s vulns=%s vuln_status=%s http=%s health=%s endpoints=%s\n" "$(date '+%F %T')" "[$2]" "$1" "$3" "$4" "$5" "$6" "$7" "${8:-0}" "${9:-UNKNOWN}" "${10:-0}" "${11:-UNKNOWN}" "${12:-n/a}" >> "${RUN_LOG_DIR}/summary.log"; }

write_health_summary(){
    printf "%s  [SITE_HEALTH] %-45s status=%s http=%s time=%s bytes=%s final=%s reason=%s\n" \
        "$(date '+%F %T')" "$1" "$2" "$3" "$4" "$5" "$6" "$7" \
        >> "${RUN_LOG_DIR}/summary.log"
}

check_one_endpoint(){
    local DOMAIN="$1" PATH_PART="$2" LABEL="$3" SITE_LOG="$4"
    local BODY META URL CURL_EXIT HTTP_CODE FINAL_URL TOTAL_TIME SIZE_DOWNLOAD CONTENT_TYPE STATUS REASON

    BODY="$(mktemp)"
    META="$(mktemp)"
    URL="https://${DOMAIN}${PATH_PART}"

    curl -L -sS \
        --connect-timeout 5 \
        --max-time 20 \
        --compressed \
        -A "WP-Warden-Health/${WRAPPER_VERSION}" \
        -o "$BODY" \
        -w '%{http_code}\t%{url_effective}\t%{time_total}\t%{size_download}\t%{content_type}\n' \
        "$URL" > "$META" 2>/dev/null
    CURL_EXIT=$?

    if [ "$CURL_EXIT" -ne 0 ]; then
        URL="http://${DOMAIN}${PATH_PART}"
        curl -L -sS \
            --connect-timeout 5 \
            --max-time 20 \
            --compressed \
            -A "WP-Warden-Health/${WRAPPER_VERSION}" \
            -o "$BODY" \
            -w '%{http_code}\t%{url_effective}\t%{time_total}\t%{size_download}\t%{content_type}\n' \
            "$URL" > "$META" 2>/dev/null
        CURL_EXIT=$?
    fi

    HTTP_CODE=0; FINAL_URL="$URL"; TOTAL_TIME=0; SIZE_DOWNLOAD=0; CONTENT_TYPE=""
    if [ -s "$META" ]; then
        IFS=$'\t' read -r HTTP_CODE FINAL_URL TOTAL_TIME SIZE_DOWNLOAD CONTENT_TYPE < "$META"
    fi

    STATUS="HEALTHY"; REASON="ok"

    if [ "$CURL_EXIT" -ne 0 ]; then
        STATUS="FAILED"; REASON="curl_exit_${CURL_EXIT}"
    elif ! [[ "$HTTP_CODE" =~ ^[0-9]{3}$ ]]; then
        STATUS="FAILED"; REASON="invalid_http_status"
    elif grep -Eqi \
        'There has been a critical error on this website|Fatal error:|Parse error:|Uncaught (Error|Exception)|Allowed memory size .* exhausted|Error establishing a database connection' \
        "$BODY"; then
        STATUS="FAILED"; REASON="fatal_error_text"
    elif [ "$LABEL" = "REST" ] && { [ "$HTTP_CODE" -eq 401 ] || [ "$HTTP_CODE" -eq 403 ]; }; then
        STATUS="WARNING"; REASON="rest_blocked_http_${HTTP_CODE}"
    elif [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 400 ]; then
        STATUS="FAILED"; REASON="http_${HTTP_CODE}"
    elif [ "${SIZE_DOWNLOAD%.*}" -le 0 ] 2>/dev/null; then
        STATUS="WARNING"; REASON="empty_response"
    fi

    echo "  [$LABEL] $STATUS HTTP=$HTTP_CODE time=${TOTAL_TIME}s bytes=$SIZE_DOWNLOAD final=$FINAL_URL reason=$REASON" | tee -a "$SITE_LOG"

    ENDPOINT_STATUS="$STATUS"
    ENDPOINT_HTTP="$HTTP_CODE"
    ENDPOINT_REASON="$REASON"
    ENDPOINT_TIME="$TOTAL_TIME"
    ENDPOINT_BYTES="$SIZE_DOWNLOAD"
    ENDPOINT_FINAL="$FINAL_URL"

    rm -f "$BODY" "$META"
}

check_site_health(){
    local DOMAIN="$1" SITE_LOG="$2"
    local WORST="HEALTHY" WORST_HTTP=200 WORST_REASON="ok"
    local HOME_HTTP=0 LOGIN_HTTP=0 REST_HTTP=0
    local HOME_STATUS LOGIN_STATUS REST_STATUS

    {
        echo
        echo ">>> POST-CLEAN SITE HEALTH"
    } | tee -a "$SITE_LOG"

    check_one_endpoint "$DOMAIN" "/" "HOME" "$SITE_LOG"
    HOME_STATUS="$ENDPOINT_STATUS"; HOME_HTTP="$ENDPOINT_HTTP"
    [ "$ENDPOINT_STATUS" = "FAILED" ] && { WORST="FAILED"; WORST_HTTP="$ENDPOINT_HTTP"; WORST_REASON="home_${ENDPOINT_REASON}"; }
    [ "$ENDPOINT_STATUS" = "WARNING" ] && [ "$WORST" = "HEALTHY" ] && { WORST="WARNING"; WORST_HTTP="$ENDPOINT_HTTP"; WORST_REASON="home_${ENDPOINT_REASON}"; }

    check_one_endpoint "$DOMAIN" "/wp-login.php" "LOGIN" "$SITE_LOG"
    LOGIN_STATUS="$ENDPOINT_STATUS"; LOGIN_HTTP="$ENDPOINT_HTTP"
    [ "$ENDPOINT_STATUS" = "FAILED" ] && { WORST="FAILED"; WORST_HTTP="$ENDPOINT_HTTP"; WORST_REASON="login_${ENDPOINT_REASON}"; }
    [ "$ENDPOINT_STATUS" = "WARNING" ] && [ "$WORST" = "HEALTHY" ] && { WORST="WARNING"; WORST_HTTP="$ENDPOINT_HTTP"; WORST_REASON="login_${ENDPOINT_REASON}"; }

    check_one_endpoint "$DOMAIN" "/wp-json/" "REST" "$SITE_LOG"
    REST_STATUS="$ENDPOINT_STATUS"; REST_HTTP="$ENDPOINT_HTTP"
    [ "$ENDPOINT_STATUS" = "FAILED" ] && { WORST="FAILED"; WORST_HTTP="$ENDPOINT_HTTP"; WORST_REASON="rest_${ENDPOINT_REASON}"; }
    [ "$ENDPOINT_STATUS" = "WARNING" ] && [ "$WORST" = "HEALTHY" ] && { WORST="WARNING"; WORST_HTTP="$ENDPOINT_HTTP"; WORST_REASON="rest_${ENDPOINT_REASON}"; }

    {
        echo " Overall:      $WORST"
        echo " HTTP summary: home=$HOME_HTTP login=$LOGIN_HTTP rest=$REST_HTTP"
        echo " Reason:       $WORST_REASON"
    } | tee -a "$SITE_LOG"

    write_health_summary "$DOMAIN" "$WORST" "$HOME_HTTP" "n/a" "n/a" \
        "home=${HOME_HTTP},login=${LOGIN_HTTP},rest=${REST_HTTP}" "$WORST_REASON"

    LAST_HEALTH_STATUS="$WORST"
    LAST_HEALTH_HTTP="$HOME_HTTP"
    LAST_HEALTH_REASON="$WORST_REASON"
    LAST_HEALTH_DETAIL="home=${HOME_HTTP},login=${LOGIN_HTTP},rest=${REST_HTTP}"
}

fleet_ioc_sweep(){
    local DOMAIN="$1" REPORT="$2" SITE_LOG="$3"
    [ -s "$REPORT" ] || return 0
    command -v jq >/dev/null 2>&1 || return 0

    local NEED_SWEEP=0
    if jq -e '
        [.findings[]? | .rule_id // ""] |
        any(. == "PHP_WPHIDDENBOT_PERSISTENCE_001"
            or . == "PHP_WPHIDDENBOT_HIDE_USER_003"
            or . == "BUILTIN_WPHIDDENBOT_ADMIN_001"
            or test("WP2SHELL|GALEX|NX_ADMIN|WARNIGHT"))
    ' "$REPORT" >/dev/null 2>&1; then
        NEED_SWEEP=1
    fi

    [ "$NEED_SWEEP" -eq 1 ] || return 0

    {
        echo
        echo ">>> FLEET IOC SWEEP"
        echo " Confirmed persistence IOC found on $DOMAIN; checking all WordPress wp-content trees."
    } | tee -a "$SITE_LOG"

    local MATCH_FILE="${RUN_LOG_DIR}/${DOMAIN}-${RUN_TIME}-fleet-ioc.txt"
    : > "$MATCH_FILE"

    while IFS='|' read -r PLATFORM SITE_ID SITE_ROOT DISCOVERED_DOMAIN; do
        ROOT="${SITE_ROOT}/wp-content"
        [ -d "$ROOT" ] || continue
        grep -RIlE \
            'wphiddenbot|wp2shell[-_.]|galex_[a-f0-9]{6,64}|@nx\.invalid|warnight6413|_wp_cache_optimizer_flag|WP_Cache_Optimizer_Core' \
            "$ROOT" 2>/dev/null >> "$MATCH_FILE" || true
    done < <(discover_sites)

    sort -u -o "$MATCH_FILE" "$MATCH_FILE"
    local COUNT
    COUNT=$(wc -l < "$MATCH_FILE" 2>/dev/null || echo 0)

    if [ "$COUNT" -gt 0 ]; then
        echo " Fleet IOC matches: $COUNT file(s)" | tee -a "$SITE_LOG"
        sed 's/^/   - /' "$MATCH_FILE" | tee -a "$SITE_LOG"
    else
        echo " Fleet IOC matches: none outside database/user IOCs." | tee -a "$SITE_LOG"
    fi
}

scan_site(){
 local PLATFORM="$1" SITE_ID="$2" SITE_ROOT="${3:-}" DOMAIN="${4:-}" QUARANTINE SITE_LOG REPORT CLEANUP_EXIT VERIFY_EXIT
 local CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0 TOTAL=0 VULN_COUNT=0 VULN_STATUS=UNKNOWN RESULT_STATUS SITE_START SITE_END DISPLAY_ID
 SITE_START=$(date +%s)
 SITE_ROOT="$(site_root "$PLATFORM" "$SITE_ID" "$SITE_ROOT")"
 if [ -z "${SITE_ROOT:-}" ]; then
   echo "[SKIP] $SITE_ID - WordPress root not found"
   write_summary "$SITE_ID" SKIPPED 0 0 0 0 0 0 NOT_RUN 0 NOT_CHECKED n/a
   return 2
 fi

 [ -n "$DOMAIN" ] || DOMAIN="$(site_domain "$PLATFORM" "$SITE_ID" "$SITE_ROOT")"
 DISPLAY_ID="${DOMAIN:-$SITE_ID}"

 QUARANTINE="$(quarantine_root "$PLATFORM" "$SITE_ID" "$SITE_ROOT")"
 if [ -z "${QUARANTINE:-}" ]; then
   echo "[SKIP] $DISPLAY_ID - quarantine path could not be determined"
   write_summary "$DISPLAY_ID" SKIPPED 0 0 0 0 0 0 NOT_RUN 0 NOT_CHECKED n/a
   return 2
 fi
 mkdir -p "$QUARANTINE"

 if [ "$PLATFORM" = "cwp" ]; then
   local CWP_USER
   CWP_USER="$(basename "$(dirname "$SITE_ROOT")")"
   if id "$CWP_USER" >/dev/null 2>&1; then
     chown "$CWP_USER:$CWP_USER" "$QUARANTINE" 2>/dev/null || true
     chmod 700 "$QUARANTINE" 2>/dev/null || true
   fi
 fi

 SITE_LOG="${RUN_LOG_DIR}/${DISPLAY_ID}-${RUN_TIME}.log"; REPORT="${RUN_LOG_DIR}/${DISPLAY_ID}-${RUN_TIME}.json"
 { line; echo " WP-Warden: $DISPLAY_ID"; echo " Started: $(date)"; echo " Platform: $PLATFORM"; echo " Site ID: $SITE_ID"; echo " Domain: ${DOMAIN:-unknown}"; echo " Site: $SITE_ROOT"; echo " Scope: $(scan_scope_label)"; echo " Quarantine: $QUARANTINE"; echo " JSON: $REPORT"; line; echo; echo ">>> PASS 1: VERIFY + SCAN + CLEANUP"; } | tee -a "$SITE_LOG"
 # Extra plugin/theme files are report-only by default. Premium/vendor checksum
 # sets can be incomplete, so their absence is not proof of malware.
 php "$WARDEN" "$SITE_ROOT" --intel-dir="$INTEL_ROOT" --verify-all --repair-original-auto --apply --fetch-official-checksums --noninteractive --quarantine-malware-auto --cleanup-malware-users-auto --cleanup-database-persistence-auto --cleanup-malware-cron-auto --quarantine-extra-core-auto --exclude-pdf --newest-first $RECENT_PHP_OPTION --max-size=1 --max-text-size=1 --quarantine="$QUARANTINE" 2>&1 | tee -a "$SITE_LOG"
 CLEANUP_EXIT=${PIPESTATUS[0]}
 { echo; echo ">>> PASS 1 EXIT CODE: $CLEANUP_EXIT"; echo ">>> PASS 2: POST-CLEANUP VERIFY (cache enabled, no checksum refetch)"; } | tee -a "$SITE_LOG"
 php "$WARDEN" "$SITE_ROOT" --intel-dir="$INTEL_ROOT" --verify-all --noninteractive --exclude-pdf --newest-first $RECENT_PHP_OPTION --max-size=1 --max-text-size=1 --vulnerability-scan --report-json="$REPORT" 2>&1 | tee -a "$SITE_LOG"
 VERIFY_EXIT=${PIPESTATUS[0]}
 if [ -s "$REPORT" ] && command -v jq >/dev/null 2>&1; then
   CRITICAL=$(jq -r '.summary.critical // 0' "$REPORT"); HIGH=$(jq -r '.summary.high // 0' "$REPORT"); MEDIUM=$(jq -r '.summary.medium // 0' "$REPORT"); LOW=$(jq -r '.summary.low // 0' "$REPORT"); TOTAL=$(jq -r '.summary.findings_total // 0' "$REPORT")
   VULN_COUNT=$(jq -r '.vulnerabilities.summary.total // 0' "$REPORT")
   VULN_STATUS=$(jq -r '.vulnerabilities.status // "UNKNOWN"' "$REPORT")
   [[ "$CRITICAL" =~ ^[0-9]+$ ]] || CRITICAL=0; [[ "$HIGH" =~ ^[0-9]+$ ]] || HIGH=0; [[ "$MEDIUM" =~ ^[0-9]+$ ]] || MEDIUM=0; [[ "$LOW" =~ ^[0-9]+$ ]] || LOW=0; [[ "$TOTAL" =~ ^[0-9]+$ ]] || TOTAL=0
 else
   echo "WARNING: JSON report unavailable: $REPORT"; [ "$VERIFY_EXIT" -eq 0 ] || CRITICAL=1
 fi
 [ "$CRITICAL" -eq 0 ] && [ "$HIGH" -eq 0 ] && RESULT_STATUS=CLEAN || RESULT_STATUS=NOT_CLEAN

 LAST_HEALTH_STATUS="UNKNOWN"
 LAST_HEALTH_HTTP="0"
 LAST_HEALTH_REASON="not_checked"
 LAST_HEALTH_DETAIL="n/a"
 if [ -n "$DOMAIN" ]; then
   check_site_health "$DOMAIN" "$SITE_LOG"
 else
   echo " Site health: skipped - domain could not be determined" | tee -a "$SITE_LOG"
   LAST_HEALTH_STATUS="NOT_CHECKED"
   LAST_HEALTH_REASON="domain_unknown"
 fi

 if [ "${RUNNING_ALL:-0}" -ne 1 ]; then
   fleet_ioc_sweep "$DISPLAY_ID" "$REPORT" "$SITE_LOG"
   [ -s "$REPORT" ] && trigger_missing_intel_recovery "$REPORT" | tee -a "$SITE_LOG"
 fi

 SITE_END=$(date +%s)
 { echo; line; echo " RESULT: ${RESULT_STATUS/_/ }"; echo " Platform: $PLATFORM"; echo " Site ID: $SITE_ID"; echo " Domain: ${DOMAIN:-unknown}"; echo " Critical: $CRITICAL"; echo " High: $HIGH"; echo " Medium: $MEDIUM"; echo " Low: $LOW"; echo " Findings: $TOTAL"; echo " Vulnerabilities: $VULN_COUNT ($VULN_STATUS)"; echo " Site health: $LAST_HEALTH_STATUS (HTTP $LAST_HEALTH_HTTP, $LAST_HEALTH_REASON)"; printf " Runtime: %dm %02ds\n" "$(((SITE_END-SITE_START)/60))" "$(((SITE_END-SITE_START)%60))"; echo " JSON: $REPORT"; line; } | tee -a "$SITE_LOG"
 write_summary "$DISPLAY_ID" "$RESULT_STATUS" "$CRITICAL" "$HIGH" "$MEDIUM" "$LOW" "$TOTAL" "$VULN_COUNT" "$VULN_STATUS" "$LAST_HEALTH_HTTP" "$LAST_HEALTH_STATUS" "$LAST_HEALTH_DETAIL"
 [ "$RESULT_STATUS" = CLEAN ] && return 0 || return 1
}

discover_sites(){
    local d ROOT USER DOMAIN WWW_ROOT CANON_WWW CANON_ROOT WEB_NAME
    local -A SEEN_APISCP_ROOTS=()

    {

    # ApisCP: discover the primary var/www/html site plus WordPress installs
    # in immediate subdomain/addon-domain document roots under var/www.
    if [ -d "$VIRTUAL_ROOT" ]; then
        while IFS= read -r -d '' d; do
            d="$(basename "$d")"
            [ -z "$d" ] && continue
            case "$d" in site*|admin*|FILESYSTEMTEMPLATE) continue;; esac
            WWW_ROOT="${VIRTUAL_ROOT}/${d}/var/www"
            [ -d "$WWW_ROOT" ] || continue
            CANON_WWW="$(readlink -f -- "$WWW_ROOT" 2>/dev/null || true)"
            [ -n "$CANON_WWW" ] || continue

            while IFS= read -r -d '' ROOT; do
                [ -f "$ROOT/wp-config.php" ] || continue
                CANON_ROOT="$(readlink -f -- "$ROOT" 2>/dev/null || true)"
                [ -n "$CANON_ROOT" ] || continue

                # Do not let a document-root symlink escape this ApisCP account.
                case "${CANON_ROOT}/" in
                    "${CANON_WWW}/"*) ;;
                    *) echo "WARN: skipping ApisCP web-root symlink outside account: $ROOT -> $CANON_ROOT" >&2; continue;;
                esac

                # ApisCP may expose one account through several /home/virtual
                # aliases. Scan each physical WordPress root only once.
                [ -z "${SEEN_APISCP_ROOTS[$CANON_ROOT]+x}" ] || continue
                SEEN_APISCP_ROOTS["$CANON_ROOT"]=1

                WEB_NAME="$(basename "$ROOT")"
                DOMAIN="$WEB_NAME"
                [ "$WEB_NAME" = "html" ] && DOMAIN="$d"
                printf 'apiscp|%s|%s|%s\n' "$d" "$ROOT" "$DOMAIN"
            done < <(find "$WWW_ROOT" -mindepth 1 -maxdepth 1 \( -type d -o -type l \) -print0 2>/dev/null)
        done < <(find "$VIRTUAL_ROOT" -mindepth 1 -maxdepth 1 \( -type l -o -type d \) -print0 2>/dev/null)
    fi

    # CWP: /home/username/public_html
    for ROOT in "$CWP_HOME_ROOT"/*/public_html; do
        [ -f "$ROOT/wp-config.php" ] || continue
        USER="$(basename "$(dirname "$ROOT")")"
        DOMAIN="$(site_domain cwp "$USER" "$ROOT")"
        printf 'cwp|%s|%s|%s\n' "$USER" "$ROOT" "$DOMAIN"
    done
    } | sort -u
}

aggregate_health(){
 local -a reports=("${RUN_LOG_DIR}"/*-"${RUN_TIME}".json)
 [ -e "${reports[0]:-}" ] || return 0
 echo; line; echo " MISSING CHECKSUM INTEL - ALL SITES"; line
 jq -rs '
   def domain: (.target|split("/")|.[3] // .site_id);
   [ .[] as $r | ($r.checksum_intel.missing_plugins // [])[] | . + {site:($r|domain)} ] | group_by(.slug,.version)[] | "PLUGIN\t\(.[0].slug)\t\(.[0].version)\t\(map(.site)|unique|join(", "))\t\(.[0].expected_intel)" ,
   [ .[] as $r | ($r.checksum_intel.missing_themes // [])[] | . + {site:($r|domain)} ] | group_by(.slug,.version)[] | "THEME\t\(.[0].slug)\t\(.[0].version)\t\(map(.site)|unique|join(", "))\t\(.[0].expected_intel)"
 ' "${reports[@]}" 2>/dev/null | sed $'s/\t/  /g'
 echo
 line
 echo " VULNERABILITY HEALTH - ALL SITES"
 line
 jq -rs '
   def domain: (.target|split("/")|.[3] // .site_id);
   .[] as $r |
   ($r.vulnerabilities.wordpress // [])[] |
   "\($r|domain)\tWORDPRESS\t\(.type)\t\(.slug)\t\(.installed)\t\(.title)\tpatched=\(.patched)"
 ' "${reports[@]}" 2>/dev/null | sort -u | sed $'s/\t/  /g'
 jq -rs '
   def domain: (.target|split("/")|.[3] // .site_id);
   .[] as $r |
   ($r.vulnerabilities.composer // [])[] |
   "\($r|domain)\tCOMPOSER\t\(.package)\t\(.installed)\t\(.id)\t\(.summary)"
 ' "${reports[@]}" 2>/dev/null | sort -u | sed $'s/\t/  /g'
 echo
 line
 echo " CONFIRMED IOCS - ALL SITES"
 line
 jq -rs '
   def domain: (.target|split("/")|.[3] // .site_id);
   .[] as $r |
   ($r.findings // [])[] |
   select((.severity // "" | ascii_downcase) == "critical") |
   select((.rule_id // "") != "") |
   "\($r|domain)\t\(.rule_id)\t\(.relative_path // .path // "")"
 ' "${reports[@]}" 2>/dev/null | sort -u | sed $'s/\t/  /g'
 echo; line; echo " UPDATE HEALTH - MANUAL REVIEW"; line
 jq -rs '
   def domain: (.target|split("/")|.[3] // .site_id);
   .[] as $r |
   (if ($r.updates.core.outdated // false) then "CORE\t\($r|domain)\t\($r.updates.core.installed) -> \($r.updates.core.latest)" else empty end),
   (($r.updates.plugins // [])[] | select(.outdated==true) | "PLUGIN\t\($r|domain)\t\(.slug)\t\(.installed) -> \(.latest)"),
   (($r.updates.themes // [])[] | select(.outdated==true) | "THEME\t\($r|domain)\t\(.slug)\t\(.installed) -> \(.latest)"),
   (($r.updates.unknown // [])[] | "UNKNOWN\t\($r|domain)\t\(.type)\t\(.slug // "")\t\(.installed // "")\t\(.reason)")
   ,(($r.updates.private_or_custom // [])[] | "PRIVATE/CUSTOM\t\($r|domain)\t\(.type)\t\(.slug // "")\t\(.installed // "")\t\(.reason)")
 ' "${reports[@]}" 2>/dev/null | sed $'s/\t/  /g'
}

trigger_missing_intel_recovery(){
 local FINDER="${REPO_ROOT}/scanner/wp-find-clean.sh" KIND SLUG VERSION
 local -a REPORTS=("$@")
 [ "$RECOVER_MISSING_INTEL" = 1 ] || return 0
 [ -f "$FINDER" ] || { echo "WARN: missing-intel recovery helper unavailable: $FINDER"; return 0; }
 command -v jq >/dev/null 2>&1 || { echo "WARN: jq is required for missing-intel recovery"; return 0; }
 [ "${#REPORTS[@]}" -gt 0 ] || return 0

 while IFS=$'\t' read -r KIND SLUG VERSION; do
   [ -n "$KIND" ] && [ -n "$SLUG" ] && [ -n "$VERSION" ] || continue
   echo
   line
   echo " MISSING INTEL RECOVERY: ${KIND} ${SLUG} ${VERSION}"
   line
   bash "$FINDER" "${KIND,,}" "$SLUG" "$VERSION" --zip || true
 done < <(jq -rsr '
   ([ .[] | (.checksum_intel.missing_plugins // [])[] | ["PLUGIN", .slug, .version] ] +
    [ .[] | (.checksum_intel.missing_themes // [])[] | ["THEME", .slug, .version] ])
   | unique | .[] | @tsv
 ' "${REPORTS[@]}" 2>/dev/null)
}

scan_all(){
 RUNNING_ALL=1
 local START_TIME=$(date +%s) CLEAN_COUNT=0 DIRTY_COUNT=0 SKIPPED_COUNT=0 TOTAL_COUNT=0 SITE_RESULT
 local HEALTHY_COUNT=0 HEALTH_WARNING_COUNT=0 HEALTH_FAILED_COUNT=0
 local PLATFORM SITE_ID SITE_ROOT DOMAIN DISPLAY_ID ENTRY
 local -a CLEAN_SITES=() DIRTY_SITES=() SKIPPED_SITES=() HEALTH_FAILED_SITES=() HEALTH_WARNING_SITES=() SITES=()
 local ALL_LOG="${RUN_LOG_DIR}/all-sites-${RUN_TIME}.log"; exec > >(tee -a "$ALL_LOG") 2>&1
 line; echo " WP-WARDEN - ALL WORDPRESS SITES"; echo " Started: $(date)"; echo " Scanner: $WARDEN"; echo " Discovery: ApisCP + CWP"; echo " Scope: $(scan_scope_label)"; echo " Log: $ALL_LOG"; line
 mapfile -t SITES < <(discover_sites); [ "${#SITES[@]}" -gt 0 ] || { echo "No WordPress installations found."; return 1; }
 echo "Found ${#SITES[@]} WordPress site(s)."
 for ENTRY in "${SITES[@]}"; do
   IFS='|' read -r PLATFORM SITE_ID SITE_ROOT DOMAIN <<< "$ENTRY"
   DISPLAY_ID="${DOMAIN:-$SITE_ID}"
   TOTAL_COUNT=$((TOTAL_COUNT+1)); echo; line; echo "[$TOTAL_COUNT/${#SITES[@]}] SCANNING: $DISPLAY_ID"; echo " Platform: $PLATFORM"; echo " Root: $SITE_ROOT"; line
   LAST_HEALTH_STATUS="UNKNOWN"; LAST_HEALTH_HTTP="0"; LAST_HEALTH_REASON="not_checked"
   scan_site "$PLATFORM" "$SITE_ID" "$SITE_ROOT" "$DOMAIN"; SITE_RESULT=$?
   case "$SITE_RESULT" in
     0) CLEAN_COUNT=$((CLEAN_COUNT+1)); CLEAN_SITES+=("$DISPLAY_ID");;
     1) DIRTY_COUNT=$((DIRTY_COUNT+1)); DIRTY_SITES+=("$DISPLAY_ID");;
     *) SKIPPED_COUNT=$((SKIPPED_COUNT+1)); SKIPPED_SITES+=("$DISPLAY_ID");;
   esac
   case "$LAST_HEALTH_STATUS" in
     HEALTHY) HEALTHY_COUNT=$((HEALTHY_COUNT+1));;
     WARNING) HEALTH_WARNING_COUNT=$((HEALTH_WARNING_COUNT+1)); HEALTH_WARNING_SITES+=("$DISPLAY_ID");;
     FAILED) HEALTH_FAILED_COUNT=$((HEALTH_FAILED_COUNT+1)); HEALTH_FAILED_SITES+=("$DISPLAY_ID");;
   esac
 done
 aggregate_health
 local -a RECOVERY_REPORTS=("${RUN_LOG_DIR}"/*-"${RUN_TIME}".json)
 [ -e "${RECOVERY_REPORTS[0]:-}" ] && trigger_missing_intel_recovery "${RECOVERY_REPORTS[@]}"
 local END_TIME=$(date +%s) ELAPSED=$((END_TIME-START_TIME)); echo; line; echo " WP-WARDEN ALL-SITE SUMMARY"; line; printf " Sites scanned : %d\n CLEAN         : %d\n NOT CLEAN     : %d\n Skipped       : %d\n" "$TOTAL_COUNT" "$CLEAN_COUNT" "$DIRTY_COUNT" "$SKIPPED_COUNT"; printf " Runtime       : %dh %02dm %02ds\n" "$((ELAPSED/3600))" "$(((ELAPSED%3600)/60))" "$((ELAPSED%60))"
 echo
 echo "SITE HEALTH:"
 printf " Healthy       : %d\n" "$HEALTHY_COUNT"
 printf " Warning       : %d\n" "$HEALTH_WARNING_COUNT"
 printf " Failed        : %d\n" "$HEALTH_FAILED_COUNT"
 [ "$HEALTH_WARNING_COUNT" -gt 0 ] && { echo; echo "HEALTH WARNINGS:"; printf '  [WARNING] %s\n' "${HEALTH_WARNING_SITES[@]}"; }
 [ "$HEALTH_FAILED_COUNT" -gt 0 ] && { echo; echo "HEALTH FAILURES:"; printf '  [FAILED] %s\n' "${HEALTH_FAILED_SITES[@]}"; }
 [ "$CLEAN_COUNT" -gt 0 ] && { echo; echo CLEAN:; printf '  [CLEAN] %s\n' "${CLEAN_SITES[@]}"; }; [ "$DIRTY_COUNT" -gt 0 ] && { echo; echo 'NOT CLEAN:'; printf '  [NOT CLEAN] %s\n' "${DIRTY_SITES[@]}"; }; [ "$SKIPPED_COUNT" -gt 0 ] && { echo; echo SKIPPED:; printf '  [SKIPPED] %s\n' "${SKIPPED_SITES[@]}"; }
 echo; echo "Logs: $RUN_LOG_DIR"; line; [ "$DIRTY_COUNT" -gt 0 ] && return 1 || return 0
}

TARGET_ARG=""
for ARG in "$@"; do
    case "$ARG" in
        --recent-php-days=*)
            RECENT_PHP_DAYS="${ARG#*=}"
            [[ "$RECENT_PHP_DAYS" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: --recent-php-days requires a positive integer"; exit 1; }
            [ -z "$RECENT_PHP_OPTION" ] || { echo "ERROR: --recent-php-days may only be specified once"; exit 1; }
            RECENT_PHP_OPTION="--recent-php-days=$RECENT_PHP_DAYS"
            ;;
        *)
            [ -z "$TARGET_ARG" ] || usage
            TARGET_ARG="$ARG"
            ;;
    esac
done
set --
[ -z "$TARGET_ARG" ] || set -- "$TARGET_ARG"

cleanup_old_logs
if [ "${1:-}" = "--check-updates" ]; then check_updates 1; exit $?; fi
if [ "${1:-}" = "--self-update" ]; then self_update; exit $?; fi
check_updates 0
WARDEN=$(find_warden)
[ -f "$WARDEN" ] || { echo "ERROR: WP-Warden not found: $WARDEN"; exit 1; }
[ $# -eq 1 ] || usage
if [ "$1" = --all ]; then scan_all; exit $?; fi
DOMAIN="${1,,}"; [[ "$DOMAIN" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] || { echo "ERROR: Invalid domain: $DOMAIN"; exit 1; }

MATCH=""
while IFS= read -r ENTRY; do
    IFS='|' read -r PLATFORM SITE_ID SITE_ROOT DISCOVERED_DOMAIN <<< "$ENTRY"
    if [ "$DOMAIN" = "${DISCOVERED_DOMAIN,,}" ] || [ "$DOMAIN" = "${SITE_ID,,}" ]; then
        MATCH="$ENTRY"
        break
    fi
done < <(discover_sites)

if [ -z "$MATCH" ]; then
    MATCH="$(resolve_requested_cwp_site "$DOMAIN" || true)"
fi

[ -n "$MATCH" ] || { echo "ERROR: WordPress site not found for: $DOMAIN"; exit 1; }
IFS='|' read -r PLATFORM SITE_ID SITE_ROOT DISCOVERED_DOMAIN <<< "$MATCH"
scan_site "$PLATFORM" "$SITE_ID" "$SITE_ROOT" "$DISCOVERED_DOMAIN"; exit $?
