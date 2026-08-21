#!/bin/bash
set -u
set -o pipefail

WARDEN="/root/wp-warden/scanner/wp-warden-pef-0.1.56.php"
VIRTUAL_ROOT="/home/virtual"
LOG_ROOT="/root/wp-warden/logs"
LOG_RETENTION_DAYS=30
RUN_DATE="$(date +%Y-%m-%d)"
RUN_TIME="$(date +%H%M%S)"
RUN_LOG_DIR="${LOG_ROOT}/${RUN_DATE}"
mkdir -p "$RUN_LOG_DIR"

usage(){ echo "Usage: $0 domain.com.au | --all"; exit 1; }
line(){ echo "======================================================================"; }
site_root(){ local d="$1" b="${VIRTUAL_ROOT}/${1}"; [ -f "$b/var/www/html/wp-config.php" ] && echo "$b/var/www/html"; }
quarantine_root(){ echo "${VIRTUAL_ROOT}/${1}/var/www/q"; }
cleanup_old_logs(){ [ -d "$LOG_ROOT" ] && find "$LOG_ROOT" -mindepth 1 -maxdepth 1 -type d -mtime +"$LOG_RETENTION_DAYS" -exec rm -rf {} \; 2>/dev/null; }
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
        -A "WP-Warden-Health/0.1.56" \
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
            -A "WP-Warden-Health/0.1.56" \
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
            or test("WP2SHELL|NX_ADMIN"))
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

    for ROOT in "$VIRTUAL_ROOT"/*/var/www/html/wp-content; do
        [ -d "$ROOT" ] || continue
        grep -RIlE \
            'wphiddenbot|wp2shell\.(invalid|local)|@nx\.invalid|_wp_cache_optimizer_flag|WP_Cache_Optimizer_Core' \
            "$ROOT" 2>/dev/null >> "$MATCH_FILE" || true
    done

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
 local DOMAIN="$1" SITE_ROOT QUARANTINE SITE_LOG REPORT CLEANUP_EXIT VERIFY_EXIT
 local CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0 TOTAL=0 VULN_COUNT=0 VULN_STATUS=UNKNOWN RESULT_STATUS SITE_START SITE_END
 SITE_START=$(date +%s); SITE_ROOT="$(site_root "$DOMAIN")"
 if [ -z "${SITE_ROOT:-}" ]; then echo "[SKIP] $DOMAIN - WordPress root not found"; write_summary "$DOMAIN" SKIPPED 0 0 0 0 0 0 NOT_RUN 0 NOT_CHECKED n/a; return 2; fi
 QUARANTINE="$(quarantine_root "$DOMAIN")"; mkdir -p "$QUARANTINE"
 SITE_LOG="${RUN_LOG_DIR}/${DOMAIN}-${RUN_TIME}.log"; REPORT="${RUN_LOG_DIR}/${DOMAIN}-${RUN_TIME}.json"
 { line; echo " WP-Warden: $DOMAIN"; echo " Started: $(date)"; echo " Site: $SITE_ROOT"; echo " Quarantine: $QUARANTINE"; echo " JSON: $REPORT"; line; echo; echo ">>> PASS 1: VERIFY + SCAN + CLEANUP"; } | tee -a "$SITE_LOG"
 php "$WARDEN" "$SITE_ROOT" --verify-all --repair-original-auto --apply --fetch-official-checksums --noninteractive --quarantine-malware-auto --cleanup-malware-users-auto --quarantine-extra-auto --quarantine-extra-core-auto --exclude-pdf --max-size=1 --max-text-size=1 --quarantine="$QUARANTINE" 2>&1 | tee -a "$SITE_LOG"
 CLEANUP_EXIT=${PIPESTATUS[0]}
 { echo; echo ">>> PASS 1 EXIT CODE: $CLEANUP_EXIT"; echo ">>> PASS 2: POST-CLEANUP VERIFY (cache enabled, no checksum refetch)"; } | tee -a "$SITE_LOG"
 php "$WARDEN" "$SITE_ROOT" --verify-all --noninteractive --exclude-pdf --max-size=1 --max-text-size=1 --vulnerability-scan --report-json="$REPORT" 2>&1 | tee -a "$SITE_LOG"
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
 check_site_health "$DOMAIN" "$SITE_LOG"

 if [ "${RUNNING_ALL:-0}" -ne 1 ]; then
   fleet_ioc_sweep "$DOMAIN" "$REPORT" "$SITE_LOG"
 fi

 SITE_END=$(date +%s)
 { echo; line; echo " RESULT: ${RESULT_STATUS/_/ }"; echo " Domain: $DOMAIN"; echo " Critical: $CRITICAL"; echo " High: $HIGH"; echo " Medium: $MEDIUM"; echo " Low: $LOW"; echo " Findings: $TOTAL"; echo " Vulnerabilities: $VULN_COUNT ($VULN_STATUS)"; echo " Site health: $LAST_HEALTH_STATUS (HTTP $LAST_HEALTH_HTTP, $LAST_HEALTH_REASON)"; printf " Runtime: %dm %02ds\n" "$(((SITE_END-SITE_START)/60))" "$(((SITE_END-SITE_START)%60))"; echo " JSON: $REPORT"; line; } | tee -a "$SITE_LOG"
 write_summary "$DOMAIN" "$RESULT_STATUS" "$CRITICAL" "$HIGH" "$MEDIUM" "$LOW" "$TOTAL" "$VULN_COUNT" "$VULN_STATUS" "$LAST_HEALTH_HTTP" "$LAST_HEALTH_STATUS" "$LAST_HEALTH_DETAIL"
 [ "$RESULT_STATUS" = CLEAN ] && return 0 || return 1
}

discover_sites(){ find "$VIRTUAL_ROOT" -maxdepth 1 -type l -printf '%f\n' 2>/dev/null | while read -r d; do [ -z "$d" ] && continue; case "$d" in site*|admin*|FILESYSTEMTEMPLATE) continue;; esac; [ -f "$VIRTUAL_ROOT/$d/var/www/html/wp-config.php" ] && echo "$d"; done | sort -u; }

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

scan_all(){
 RUNNING_ALL=1
 local START_TIME=$(date +%s) CLEAN_COUNT=0 DIRTY_COUNT=0 SKIPPED_COUNT=0 TOTAL_COUNT=0 SITE_RESULT
 local HEALTHY_COUNT=0 HEALTH_WARNING_COUNT=0 HEALTH_FAILED_COUNT=0
 local -a CLEAN_SITES=() DIRTY_SITES=() SKIPPED_SITES=() HEALTH_FAILED_SITES=() HEALTH_WARNING_SITES=() SITES=()
 local ALL_LOG="${RUN_LOG_DIR}/all-sites-${RUN_TIME}.log"; exec > >(tee -a "$ALL_LOG") 2>&1
 line; echo " WP-WARDEN - ALL WORDPRESS SITES"; echo " Started: $(date)"; echo " Scanner: $WARDEN"; echo " Log: $ALL_LOG"; line
 mapfile -t SITES < <(discover_sites); [ "${#SITES[@]}" -gt 0 ] || { echo "No WordPress installations found."; return 1; }
 echo "Found ${#SITES[@]} WordPress site(s)."
 for DOMAIN in "${SITES[@]}"; do
   TOTAL_COUNT=$((TOTAL_COUNT+1)); echo; line; echo "[$TOTAL_COUNT/${#SITES[@]}] SCANNING: $DOMAIN"; line
   LAST_HEALTH_STATUS="UNKNOWN"; LAST_HEALTH_HTTP="0"; LAST_HEALTH_REASON="not_checked"
   scan_site "$DOMAIN"; SITE_RESULT=$?
   case "$SITE_RESULT" in
     0) CLEAN_COUNT=$((CLEAN_COUNT+1)); CLEAN_SITES+=("$DOMAIN");;
     1) DIRTY_COUNT=$((DIRTY_COUNT+1)); DIRTY_SITES+=("$DOMAIN");;
     *) SKIPPED_COUNT=$((SKIPPED_COUNT+1)); SKIPPED_SITES+=("$DOMAIN");;
   esac
   case "$LAST_HEALTH_STATUS" in
     HEALTHY) HEALTHY_COUNT=$((HEALTHY_COUNT+1));;
     WARNING) HEALTH_WARNING_COUNT=$((HEALTH_WARNING_COUNT+1)); HEALTH_WARNING_SITES+=("$DOMAIN");;
     FAILED) HEALTH_FAILED_COUNT=$((HEALTH_FAILED_COUNT+1)); HEALTH_FAILED_SITES+=("$DOMAIN");;
   esac
 done
 aggregate_health
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

cleanup_old_logs
[ -f "$WARDEN" ] || { echo "ERROR: WP-Warden not found: $WARDEN"; exit 1; }
[ $# -eq 1 ] || usage
if [ "$1" = --all ]; then scan_all; exit $?; fi
DOMAIN="${1,,}"; [[ "$DOMAIN" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] || { echo "ERROR: Invalid domain: $DOMAIN"; exit 1; }
scan_site "$DOMAIN"; exit $?
