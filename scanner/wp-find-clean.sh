#!/usr/bin/env bash
set -u
set -o pipefail
shopt -s nullglob

TYPE="${1:-}"
SLUG="${2:-}"
VERSION="${3:-}"
MODE="${4:-}"
MIN_MATCHING_COPIES="${WP_WARDEN_RECOVERY_MIN_COPIES:-4}"
WORK_ROOT="${WP_WARDEN_RECOVERY_WORK_ROOT:-/root/wp-warden/recovery-candidates}"
ZIP_ROOT="${WP_WARDEN_RECOVERY_ZIP_ROOT:-/root/wp-recovered-zips}"

usage(){ echo "Usage: $0 plugin|theme SLUG VERSION [--zip]" >&2; exit 1; }
[[ "$TYPE" = plugin || "$TYPE" = theme ]] || usage
[[ "$SLUG" =~ ^[A-Za-z0-9._-]+$ ]] || usage
[[ "$VERSION" =~ ^[A-Za-z0-9._+-]+$ ]] || usage
[[ -z "$MODE" || "$MODE" = --zip ]] || usage
[[ "$MIN_MATCHING_COPIES" =~ ^[1-9][0-9]*$ ]] || { echo "Invalid recovery threshold" >&2; exit 1; }

for CMD in find grep sed sha256sum sort awk basename dirname xargs; do
    command -v "$CMD" >/dev/null 2>&1 || { echo "Missing required command: $CMD" >&2; exit 1; }
done

KIND_DIR="${TYPE}s"
RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
TARGET="${WORK_ROOT}/${TYPE}-${SLUG}-${VERSION}-${RUN_ID}"
mkdir -p "$TARGET/manifests" "$TARGET/php-manifests"

component_version(){
    local DIR="$1" HEADER="" VALUE=""
    if [ "$TYPE" = theme ]; then
        HEADER="$DIR/style.css"
    elif [ -f "$DIR/$SLUG.php" ]; then
        HEADER="$DIR/$SLUG.php"
    else
        HEADER="$(grep -rilm1 --include='*.php' -E '^[[:space:]]*\*?[[:space:]]*Plugin Name:[[:space:]]*' "$DIR" 2>/dev/null | head -n 1)"
    fi
    [ -f "$HEADER" ] || return 1
    VALUE="$(grep -im1 -E '^[[:space:]]*\*?[[:space:]]*Version:[[:space:]]*' "$HEADER" 2>/dev/null |
        sed -E 's/^[[:space:]]*\*?[[:space:]]*Version:[[:space:]]*//; s/[[:space:]]*\*\/.*$//; s/[[:space:]]*$//')"
    [ -n "$VALUE" ] || return 1
    printf '%s\n' "$VALUE"
}

MATCHES=()
while IFS= read -r -d '' DIR; do
    FOUND_VERSION="$(component_version "$DIR" || true)"
    [ "$FOUND_VERSION" = "$VERSION" ] && MATCHES+=("$DIR")
done < <(find /home -maxdepth 10 -type d -path "*/wp-content/${KIND_DIR}/${SLUG}" -print0 2>/dev/null)

COUNT="${#MATCHES[@]}"
echo "[RECOVERY] $TYPE $SLUG $VERSION: found $COUNT matching installation(s)"
[ "$COUNT" -gt 0 ] || exit 2

declare -A GROUP_COUNT GROUP_PATHS
for INDEX in "${!MATCHES[@]}"; do
    DIR="${MATCHES[$INDEX]}"
    MANIFEST="$TARGET/manifests/$INDEX.sha256"
    PHP_MANIFEST="$TARGET/php-manifests/$INDEX.sha256"
    (cd "$DIR" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$MANIFEST"
    (cd "$DIR" && find . -type f -name '*.php' -print0 | sort -z | xargs -0 sha256sum) > "$PHP_MANIFEST"
    HASH="$(sha256sum "$MANIFEST" | awk '{print $1}')"
    GROUP_COUNT["$HASH"]=$(( ${GROUP_COUNT["$HASH"]:-0} + 1 ))
    GROUP_PATHS["$HASH"]="${GROUP_PATHS["$HASH"]:-}|$DIR"
done

MAJORITY_HASH=""
MAJORITY_COUNT=0
for HASH in "${!GROUP_COUNT[@]}"; do
    N="${GROUP_COUNT[$HASH]}"
    echo "[RECOVERY] fileset $HASH: $N identical copy/copies"
    if (( N > MAJORITY_COUNT )); then MAJORITY_COUNT="$N"; MAJORITY_HASH="$HASH"; fi
done

CONSENSUS=$((MAJORITY_COUNT * 100 / COUNT))
BEST_PATH="${GROUP_PATHS[$MAJORITY_HASH]#|}"
BEST_PATH="${BEST_PATH%%|*}"
echo "[RECOVERY] consensus: $MAJORITY_COUNT/$COUNT (${CONSENSUS}%)"
echo "[RECOVERY] candidate: $BEST_PATH"
echo "[RECOVERY] manifests: $TARGET"

[ "$MODE" = --zip ] || exit 0
if (( MAJORITY_COUNT < MIN_MATCHING_COPIES )); then
    echo "[RECOVERY] ZIP not created: requires $MIN_MATCHING_COPIES identical copies"
    exit 6
fi
command -v zip >/dev/null 2>&1 || { echo "[RECOVERY] ZIP not created: zip is unavailable"; exit 7; }
command -v unzip >/dev/null 2>&1 || { echo "[RECOVERY] ZIP not created: unzip is unavailable"; exit 7; }

ZIP_DIR="$ZIP_ROOT/$KIND_DIR"
ZIP_FILE="$ZIP_DIR/$SLUG.$VERSION.zip"
mkdir -p "$ZIP_DIR"
if [ -e "$ZIP_FILE" ]; then ZIP_FILE="$ZIP_DIR/$SLUG.$VERSION.$RUN_ID.zip"; fi
(cd "$(dirname "$BEST_PATH")" && zip -q -r "$ZIP_FILE" "$(basename "$BEST_PATH")")
unzip -t "$ZIP_FILE" >/dev/null 2>&1 || { echo "[RECOVERY] ZIP verification failed: $ZIP_FILE"; exit 5; }
echo "[RECOVERY] candidate ZIP: $ZIP_FILE"
sha256sum "$ZIP_FILE"
echo "[RECOVERY] REVIEW REQUIRED: consensus is not proof that this package is vendor-clean."
