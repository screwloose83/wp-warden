#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-}"

if [ -z "$VERSION" ]; then
  VERSION="$(date -u +%Y.%m.%d.%H%M)"
fi

PACKAGE_NAME="wp-warden-intel-${VERSION}.zip"
OUT_DIR="${ROOT_DIR}/releases"
OUT_FILE="${OUT_DIR}/${PACKAGE_NAME}"
TMP_MANIFEST="$(mktemp)"

mkdir -p "$OUT_DIR"
mkdir -p "$ROOT_DIR/clean-zips"

cd "$ROOT_DIR"

python3 - "$ROOT_DIR/releases/manifest.json" "$TMP_MANIFEST" "$VERSION" "$PACKAGE_NAME" <<'PY'
import json
import sys
from datetime import datetime, timezone

manifest_path, out_path, version, package_name = sys.argv[1:]

with open(manifest_path, "r", encoding="utf-8-sig") as f:
    manifest = json.load(f)

manifest["version"] = version
manifest["created_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
manifest.setdefault("bundle", {})
manifest["bundle"]["format"] = "zip"
manifest["bundle"]["sha256"] = None
manifest["bundle"]["url"] = package_name

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
PY

cp "$TMP_MANIFEST" "$ROOT_DIR/releases/manifest.json"

zip -qr "$OUT_FILE" \
  checksums \
  clean-zips \
  whitelists \
  patterns \
  policy \
  releases/manifest.json \
  README.md

SHA256="$(sha256sum "$OUT_FILE" | awk '{print $1}')"

python3 - "$ROOT_DIR/releases/manifest.json" "$TMP_MANIFEST" "$SHA256" <<'PY'
import json
import sys

manifest_path, out_path, sha256 = sys.argv[1:]

with open(manifest_path, "r", encoding="utf-8-sig") as f:
    manifest = json.load(f)

manifest["bundle"]["sha256"] = sha256

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
PY

cp "$TMP_MANIFEST" "$ROOT_DIR/releases/manifest.json"

zip -q "$OUT_FILE" releases/manifest.json
rm -f "$TMP_MANIFEST"

echo "$OUT_FILE"
echo "$SHA256"
