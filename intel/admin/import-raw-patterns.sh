#!/usr/bin/env bash
set -euo pipefail

INPUT_FILE="${1:-}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_FILE="${2:-$ROOT_DIR/patterns/community-malware-rules.json}"

if [ -z "$INPUT_FILE" ] || [ ! -f "$INPUT_FILE" ]; then
  echo "Usage: $0 /path/to/raw-patterns.txt [output-json]" >&2
  exit 1
fi

python3 - "$INPUT_FILE" "$OUTPUT_FILE" <<'PY'
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

input_file, output_file = sys.argv[1:]

critical_terms = [
    "@eval", r"eval\\s*\\(", r"eval\(", r"assert\\s*\\(", r"system\\s*\\(",
    r"passthru\\s*\\(", "bindshell", "ConnectBackShell", "ShellBOT",
    "wp-vcd", "WordpressApieSystem", "jquerysv", r"HTTP_[A-Z0-9_]+",
    "/etc/shadow", r"GIF89A;<\\?php",
]
high_terms = [
    "base64_decode", "gzinflate", "str_rot13", "create_fun", "preg_replace",
    "HACKED BY", "Backdoor", "SHELL_PASSWORD", "php_uname", "/etc/passwd",
    "wp_set_auth_cookie", "wp_set_current_user",
]

def strip_delimiters(line):
    m = re.match(r"^/(.*)/([a-zA-Z]*)\s*$", line)
    return m.group(1) if m else line

def severity(pattern):
    for term in critical_terms:
        if re.search(term, pattern, re.I):
            return "critical"
    for term in high_terms:
        if re.search(term, pattern, re.I):
            return "high"
    return "medium"

rules = []
with open(input_file, "r", encoding="utf-8", errors="replace") as f:
    for raw in f:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pattern = strip_delimiters(line)
        sev = severity(pattern)
        rules.append({
            "id": f"COMMUNITY_MALWARE_{len(rules) + 1:04d}",
            "enabled": True,
            "severity": sev,
            "confidence": "high" if sev == "critical" else "medium",
            "type": "regex_file",
            "pattern": pattern,
            "description": "Imported community malware signature.",
        })

payload = {
    "schema": "wp-warden.patterns.php.v1",
    "source": "imported raw regex list",
    "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "rules": rules,
}

Path(output_file).parent.mkdir(parents=True, exist_ok=True)
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
    f.write("\n")

print(output_file)
print(f"Imported {len(rules)} rules")
PY
