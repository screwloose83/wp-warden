"""Offline, curated import. Reads SQL-like records as text; never executes SQL.

Usage: python3 intel/admin/import-antihacker.py /path/to/_rules.txt
New upstream revisions require explicit review of the pin and selections below.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re

REVISION = "cdab7d28f84cfc98bf248729404da6fc6468e559"
SOURCE = f"https://github.com/sminozzi/antihacker/blob/{REVISION}/assets/_rules.txt"
# Require both selected, distinctive indicators instead of upstream 'any of them'.
SELECTED = {
    "ajaxcommand": ["a", "c"], "angel_shell": ["d", "e"],
    "b374k": ["c", "g"], "c100": ["e", "f"], "c99": ["c", "e"],
    "cyb3rsh3ll": ["b", "d"], "r57": ["a", "b"],
    "simatacker": ["a", "g"], "sosyete": ["a", "b"],
    "wso": ["c", "d"], "darkshell": ["a", "b"],
    "pseudo_darkleech": ["a", "b"], "phpmailer": ["h", "j"],
    "phpshell1": ["a", "b"],
}


def convert(raw):
    # Normalize transport line endings only, then verify the reviewed source.
    raw = raw.replace(b"\r\n", b"\n")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != "9a62757277eea8607221e261cb8d8033ef0039e1e23979bf67afc8329b7a01f3":
        raise ValueError("Unreviewed definition bundle: SHA-256 mismatch")
    found = {}
    for line in raw.decode("utf-8-sig").splitlines():
        row = re.fullmatch(r"INSERT INTO .* VALUES\((\d+), (.*)\)\s*;?", line)
        if not row:
            continue
        fields = re.findall(r"'((?:\\.|[^'\\])*)'", row[2])
        if len(fields) != 8:
            raise ValueError("Malformed source record")
        name, strings, condition, description, author, url, _, _ = fields
        name = name[::-1]
        if name not in SELECTED:
            continue
        if name in found or condition[::-1] != "any of them":
            raise ValueError("Duplicate family or changed condition: " + name)
        literals = {}
        for encoded in strings.split(r"\n"):
            if not encoded:
                continue
            definition = base64.b64decode(encoded, validate=True).decode()
            match = re.fullmatch(r'\$(\w+)\s*=\s*("(?:\\.|[^"\\])*")', definition)
            if match and match[1] in SELECTED[name]:
                # These reviewed definitions use JSON-compatible string escapes.
                literals[match[1]] = json.loads(match[2])
        anchors = [literals[key] for key in SELECTED[name]]
        if any(len(value) < 12 for value in anchors):
            raise ValueError("Indicator too broad: " + name)
        found[name] = {
            "id": "EXTERNAL_ANTIHACKER_" + name.upper() + "_001",
            "enabled": True, "severity": "high", "confidence": "medium",
            "type": "regex_file", "anchors": anchors,
            "pattern": r"\A" + "".join(r"(?=[\s\S]*" + re.escape(a) + ")" for a in anchors),
            "report_only": True,
            "description": f"External {name} family indicators occur together; review code before remediation.",
            "source": SOURCE, "source_revision": REVISION,
            "source_rule": name, "source_record_id": int(row[1]),
            "source_author": author[::-1].strip(), "source_reference": url[::-1].strip(),
            "source_condition": condition[::-1],
            "adaptation": "Require all selected literals, case-insensitive, in PHP scan context; report only.",
        }
    if set(found) != set(SELECTED):
        raise ValueError("Missing reviewed families")
    return {"schema": "wp-warden.patterns.php.v1", "source": SOURCE,
            "source_revision": REVISION, "source_sha256_lf": digest,
            "upstream_declared_license": "GPL-2.0-or-later",
            "rules": [found[name] for name in SELECTED]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "patterns/external-malware-rules.json")
    args = parser.parse_args()
    bundle = convert(args.input.read_bytes())
    args.output.write_text(json.dumps(bundle, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"Wrote {len(bundle['rules'])} curated report-only rules to {args.output}")
