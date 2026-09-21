# WP Warden Intel

Central intelligence bundle for WP Warden scanners.

This repository is intended to be managed centrally and distributed to servers as a ZIP archive. Production servers should consume the exported bundle read-only; they should not directly write global whitelists or detection rules.

## Goals

- Share checksum baselines, whitelists, and detection patterns across ApisCP and CWP servers.
- Support noninteractive cron scans with structured reports.
- Keep quarantine and repair actions explicit, interactive, and auditable.
- Allow admin review before promoting local findings into global trust.

## Layout

```text
checksums/
  wordpress-core/      Official or locally mirrored WordPress core checksum maps.
  plugins/             Plugin checksum maps by slug/version.
  themes/              Theme checksum maps by slug/version.

whitelists/
  global/              Strict organization-wide allowlists.
  sites/               Per-site allowlists, named by site id.

patterns/
  php-malware-rules.json
  db-patterns.json
  process-patterns.json

policy/
  default.json
  apiscp.json
  cwp.json

admin/
  pending-approvals.jsonl
  schema-notes.md

releases/
  manifest.json
```

## Server Use

Recommended scanner flags:

```bash
php wp-warden.php /home/site/public_html \
  --intel-dir=/var/lib/wp-warden/intel \
  --policy=apiscp \
  --site-id=example.com \
  --noninteractive \
  --report-json=/var/log/wp-warden/example.com.json
```

Interactive cleanup should require explicit action flags:

```bash
php wp-warden.php /home/site/public_html \
  --intel-dir=/var/lib/wp-warden/intel \
  --policy=apiscp \
  --site-id=example.com \
  --interactive \
  --apply \
  --quarantine=/var/lib/wp-warden/quarantine/example.com
```

## Build A ZIP Package

From Linux/macOS:

```bash
cd wp-warden-intel
bash admin/build-package.sh 0.1.1
```

From PowerShell:

```powershell
cd wp-warden-intel
.\admin\build-package.ps1 -Version 0.1.1
```

The package is written to `releases/wp-warden-intel-VERSION.zip`, and `releases/manifest.json` is updated with the package name and SHA-256 hash.

## Import Raw Malware Patterns

Raw regex lists can be imported into `patterns/community-malware-rules.json`.

Linux/macOS:

```bash
bash admin/import-raw-patterns.sh /path/to/patterns_raw.txt
```

PowerShell:

```powershell
.\admin\import-raw-patterns.ps1 -InputFile C:\path\patterns_raw.txt
```

The scanner loads both `patterns/php-malware-rules.json` and `patterns/community-malware-rules.json`.

## Curated external definitions (scanner v0.1.87)

The scanner additionally loads `patterns/external-malware-rules.json` automatically.
The first bundle adapts 14 named PHP malware/webshell families from AntiHacker:
Ajax Command Shell, Angel Shell, b374k, c100, c99, cyb3rsh3ll, r57, SimAttacker,
Sosyete, WSO, Dark Shell, pseudo-Darkleech, malicious mailer and phpshell1.
Each rule requires two selected indicators together. Broad upstream checks such
as PHPMailer class names, security-site URLs and standalone system commands were
not imported. This is a curated subset of 797 upstream records, not a complete
AntiHacker or YARA engine, and does not guarantee detection of all variants.

These findings are HIGH and report-only, including with automatic quarantine
enabled. Their rule IDs are isolated from trusted cleanup IDs; the source URL,
revision and original family are retained in JSON findings. Existing local rules
may independently detect and remediate the same file. Normal size, exclusion,
PHP-context and allowlist rules still apply. New definitions invalidate the
relevant scan cache. No third-party code, SQL or malware is executed, and scans
use the bundled definitions without fetching external feeds.

To reproduce this bundle, download `assets/_rules.txt` from AntiHacker revision
`cdab7d28f84cfc98bf248729404da6fc6468e559`, then run:

```bash
python3 intel/admin/import-antihacker.py /path/to/_rules.txt
php intel/admin/test-external-definitions.php
```

The importer verifies the pinned source checksum before writing output. A new
upstream revision requires reviewing the selections and updating the pin; it is
not silently trusted. The other upstream rule files include malformed records
and are not accepted by this importer. Attribution and license text ship in
`patterns/ANTIHACKER-NOTICE.md` and `patterns/ANTIHACKER-LICENSE.txt`.

## Add Paid Plugin Checksums

Use a clean vendor ZIP, not a copy taken from an infected server.

```bash
php admin/add-plugin-zip-checksums.php \
  /root/clean-zips/unlimited-elements-for-elementor-premium.2.0.10.zip \
  unlimited-elements-for-elementor-premium \
  2.0.10
```

This writes the checksum file and stores a copy of the clean ZIP:

```text
checksums/plugins/unlimited-elements-for-elementor-premium/2.0.10.json
clean-zips/plugins/unlimited-elements-for-elementor-premium.2.0.10.zip
```

Then build and publish a new intel ZIP:

```bash
bash admin/build-package.sh 0.1.6
```

PowerShell:

```powershell
.\admin\build-package.ps1 -Version 0.1.6
```

Scanners can then replace modified paid-plugin files from that clean ZIP when run with repair enabled.

## Known WordPress Admins

The scanner can audit administrator users directly from the WordPress database. Add approved logins to the active policy before building a package:

```json
"db": {
  "audit_admins": true,
  "known_admins": ["admin", "siteowner"]
}
```

If `known_admins` is empty, admin users are shown in the report but are not flagged. If it contains one or more logins, any other administrator account is reported as `unknown_admin_user`.

## Admin Flow

1. Server runs scanner and writes JSON report.
2. Admin reviews findings.
3. Known-good custom files, cron jobs, or processes are added to `admin/pending-approvals.jsonl`.
4. A reviewer promotes approved entries into `whitelists/global/` or `whitelists/sites/`.
5. A new ZIP bundle is published with an updated `releases/manifest.json`.

## Safety Rules

- Global whitelists should be rare and reviewed.
- Per-site whitelists are preferred for custom plugins/themes.
- Findings from infected servers should not be auto-promoted.
- Destructive scanner actions should require `--apply`.
- Cron mode should report only by default.
