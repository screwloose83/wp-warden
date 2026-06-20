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
