# WP Warden

First standalone scanner that consumes a `wp-warden-intel` bundle.

## Cron Report Mode

```bash
php wp-warden.php /home/site/public_html \
  --intel-dir=/var/lib/wp-warden/intel \
  --policy=apiscp \
  --site-id=example.com \
  --noninteractive \
  --report-json=/var/log/wp-warden/example.com.json
```

By default, WP Warden prints a human-readable end summary. Add `--report-json=FILE` when you also want the full machine-readable report.

## WordPress Admin User Audit

WP Warden reads `wp-config.php`, connects to the WordPress database, and lists administrator users in the human report.

To flag unexpected admins from cron, provide the approved logins:

```bash
php wp-warden.php /home/site/public_html \
  --verify-all \
  --fetch-official-checksums \
  --known-admins=admin,siteowner \
  --noninteractive
```

For central management, put the approved logins in the intel policy:

```json
"db": {
  "audit_admins": true,
  "known_admins": ["admin", "siteowner"]
}
```

When `known_admins` is empty, the scanner reports the admin users it found but does not flag them.

## WP Warden and Intel Updates

The versioned multi-site wrapper checks GitHub for updates at most once every six hours. A failed network check never blocks a scan. It reports changes separately for the scanner and these deployed intelligence directories:

- `wp-warden-intel/patterns`
- `wp-warden-intel/clean-zips`
- `wp-warden-intel/checksums`

Run a check immediately without scanning a site:

```bash
/root/wp-warden/scanner/wp-warden-scan-sites-0.1.58.sh --check-updates
```

Install a clean fast-forward update and copy published intel files into the deployed intel bundle:

```bash
/root/wp-warden/scanner/wp-warden-scan-sites-0.1.58.sh --self-update
```

The check displays both the installed scanner version/local commit and the newest scanner version/GitHub `main` commit. `--self-update` stops when the Git checkout contains local changes. Intel syncing overwrites published files that changed but preserves local-only files. Override the standard locations with `WP_WARDEN_REPO_ROOT` and `WP_WARDEN_INTEL_ROOT`. Set `WP_WARDEN_UPDATE_CHECK_INTERVAL` to change the default 21,600-second check interval.

## High-confidence Malicious Plugin Families

WP Warden treats version-suffixed `wp2shell-<hex>` and `galex_<hex>` plugin directories as critical malware indicators rather than unknown plugins needing checksum intel. The Galex command-shell content signature also detects renamed copies that accept request-controlled commands and return `[S]`/`[E]` output markers.

With `--apply --quarantine=DIR --quarantine-malware-auto`, WP Warden quarantines the entire containing plugin directory for these high-confidence detections. Without those explicit options, it reports the finding without changing the site.

## Database-to-/tmp wp-config Persistence

WP Warden detects the confirmed `WP_Core_Integrity <hex>` persistence family that injects a PDO loader into `wp-config.php`, reads `_site_transient_health_<hex>` from the WordPress options table, Base64-decodes it, and writes a `/tmp/php...` payload.

Report-only detection happens during every database-enabled scan. Explicit cleanup requires both apply and quarantine controls:

```bash
php wp-warden-pef-0.1.58.php /path/to/wordpress \
  --apply \
  --quarantine=/var/lib/wp-warden/quarantine/site \
  --cleanup-database-persistence-auto
```

Cleanup backs up the infected `wp-config.php` and each database option into the quarantine directory, removes only the confirmed injected block and matching options, and moves the exact `/tmp/php...` payload when it exists. The normal multi-site cleanup pass enables this guarded action automatically because it already supplies `--apply` and a per-site quarantine directory.

## System Cron PHP-Recreation Persistence

WP Warden audits the WordPress filesystem owner's crontab for confirmed jobs that recreate a missing PHP file from a long embedded Base64 payload. On CWP, detection covers PHP targets under the current account's `/home/account` tree so primary and add-on domains are cleaned together. ApisCP and custom layouts remain scoped to the WordPress root. Unrelated cron jobs and other hosting accounts are not changed.

Report-only cron auditing runs automatically. To back up the complete original crontab and remove only the matching persistence entries:

```bash
php wp-warden-pef-0.1.58.php /path/to/wordpress \
  --apply \
  --quarantine=/var/lib/wp-warden/quarantine/site \
  --cleanup-malware-cron-auto
```

The multi-site wrapper enables this guarded cleanup during its first cleanup pass. The following verification pass audits the crontab again to confirm the persistence entry is gone.

## Fetch Official Checksums

On an admin/build machine or a server with outbound HTTPS, you can fetch and cache official checksum sources into the intel directory:

```bash
php wp-warden.php /home/site/public_html \
  --intel-dir=/var/lib/wp-warden/intel \
  --policy=apiscp \
  --fetch-official-checksums \
  --noninteractive \
  --report-json=/var/log/wp-warden/example.com.json
```

This currently supports:

- WordPress core via `https://api.wordpress.org/core/checksums/1.0/`
- wordpress.org plugins via `https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json`
- Fallback checksums via `http://wpmd5.mattjung.net/` when the WordPress.org source is unavailable
- Theme checksums via `http://wpmd5.mattjung.net/theme/{slug}/{version}/` when available

Paid plugins and themes still need local checksum files in `wp-warden-intel/checksums/plugins/` or `wp-warden-intel/checksums/themes/`. WordPress.org does not provide the same official checksum API for arbitrary paid vendor packages.

## Interactive Quarantine Mode

```bash
php wp-warden.php /home/site/public_html \
  --intel-dir=/var/lib/wp-warden/intel \
  --policy=apiscp \
  --site-id=example.com \
  --interactive \
  --apply \
  --quarantine=/var/lib/wp-warden/quarantine/example.com \
  --report-json=/var/log/wp-warden/example.com-cleanup.json
```

When `--interactive --apply` is used, high and critical findings offer an action menu:

```text
V = view preview/details
R = replace modified file from clean package/ZIP, when checksum repair is available
Q = quarantine/move file, when --quarantine is supplied
D = delete permanently
A = allowlist this file hash for this site
S = skip/leave as-is
```

Use a quarantine directory for safer cleanup:

```bash
php wp-warden.php /home/site/public_html \
  --verify-all \
  --fetch-official-checksums \
  --interactive \
  --apply \
  --quarantine=/var/lib/wp-warden/quarantine/site
```

`extra_plugin_file` and `extra_theme_file` findings are report-only in the
multi-site wrapper. Package/checksum sets for premium plugins can be incomplete,
so use `--quarantine-extra-auto` only after confirming the checksum source is a
complete trusted package. A PHP tag in documentation, test fixtures, JavaScript,
HTML, or JSON is also reported for review; automatic malware quarantine requires
a stronger built-in execution heuristic or an explicitly trusted rule.

## Interactive Checksum Repair

When a core/plugin/theme file differs from checksum intel, WP Warden can offer to replace that file from a clean package ZIP.

```bash
php wp-warden.php /home/site/public_html \
  --intel-dir=/var/lib/wp-warden/intel \
  --verify-all \
  --fetch-official-checksums \
  --interactive \
  --apply \
  --repair-original \
  --repair-backup=/var/lib/wp-warden/repair-backups/site
```

Noninteractive automatic repair:

```bash
php wp-warden.php /home/site/public_html \
  --intel-dir=/var/lib/wp-warden/intel \
  --verify-all \
  --fetch-official-checksums \
  --noninteractive \
  --apply \
  --repair-original-auto \
  --repair-backup=/var/lib/wp-warden/repair-backups/site \
  --report-json=/var/log/wp-warden/site-repair.json
```

Repair currently supports clean ZIPs for:

- WordPress core from `wordpress.org`
- wordpress.org plugins from `downloads.wordpress.org`, trying versioned ZIPs first and unversioned ZIPs last
- wordpress.org themes from `downloads.wordpress.org`, trying versioned ZIPs first and unversioned ZIPs last
- WordPress.org plugin/theme SVN tag file fallback after ZIP sources fail
- Paid/vendor plugins and themes when checksum intel includes a `clean_zip` entry

The `wp-warden-intel` helper `admin/add-plugin-zip-checksums.php` can generate paid-plugin checksums and copy the clean vendor ZIP into `clean-zips/plugins/`.

If checksum intel does not include an explicit `clean_zip`, repair also looks for local paid package ZIPs in:

```text
clean-zips/plugins/{slug}.{version}.zip
clean-zips/plugins/{slug}-{version}.zip
clean-zips/plugins/{slug}/{version}.zip
clean-zips/themes/{slug}.{version}.zip
clean-zips/themes/{slug}-{version}.zip
clean-zips/themes/{slug}/{version}.zip
```

## Speed Tips

Fastest normal cleanup run:

```bash
php wp-warden.php /home/site/public_html \
  --intel-dir=/var/lib/wp-warden/intel \
  --verify-all \
  --max-size=50 \
  --max-text-size=1 \
  --apply \
  --interactive \
  --quarantine=/var/lib/wp-warden/quarantine/site
```

For cron reports, avoid interactive prompts:

```bash
php wp-warden.php /home/site/public_html \
  --intel-dir=/var/lib/wp-warden/intel \
  --verify-all \
  --max-size=50 \
  --max-text-size=1 \
  --noninteractive \
  --report-json=/var/log/wp-warden/site.json
```

Best speed improvements:

- Keep paid plugin/theme checksum intel current; trusted matches skip noisy pattern scanning.
- Keep clean ZIPs available for paid plugins so repair does not wait on failed WordPress.org downloads.
- Add large backup/cache folders to `policy/default.json` `skip_relative_prefixes` if you do not want to scan archives on every run.
- Use `--debug-progress` only for troubleshooting; it prints every file and slows scans.
- Use `--newest-first` to inspect recently modified files earlier while still completing the full scan. This changes ordering only; malware can forge or backdate timestamps.
- Use `--recent-php-days=N` for an opt-in quick sweep of recently modified PHP-like files. It is faster but incomplete: follow it with a full scan because malware can use non-PHP extensions or forged timestamps.

## Notes

- `--apply` is required before any file-changing action.
- Noninteractive mode reports only.
- `--repair-original` offers per-file replacement from clean original ZIPs when checksum mismatches are found.
- `--verify-all` reports files that should not exist in core/plugin/theme areas when checksum intel is available.
- Quarantine writes `manifest.jsonl` in the quarantine directory.
- This version focuses on intel-driven scan/report/quarantine. Official ZIP repair from the older script should be ported in the next pass.
