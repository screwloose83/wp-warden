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

## Notes

- `--apply` is required before any file-changing action.
- Noninteractive mode reports only.
- `--repair-original` offers per-file replacement from clean original ZIPs when checksum mismatches are found.
- `--verify-all` reports files that should not exist in core/plugin/theme areas when checksum intel is available.
- Quarantine writes `manifest.jsonl` in the quarantine directory.
- This version focuses on intel-driven scan/report/quarantine. Official ZIP repair from the older script should be ported in the next pass.
