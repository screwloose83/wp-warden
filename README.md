# WP Warden

WordPress malware hunting, integrity verification, and cleanup tooling.

This repository contains two parts:

- `scanner/` - the standalone `wp-warden.php` scanner/remediation tool.
- `intel/` - centralized checksums, whitelists, policies, malware patterns, and helper scripts.

Stable scanner entry points are `scanner/wp-warden-pef.php` and
`scanner/wp-warden-scan-sites.sh`. Release versions are reported from inside
the programs rather than encoded in the command filename.

WP Warden is designed for ApisCP/CWP style multi-server WordPress administration. It favors trusted checksum intel first, then targeted malware heuristics and interactive repair/quarantine actions.

## Quick Start

```bash
php scanner/wp-warden.php /home/site/public_html \
  --intel-dir=/var/lib/wp-warden/intel \
  --verify-all \
  --max-size=50 \
  --max-text-size=1 \
  --apply \
  --quarantine=/var/lib/wp-warden/quarantine/site
```

See `scanner/README.md` and `intel/README.md` for usage and intel package management.

## Missing checksum intel recovery

The multi-site wrapper automatically runs `scanner/wp-find-clean.sh` after a
scan reports missing plugin or theme checksum intel. The helper compares every
matching installation under `/home` and stores manifests beneath
`/root/wp-warden/recovery-candidates`.

When at least four complete copies are byte-for-byte identical, it also creates
a candidate ZIP beneath `/root/wp-recovered-zips/plugins` or
`/root/wp-recovered-zips/themes`. Candidate ZIPs are deliberately not promoted
to trusted intel automatically: consensus does not prove a package is clean.

Set `WP_WARDEN_RECOVER_MISSING_INTEL=0` to disable the trigger, or change the
minimum with `WP_WARDEN_RECOVERY_MIN_COPIES`.
