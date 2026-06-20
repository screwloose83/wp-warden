# WP Warden

WordPress malware hunting, integrity verification, and cleanup tooling.

This repository contains two parts:

- `scanner/` - the standalone `wp-warden.php` scanner/remediation tool.
- `intel/` - centralized checksums, whitelists, policies, malware patterns, and helper scripts.

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
