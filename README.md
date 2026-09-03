# WP Warden

WordPress malware hunting, integrity verification, and cleanup tooling.

This repository contains two parts:

- `scanner/` - the standalone `wp-warden.php` scanner/remediation tool.
- `intel/` - centralized checksums, whitelists, policies, malware patterns, and helper scripts.

Stable scanner entry points are `scanner/wp-warden-pef.php` and
`scanner/wp-warden-scan-sites.sh`. Release versions are reported from inside
the programs rather than encoded in the command filename.

WP Warden is designed for ApisCP/CWP style multi-server WordPress administration. It favors trusted checksum intel first, then targeted malware heuristics and interactive repair/quarantine actions.

On ApisCP, wrapper discovery checks both the primary `var/www/html` document
root and immediate `var/www/<domain-or-subdomain>` roots containing a
`wp-config.php`. Physical roots exposed through multiple ApisCP aliases are
deduplicated, and document-root symlinks that resolve outside the account's
`var/www` tree are skipped.

When a wrapper scan finishes with critical or high findings still present, it
prints a shell-escaped interactive follow-up command. That command enables
manual repair, quarantine, deletion, and allowlisting choices but does not
enable broad automatic quarantine of extra plugin or theme files.

## Install on a new server

WP Warden is intended to run as `root` on a CWP or ApisCP server. Before
installing it, confirm that Git and PHP CLI are available:

```bash
command -v git
command -v php
php -v
```

PHP 7.4 or newer is required. The JSON, PCRE, tokenizer and hash extensions are
required. cURL, MySQLi and ZIP support are strongly recommended for remote
checksum retrieval, WordPress database auditing, and clean-package repair.
`jq`, `curl`, `tar` and `unzip` are also recommended for the multi-site wrapper.
Package names vary between CWP/ApisCP hosts; on an AlmaLinux/Rocky-style server,
install the missing tools from the PHP repository already used by that server.

Clone the repository into the wrapper's default location:

```bash
git clone https://github.com/screwloose83/wp-warden.git /root/wp-warden
chmod 750 /root/wp-warden/scanner/wp-warden-scan-sites.sh
chmod 750 /root/wp-warden/scanner/wp-find-clean.sh
chmod 750 /root/wp-warden/scanner/wp-warden-pef.php
```

Run the initial self-update. In addition to checking out the latest `main`
commit, this creates/updates the deployed intelligence tree at
`/root/wp-warden/wp-warden-intel`:

```bash
bash /root/wp-warden/scanner/wp-warden-scan-sites.sh --self-update
```

Validate PHP, cache access, intel JSON and all enabled malware expressions
without scanning or modifying a WordPress site:

```bash
php /root/wp-warden/scanner/wp-warden-pef.php \
  --self-test \
  --intel-dir=/root/wp-warden/wp-warden-intel
```

A missing optional ZIP extension is reported as a warning; any self-test failure
should be corrected before production scanning.

Scan a single CWP/ApisCP domain, every discovered WordPress installation, or
only recently modified PHP files:

```bash
bash /root/wp-warden/scanner/wp-warden-scan-sites.sh example.com
bash /root/wp-warden/scanner/wp-warden-scan-sites.sh --all
bash /root/wp-warden/scanner/wp-warden-scan-sites.sh --recent-php-days=7 --all
```

The wrapper creates per-site quarantine directories and writes logs beneath
`/root/wp-warden/logs`. Review the first run carefully before scheduling it.

To update an existing clean Git checkout later:

```bash
bash /root/wp-warden/scanner/wp-warden-scan-sites.sh --check-updates
bash /root/wp-warden/scanner/wp-warden-scan-sites.sh --self-update
```

`--self-update` refuses to overwrite tracked local changes and prints the paths
that block an update.

## Direct scanner example

```bash
php /root/wp-warden/scanner/wp-warden-pef.php /home/site/public_html \
  --intel-dir=/root/wp-warden/wp-warden-intel \
  --verify-all \
  --max-size=50 \
  --max-text-size=1 \
  --apply \
  --quarantine=/home/site/wp-warden-quarantine
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
