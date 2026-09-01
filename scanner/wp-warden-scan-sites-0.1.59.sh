#!/usr/bin/env bash
# Transitional launcher. Use wp-warden-scan-sites.sh for all future releases.
exec bash "$(dirname "$0")/wp-warden-scan-sites.sh" "$@"
