# External definition attribution

The selected strings in external-malware-rules.json are adapted from the
AntiHacker WordPress plugin by sminozzi (Bill Minozzi):
https://github.com/sminozzi/antihacker

Source: assets/_rules.txt at revision
cdab7d28f84cfc98bf248729404da6fc6468e559.
Upstream declares GPL version 2 or later. Its supplied license is reproduced in
ANTIHACKER-LICENSE.txt. Original rule authors and reference URLs, where supplied,
are preserved per rule; selected entries credit @tenacioustek.

WP-Warden adaptations: select 14 PHP families, require two distinctive literals
together instead of any single upstream indicator, use case-insensitive matching
in the existing PHP scan context, and enforce report-only results. No upstream
scanner implementation or executable malware payload is included in this pack.

The offline importer records and verifies the normalized source SHA-256. Do not
replace this curated pack with an unreviewed bulk conversion of the upstream
conditions, regexes or hexadecimal signatures.
