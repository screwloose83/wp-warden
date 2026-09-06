# SC persistence and encrypted web-shell patterns

Added nine reviewed content rules to `patterns/php-malware-rules.json` on 2026-09-06.

| Rule suffix | Coverage |
| --- | --- |
| ANIMAL_XOR_TEMP_INCLUDE_001 | URL-safe alphabet / repeating XOR decoder that writes, includes and deletes a `shf_` temporary payload. Matches all 14 encrypted web-shell components in the supplied batch without depending on their animal filenames or encryption keys. |
| SC_RESTORER_FAMILY_001 | Combined SC-family unpadding, padding, hidden-core loading and validation helpers in obfuscated restorers. |
| SC_HASHED_HIDDEN_INCLUDE_001 | Hash-verified hidden companion loader; permits different eight-hex filenames and MD5 values. |
| SC_SCD1_PACKED_CORE_001 | Versioned SCD1 gzip/Base64 payload envelope, including `.dat` and `.lkg` copies. |
| SC_KNOWN_PREPEND_CONFIG_001 | Active auto-prepend directives referencing the confirmed `bac4a7ce.php` or `735e7808.php` loaders under wp-content. Deliberately does not flag all auto-prepend usage or arbitrary hashed filenames. |
| SC_OBFUSCATED_CORE_001 | SCV-marked obfuscated core with boot-version guard identifiers. |
| ONYX_WRAPPER_RESTORER_001 | Onyx Wrapper Tap installer/restorer requiring its implant path plus both hidden state and recovery markers. |
| ONYX_AERO_BRIDGE_IMPLANT_001 | SC-family core masquerading as the fictional Aero Bridge Pad WordPress plugin. |
| ONYX_STATUS_BEACON_001 | Generated status artifact naming the Onyx mu-plugin path, successful state and boot timestamp. |

All IDs have the `PHP_` prefix. The stable scanner's early reviewed-rule list includes these IDs. This is necessary for the configuration and SCD1 rules: those files lack PHP tags and would otherwise fail the generic PHP-context gate. Deploy the scanner change together with the intel change; pattern JSON alone on an older scanner does not guarantee these non-PHP matches.

The two supplied SCD1 files are identical. Static base64/gzip decoding recovers the exact earlier core sample, SHA-256 `c448888d231f065f9d55dd2dda974465d79a9dfff960d57badf07b3fabdfd108`. The web-shell components decode to administrator restoration, remote credential authentication, file management and PHP execution features. No sample was executed or contacted remotely.

## Validation

Run without private samples for synthetic positive/negative checks:

```sh
php intel/admin/test-sc-animal-patterns.php
php scanner/wp-warden-pef.php --self-test --intel-dir=intel
```

An optional first argument points to the supplied `3/2` sample directory. This checks all 22 nonempty files recursively and the earlier core, installer and theme backup in its parent. Samples are read as inert data by actual scanner rule-preparation, text-reader and early-matching functions. Private malware samples are not shipped in the repository.

Verified on PHP 8.4: all 22 nonempty new samples and both earlier malware samples match; the theme backup and eight synthetic negative cases do not. All 407 enabled intel expressions compile; scanner self-test passes (38 checks, optional ZIP-extension warning).

Three empty marker files are not executable payloads and intentionally receive no content signature. These rules are family signatures, not general deobfuscation: changing the decoder structure or family identifiers may evade them. Existing scan exclusions and size limits still apply. For the family's multi-megabyte padded copies, increase both `--max-size` and `--max-text-size` (for example, to 50 and 10 MB respectively). Review malicious directives within configuration files while preserving unrelated settings.

Changes are local source updates; no remote release, deployment or remediation is performed by these tests.
