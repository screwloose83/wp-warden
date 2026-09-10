# Ridge / SC 4.5.3 detection regression

Tested against the attachments from “WP Warden Detection Failure”: Fragx.zip,
object-cache.php, e0539fae.zip, .sd_ridge-interface-bit and .pv_ridge-interface-bit.
All samples were read as inert bytes. No WordPress or malware code was loaded.

## Reproduced causes

- The existing `PHP_SC_OBFUSCATED_CORE_001` rule **already detects** the 547,590-byte
  core as an ordinary PHP file under the wrapper's 1 MiB limits. Its late `eval`
  position does not explain a miss of this extracted copy with current intel.
- The 24,009-byte object-cache restorer lacked a matching family rule and was
  absent from the coordinated audit's drop-in list.
- Coordinated payload and ZIP detection depended on old Onyx/Aero names.
  The ZIP detector accepted only a member named onyx-wrapper-tap.php.
- Marker handling depended on old Onyx names. Bare version/state files are not
  independently sufficient evidence of malware.
- Files over size limits only received a narrow eval/base64 prefix check; the
  text-size-only skip did not run family prefix checks either.

## Changes in scanner 0.1.83

Adds a content-constrained SCOCV object-cache rule; recognizes SC core boot
guards independently of the plugin slug; checks object-cache.php and PHP files
at the MU-plugin and plugin-main-file level during the coordinated audit.
Related small state files are reported only when a content-confirmed PHP
implant references that slug. They are eligible for existing explicitly enabled
coordinated quarantine, but are described as state rather than executable code.

The early ZIP check now inspects PHP member prefixes without requiring a
specific filename. It never extracts or executes a member. Bounds: archives
at most 16 MiB, first 100 members, up to 256 KiB per PHP member and 8 MiB total
member data per archive. ZIP support is required; the audit warns when it is
missing and wp-content ZIP candidates exist. This is not recursive inspection
of every ZIP anywhere on disk; nested archives and entries beyond these bounds
remain outside this check.

Both PHP size-skip paths run the two narrowly gated core/restorer signatures
against the first 256 KiB. This catches the tested family with trailing padding
without loading multi-megabyte files or removing global scan limits. It does
not promise detection of arbitrary malicious code beyond that prefix.

Regression testing also exposed existing backtrack errors. The Onyx restorer's
whole-file lookaheads are now start-anchored and lazy (same conjunction), and the
fragmented ROT13 rule has additional literal prefilters that its expression
already requires. These avoid errors on these samples without raising limits.

## Validation

```sh
php intel/admin/test-sc-ridge.php
php intel/admin/test-sc-ridge.php /path/to/inert-site-fixture
php intel/admin/test-sc-animal-patterns.php /path/to/previous-batch/3/2
php scanner/wp-warden-pef.php --self-test --intel-dir=intel
```

The optional private fixture places the loader and ZIP in wp-content and the
extracted core in wp-content/mu-plugins/ridge-interface-bit.php. Samples are not
distributed with the repository. Tests exercise the actual rule preparation,
fast matcher, prefix path, ZIP matcher and report-only coordinated audit, with
renamed files, 7 MiB padding, clean lookalikes, unrelated markers and missing ZIP
support. A full report-only scanner run also verifies both original PHP files,
the ZIP, and associated state. Historical scanner/intel files are unchanged.

This reproduces present detection behavior. The original server's exact file
layout, PHP extensions, cached trust decisions and deployed intel at the time
of the reported miss were not available, so the original incident cannot be
attributed to a single cause with certainty.
