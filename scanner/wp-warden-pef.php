#!/usr/bin/env php
<?php
/**
 * WP Warden - WordPress malware and integrity scanner (stable entry point).
 *
 * First standalone version wired to the wp-warden-intel bundle layout.
 * Noninteractive runs are report-only unless --apply is supplied.
 */

const WP_WARDEN_VERSION = '0.1.60';
const WP_WARDEN_CACHE_VERSION = '3';

$opts = parse_args($argv);
@ini_set('pcre.backtrack_limit', '500000');
@ini_set('pcre.recursion_limit', '500000');

if (isset($opts['help']) || (empty($opts['target']) && !isset($opts['self-test']))) {
    print_help();
    exit(isset($opts['help']) ? 0 : 1);
}

$intelDirExplicit = isset($opts['intel-dir']) && is_string($opts['intel-dir']);
$intelDir = normalize_path($intelDirExplicit ? $opts['intel-dir'] : __DIR__ . '/../wp-warden-intel');
if (!$intelDirExplicit && !is_dir($intelDir . '/patterns')) {
    $repositoryIntelDir = normalize_path(__DIR__ . '/../intel');
    if (is_dir($repositoryIntelDir . '/patterns')) {
        fwrite(STDERR, "WARN: deployed intel bundle not found at $intelDir; using repository intel: $repositoryIntelDir\n");
        $intelDir = $repositoryIntelDir;
    }
}
$slowRuleMs = isset($opts['slow-rule-ms']) && ctype_digit((string)$opts['slow-rule-ms'])
    ? (int)$opts['slow-rule-ms'] : 250;
$slowFileMs = isset($opts['slow-file-ms']) && ctype_digit((string)$opts['slow-file-ms'])
    ? (int)$opts['slow-file-ms'] : 1000;
$scanRuntime = [
    'pcre_error_paths' => [],
    'generic_rule_paths' => [],
];

if (isset($opts['self-test'])) {
    exit(run_self_test($intelDir, $slowRuleMs));
}

$target = normalize_path($opts['target']);
if (!is_dir($target)) {
    fwrite(STDERR, "ERROR: target is not a directory: {$opts['target']}\n");
    exit(1);
}

$policyId = $opts['policy'] ?? 'default';
$siteId = $opts['site-id'] ?? basename($target);
$reportJson = $opts['report-json'] ?? null;
$nonInteractive = isset($opts['noninteractive']);
$interactive = isset($opts['interactive']) || !$nonInteractive;
$apply = isset($opts['apply']);
$verifyAll = isset($opts['verify-all']);
$quarantineDir = isset($opts['quarantine']) ? normalize_path($opts['quarantine']) : null;
$maxSizeMb = isset($opts['max-size']) ? max(1, (int)$opts['max-size']) : 10;
$maxTextSizeMb = isset($opts['max-text-size']) ? max(1, (int)$opts['max-text-size']) : 5;
$quiet = isset($opts['quiet']);
$debugProgress = isset($opts['debug-progress']);
$newestFirst = isset($opts['newest-first']);
$recentPhpDays = isset($opts['recent-php-days']) ? max(1, (int)$opts['recent-php-days']) : null;
$fetchOfficialChecksums = isset($opts['fetch-official-checksums']) || isset($opts['fetch-official']);
$quarantineExtraAuto = isset($opts['quarantine-extra-auto']);
$quarantineExtraCoreAuto = isset($opts['quarantine-extra-core-auto']);
$quarantineMalwareAuto = $opts['quarantine-malware-auto'] ?? false;
$quarantineWpContentAuto = isset($opts['quarantine-wp-content-auto']);
$repairOriginal = isset($opts['repair-original']) || isset($opts['repair-official']) || isset($opts['repair-original-auto']);
$repairOriginalAuto = isset($opts['repair-original-auto']);
$repairBackupDir = isset($opts['repair-backup']) && is_string($opts['repair-backup'])
    ? normalize_path($opts['repair-backup'])
    : normalize_path(__DIR__ . '/repair-backups-' . gmdate('Ymd-His'));
$packageCacheDir = isset($opts['package-cache']) && is_string($opts['package-cache'])
    ? normalize_path($opts['package-cache'])
    : normalize_path(__DIR__ . '/package-cache');
$knownAdminsOverride = isset($opts['known-admins']) && is_string($opts['known-admins'])
    ? array_values(array_filter(array_map('trim', explode(',', $opts['known-admins']))))
    : null;
$cleanupMalwareUsersAuto = isset($opts['cleanup-malware-users-auto']);
$cleanupDatabasePersistenceAuto = isset($opts['cleanup-database-persistence-auto']);
$cleanupMalwareCronAuto = isset($opts['cleanup-malware-cron-auto']);
$promptUnknownAdmins = isset($opts['prompt-unknown-admins']);
$excludePdf = isset($opts['exclude-pdf']);
$vulnerabilityScan = isset($opts['vulnerability-scan']);
$wordfenceApiKeyFile = isset($opts['wordfence-api-key-file']) && is_string($opts['wordfence-api-key-file'])
    ? normalize_path($opts['wordfence-api-key-file'])
    : normalize_path(dirname(__DIR__) . '/wordfence-intelligence.key');
$allowedWpContentDirsOverride = isset($opts['allow-wp-content-dir']) && is_string($opts['allow-wp-content-dir'])
    ? array_values(array_filter(array_map('trim', explode(',', $opts['allow-wp-content-dir']))))
    : [];
$fileCacheEnabled = !isset($opts['no-file-cache']);
$fileCacheDir = isset($opts['file-cache']) && is_string($opts['file-cache'])
    ? normalize_path($opts['file-cache'])
    : normalize_path(dirname(__DIR__) . '/cache');
$fileCacheEntries = [];
$fileCacheSeen = [];
$fileCacheDirty = false;
$fileCachePath = null;
$fileCacheSignature = null;
$fileCacheContext = [];

$state = [
    'started_at' => gmdate('c'),
    'target' => $target,
    'site_id' => $siteId,
    'intel_dir' => $intelDir,
    'policy' => $policyId,
    'apply' => $apply,
    'findings' => [],
    'actions' => [],
    'checksum_intel' => [
        'missing_plugins' => [],
        'missing_themes' => [],
        'unknown_plugin_versions' => [],
        'unknown_theme_versions' => [],
        'backup_plugin_dirs' => [],
        'backup_theme_dirs' => [],
        'built_from_local_zip' => [],
        'built_from_official_zip' => [],
    ],
    'updates' => [
        'core' => null,
        'plugins' => [],
        'themes' => [],
        'unknown' => [],
        'auto_update' => [],
    ],
    'vulnerabilities' => [
        'enabled' => $vulnerabilityScan,
        'status' => $vulnerabilityScan ? 'PENDING' : 'NOT_RUN',
        'sources' => [],
        'wordpress' => [],
        'composer' => [],
        'errors' => [],
        'summary' => ['total'=>0,'wordpress'=>0,'composer'=>0,'unpatched'=>0],
    ],
    'timing' => [
        'http_requests' => 0,
        'http_failures' => 0,
        'http_seconds' => 0.0,
        'repair_attempts' => 0,
        'repair_failures' => 0,
        'repair_seconds' => 0.0,
        'svn_attempts' => 0,
        'svn_failures' => 0,
        'svn_seconds' => 0.0,
        'pcre_errors' => 0,
        'slow_rules' => 0,
        'slow_files' => 0,
        'slowest_rule' => null,
        'slowest_file' => null,
    ],
    'db_audit' => [
        'admin_users' => [],
        'known_admins' => [],
        'active_plugins' => [],
        'persistence_findings' => [],
        'option_iocs' => [],
        'cron_iocs' => [],
        'system_cron_iocs' => [],
        'usermeta_iocs' => [],
        'config_iocs' => [],
        'error' => null,
    ],
    'summary' => [
        'files_seen' => 0,
        'files_scanned' => 0,
        'files_skipped' => 0,
        'benign_index_skipped' => 0,
        'findings_total' => 0,
        'critical' => 0,
        'high' => 0,
        'medium' => 0,
        'low' => 0,
        'info' => 0,
        'actions_taken' => 0,
        'cache_hits' => 0,
        'cache_misses' => 0,
        'cache_entries' => 0,
        'large_files_deep_scan_skipped' => 0,
        'symlinks_detected' => 0,
        'file_classifications' => [],
    ],
];
$handledInteractivePaths = [];
$runStartedMicro = microtime(true);

$intel = load_intel($intelDir, $policyId, $siteId);
$wpRoot = realpath($target) ?: $target;
$wpVersion = detect_wp_version($wpRoot);
$locale = detect_wp_locale($wpRoot);
$coreChecksums = load_core_checksums($intelDir, $wpVersion, $locale, $fetchOfficialChecksums);
$componentChecksums = load_component_checksums($wpRoot, $intelDir, $fetchOfficialChecksums);
$state['timing']['intel_and_checksums_seconds'] = round(microtime(true) - $runStartedMicro, 3);
$updateStartedMicro = microtime(true);
$state['updates'] = check_update_health($wpRoot, $wpVersion, $intelDir);
$state['timing']['update_health_seconds'] = round(microtime(true) - $updateStartedMicro, 3);

if ($vulnerabilityScan) {
    $vulnStartedMicro = microtime(true);
    $state['vulnerabilities'] = scan_vulnerabilities($wpRoot, $wpVersion, $intelDir, $wordfenceApiKeyFile);
    $state['timing']['vulnerability_scan_seconds'] = round(microtime(true) - $vulnStartedMicro, 3);
}

if ($fileCacheEnabled) {
    $fileCacheContext = build_file_cache_context($intel, $coreChecksums, $componentChecksums, $verifyAll, $maxSizeMb, $maxTextSizeMb, $excludePdf);
    // Retain a global signature for cache metadata and diagnostics. Unlike v0.1.41,
    // a global mismatch no longer discards every cached file; each file carries its
    // own signature covering only the intel that can affect that path.
    $fileCacheSignature = hash('sha256', serialize($fileCacheContext));
    $fileCachePath = file_cache_path($fileCacheDir, $wpRoot);
    $fileCacheEntries = load_file_cache($fileCachePath, $fileCacheSignature, $wpRoot);
}

say("======================================================================", true);
say("                         WP WARDEN", true);
say("", true);
say("                    In Memory Of Amy", true);
say("                         2010 - 2026", true);
say("======================================================================", true);
say("WP Warden " . WP_WARDEN_VERSION, true);
say("Target: $wpRoot", true);
say("Intel:  $intelDir", true);
say("Policy: $policyId", true);
if ($excludePdf) { say("Mode:   PDF files excluded from scanning (--exclude-pdf)", true); }
if ($newestFirst) { say("Mode:   newest files scanned first (--newest-first)", true); }
if ($recentPhpDays !== null) { say("Mode:   QUICK SWEEP - only PHP-like files modified in the last {$recentPhpDays} day(s); this is not a full scan", true); }
if ($fileCacheEnabled) {
    say("Cache:  $fileCachePath", true);
    say("Cache:  " . count($fileCacheEntries) . " clean file entries loaded", true);
} else {
    say("Cache:  disabled (--no-file-cache)", true);
}
if (!$apply) {
    say("Mode:   report-only; no file changes will be made without --apply", true);
} elseif (!$quarantineDir) {
    say("Mode:   apply enabled, but no --quarantine directory was supplied; no files will be moved", true);
}
if ($repairOriginal && !$apply) {
    say("Mode:   repair requested, but --apply is missing; repairs will be offered as report-only", true);
}
if ($quarantineExtraAuto) {
    if (!$apply) {
        say("WARN: --quarantine-extra-auto requires --apply; automatic quarantine is disabled", true);
    } elseif (!$quarantineDir) {
        say("WARN: --quarantine-extra-auto requires --quarantine=DIR; automatic quarantine is disabled", true);
    } else {
        say("Mode:   auto-quarantine enabled for checksum-proven extra plugin/theme files", true);
    }
}
if ($quarantineExtraCoreAuto) {
    if (!$apply) {
        say("WARN: --quarantine-extra-core-auto requires --apply; automatic core-extra quarantine is disabled", true);
    } elseif (!$quarantineDir) {
        say("WARN: --quarantine-extra-core-auto requires --quarantine=DIR; automatic core-extra quarantine is disabled", true);
    } else {
        say("Mode:   auto-quarantine enabled for checksum-proven extra WordPress core files", true);
    }
}
if ($quarantineMalwareAuto !== false) {
    if (!$apply) {
        say("WARN: --quarantine-malware-auto requires --apply; automatic malware quarantine is disabled", true);
    } elseif (!$quarantineDir) {
        say("WARN: --quarantine-malware-auto requires --quarantine=DIR; automatic malware quarantine is disabled", true);
    } else {
        say("Mode:   auto-quarantine enabled only for reviewed built-in/external rule IDs plus executable_in_uploads; other heuristic/community findings are report-only", true);
    if ($quarantineWpContentAuto) { say("Mode:   auto-quarantine enabled for suspicious unexpected wp-content directories", true); }
    }
}
if ($cleanupDatabasePersistenceAuto) {
    if (!$apply || !$quarantineDir) {
        say("WARN: --cleanup-database-persistence-auto requires --apply and --quarantine=DIR; persistence cleanup is disabled", true);
    } else {
        say("Mode:   confirmed wp-config/database/tmp persistence cleanup enabled", true);
    }
}
if ($cleanupMalwareCronAuto) {
    if (!$apply || !$quarantineDir) {
        say("WARN: --cleanup-malware-cron-auto requires --apply and --quarantine=DIR; system cron cleanup is disabled", true);
    } else {
        say("Mode:   confirmed malicious system cron cleanup enabled", true);
    }
}
if ($wpVersion) {
    say("WordPress: $wpVersion ($locale)", true);
}

say("Auditing wp-content directories...", true);
audit_wp_content_directories($wpRoot);
say("Auditing suspicious upload bundles...", true);
audit_malicious_upload_bundle_directories($wpRoot);
say("Auditing known malicious plugin directory names...", true);
audit_malicious_plugin_directories($wpRoot);
say("Auditing wp-config.php persistence...", true);
audit_wp_config_persistence($wpRoot);
say("Auditing system cron persistence...", true);
audit_system_cron_persistence($wpRoot);
say("Auditing symlinks...", true);
audit_wordpress_symlinks($wpRoot, $intel);
say("Scanning files...", true);
$scanStartedMicro = microtime(true);
scan_tree($wpRoot, $intel, $coreChecksums, $componentChecksums);
$state['timing']['file_scan_seconds'] = round(microtime(true) - $scanStartedMicro, 3);
save_file_cache();
say("File scan complete. Auditing WordPress admin users...", true);
audit_wordpress_admins($wpRoot, $intel);
say("Building report...", true);

$state['finished_at'] = gmdate('c');
$state['timing']['total_seconds'] = round(microtime(true) - $runStartedMicro, 3);
$state['summary']['findings_total'] = count($state['findings']);

if ($reportJson) {
    write_json_report($reportJson, $state);
    say("Report written: $reportJson", true);
}
print_human_report($state, $reportJson);

$exit = ($state['summary']['critical'] > 0 || $state['summary']['high'] > 0) ? 1 : 0;
exit($exit);

function print_help(): void {
    echo "WP Warden - WordPress malware and integrity scanner\n\n";
    echo "USAGE:\n";
    echo "  php wp-warden.php /path/to/wordpress [options]\n\n";
    echo "OPTIONS:\n";
    echo "  --intel-dir=DIR         Extracted wp-warden-intel directory\n";
    echo "  --policy=ID             Policy id: default, apiscp, cwp\n";
    echo "  --site-id=ID            Site identifier for per-site whitelist\n";
    echo "  --report-json=FILE      Also write a structured JSON report\n";
    echo "  --noninteractive        Cron-safe report mode\n";
    echo "  --interactive           Prompt for allowed actions\n";
    echo "  --apply                 Permit quarantine/actions\n";
    echo "  --quarantine=DIR        Quarantine directory for moved files\n";
    echo "  --quarantine-extra-auto Auto-quarantine extra plugin/theme files absent from a complete trusted checksum set; requires --apply and --quarantine\n";
    echo "  --quarantine-extra-core-auto Auto-quarantine files in wp-admin/wp-includes absent from official core checksums; requires --apply and --quarantine\n";
    echo "  --quarantine-malware-auto Auto-quarantine only explicitly reviewed built-in/external rule IDs and executables/scripts in uploads; requires --apply and --quarantine=DIR\n";
    echo "                          Interactive actions: V preview, R repair, Q quarantine, D delete, A allowlist, S skip\n";
    echo "  --repair-original       Offer to replace mismatched core/plugin/theme files from clean ZIPs\n";
    echo "  --repair-original-auto  Auto-replace mismatched files from clean ZIPs; requires --apply\n";
    echo "  --repair-backup=DIR     Backup originals before repair overwrite\n";
    echo "  --package-cache=DIR     Cache downloaded clean ZIP packages\n";
    echo "  --known-admins=a,b      Comma-separated expected admin logins for DB audit\n";
    echo "  --cleanup-malware-users-auto Auto-remove only admins matching strong built-in malware-user IOCs; requires --apply\n";
    echo "  --cleanup-database-persistence-auto Remove confirmed wp-config/database/tmp persistence IOCs; requires --apply and --quarantine=DIR\n";
    echo "  --cleanup-malware-cron-auto Remove confirmed Base64 PHP-recreation jobs from the site owner's crontab; backs up the crontab and requires --apply and --quarantine=DIR\n";
    echo "  --prompt-unknown-admins Prompt to remove unapproved/unverified admin users; requires --apply to delete\n";
    echo "  --no-db-audit           Skip WordPress administrator DB audit\n";
    echo "  --verify-all            Report files not matched by core checksum/baseline\n";
    echo "  --fetch-official-checksums\n";
    echo "                          Fetch/cache official WordPress core and wordpress.org plugin checksums\n";
    echo "  --max-size=MB           Skip deep inspection above MB, while retaining metadata, magic, location and checksum checks (default 10)\n";
    echo "  --max-text-size=MB      Skip regex text scan for files larger than MB (default 5)\n";
    echo "  --slow-rule-ms=N        Report regex rules slower than N milliseconds (default 250; 0 disables notices)\n";
    echo "  --slow-file-ms=N        Report stages/files slower than N milliseconds (default 1000; 0 disables notices)\n";
    echo "  --file-cache=DIR        Persistent clean-file cache directory (default ../cache)\n";
    echo "  --no-file-cache         Disable persistent clean-file cache and force full scan\n";
    echo "  --exclude-pdf           Skip PDF files entirely (faster, but PDF malware/polyglot checks are disabled)\n";
    echo "  --vulnerability-scan    Scan WordPress core/plugins/themes with Wordfence Intelligence (when configured) and Composer packages with OSV\n";
    echo "  --wordfence-api-key-file=FILE  Wordfence Intelligence V3 API key file (default ../wordfence-intelligence.key); WORDFENCE_INTEL_API_KEY env also supported\n";
    echo "  --allow-wp-content-dir=a,b  Allow additional top-level wp-content directories (comma-separated)\n";
    echo "  --quarantine-wp-content-auto  With --apply and --quarantine, quarantine HIGH/CRITICAL unexpected wp-content directories\n";
    echo "  --debug-progress        Print each file path before scanning it\n";
    echo "  --newest-first          Scan eligible files by modification time, newest first; all files are still scanned\n";
    echo "  --recent-php-days=N     Quick sweep only PHP-like files modified in the last N days; not a replacement for a full scan\n";
    echo "  --self-test             Test runtime, intel regexes, fixtures, cache and ZIP support without scanning a site\n";
    echo "  --quiet                 Less console output\n";
    echo "  --help                  Show this help\n\n";
    echo "EXAMPLES:\n";
    echo "  php wp-warden.php /home/site/public_html --intel-dir=/var/lib/wp-warden/intel --policy=apiscp --noninteractive --report-json=/var/log/wp-warden/site.json\n";
    echo "  php wp-warden.php /home/site/public_html --intel-dir=/var/lib/wp-warden/intel --interactive --apply --quarantine=/var/lib/wp-warden/quarantine/site\n";
}

function parse_args(array $argv): array {
    $opts = [];
    foreach (array_slice($argv, 1) as $arg) {
        if (substr($arg, 0, 2) === '--') {
            $eq = strpos($arg, '=');
            if ($eq === false) {
                $opts[substr($arg, 2)] = true;
            } else {
                $opts[substr($arg, 2, $eq - 2)] = substr($arg, $eq + 1);
            }
            continue;
        }
        if (empty($opts['target'])) {
            $opts['target'] = $arg;
        }
    }
    return $opts;
}

function say(string $msg, bool $force = false): void {
    global $quiet;
    if (!$quiet || $force) {
        fwrite(STDERR, $msg . PHP_EOL);
    }
}

function normalize_path(string $path): string {
    $path = str_replace('\\', '/', $path);
    return rtrim($path, '/');
}

function load_intel(string $intelDir, string $policyId, string $siteId): array {
    $policy = load_policy($intelDir, $policyId);
    $phpRules = load_php_pattern_rules($intelDir);
    $processRules = json_file("$intelDir/patterns/process-patterns.json")['rules'] ?? [];
    $dbRules = json_file("$intelDir/patterns/db-patterns.json")['rules'] ?? [];

    $globalFiles = json_file("$intelDir/whitelists/global/file-hashes.json")['entries'] ?? [];
    $siteFile = "$intelDir/whitelists/sites/$siteId.json";
    $siteWhitelist = is_file($siteFile) ? json_file($siteFile) : [];

    $fileWhitelist = [];
    foreach ($globalFiles as $entry) {
        add_whitelist_entry($fileWhitelist, $entry);
    }
    foreach (($siteWhitelist['file_hashes'] ?? []) as $entry) {
        add_whitelist_entry($fileWhitelist, $entry);
    }

    return [
        'policy' => $policy,
        'php_rules' => array_values(array_filter($phpRules, 'rule_enabled')),
        'process_rules' => array_values(array_filter($processRules, 'rule_enabled')),
        'db_rules' => array_values(array_filter($dbRules, 'rule_enabled')),
        'file_whitelist' => $fileWhitelist,
    ];
}

function load_php_pattern_rules(string $intelDir): array {
    $rules = [];
    $loadedFiles = [];
    $activeCount = 0;
    $literalCount = 0;
    $regexCount = 0;
    $invalidCount = 0;

    foreach ([
        "$intelDir/patterns/php-malware-rules.json",
        "$intelDir/patterns/community-malware-rules.json",
    ] as $path) {
        if (!is_file($path)) {
            say("WARN: PHP malware rule file not found: $path", true);
            continue;
        }

        $data = json_file($path);
        $fileCount = 0;
        foreach (($data['rules'] ?? []) as $rule) {
            if (!is_array($rule)) {
                continue;
            }

            $fileCount++;

            // Disabled rules remain represented in the loaded count but are never
            // compiled or returned to the active scan loop.
            if (!rule_enabled($rule)) {
                $rules[] = $rule;
                continue;
            }

            $prepared = prepare_php_pattern_rule($rule);
            if ($prepared === null) {
                $invalidCount++;
                $rule['enabled'] = false;
                $rules[] = $rule;
                continue;
            }

            $activeCount++;
            if (($prepared['_match_mode'] ?? '') === 'literal') {
                $literalCount++;
            } else {
                $regexCount++;
            }
            $rules[] = $prepared;
        }

        $loadedFiles[] = basename($path) . "=$fileCount";
    }

    // Run narrowly reviewed malware-family signatures before broad heuristic
    // expressions. Large malware files can embed entire third-party libraries,
    // making hundreds of generic whole-file regex checks unnecessarily slow.
    $priorityIds = [
        'PHP_AXIL_QUERY_PARENT_UPLOAD_BACKDOOR_001' => 0,
        'PHP_FRAGMENTED_SELF_TAIL_GZIP_EVAL_001' => 1,
        'PHP_FRAGMENTED_ROT13_GZINFLATE_EVAL_001' => 2,
        'PHP_INDEXED_STRING_TABLE_GOTO_REMOTE_LOADER_001' => 3,
        'PHP_TRIPLE_MD5_POST_GZIP_DROPPER_001' => 4,
        'PHP_LEAFMAILER_FAMILY_001' => 5,
        'PHP_LEAFMAILER_PASSWORD_GATE_001' => 6,
        'PHP_CWP_PASSWORDLESS_ADMIN_LOGIN_001' => 7,
    ];
    foreach ($rules as $index => &$loadedRule) {
        $loadedRule['_load_order'] = $index;
    }
    unset($loadedRule);
    usort($rules, static function (array $left, array $right) use ($priorityIds): int {
        $leftPriority = $priorityIds[(string)($left['id'] ?? '')] ?? 1000;
        $rightPriority = $priorityIds[(string)($right['id'] ?? '')] ?? 1000;
        if ($leftPriority !== $rightPriority) {
            return $leftPriority <=> $rightPriority;
        }
        return ((int)($left['_load_order'] ?? 0)) <=> ((int)($right['_load_order'] ?? 0));
    });

    say(
        "Loaded " . count($rules) . " PHP malware rules" .
        ($loadedFiles ? " (" . implode(', ', $loadedFiles) . ")" : '') .
        "; active=$activeCount, literal-fast=$literalCount, regex=$regexCount" .
        ($invalidCount ? ", invalid=$invalidCount" : ''),
        true
    );

    return $rules;
}

function prepare_php_pattern_rule(array $rule): ?array {
    $pattern = $rule['pattern'] ?? null;
    if (!is_string($pattern) || $pattern === '') {
        return $rule;
    }

    // A pattern containing no PCRE metacharacters is exactly equivalent to a
    // case-insensitive literal search. Avoid invoking PCRE for these rules.
    if (strpbrk($pattern, "\\.^$*+?()[]{}|") === false) {
        $rule['_match_mode'] = 'literal';
        $rule['_literal'] = $pattern;
    } else {
        $regex = '~' . str_replace('~', '\\~', $pattern) . '~i';
        $compileMatches = null;
        $check = warden_preg_match($regex, '', $compileMatches, 0, 0, [
            'rule_id' => (string)($rule['id'] ?? '(unnamed rule)'),
            'path' => '(intel compile)',
        ]);

        if ($check === false) {
            $ruleId = $rule['id'] ?? '(unnamed rule)';
            $detail = pcre_error_message(preg_last_error());
            say("[RULE-ERROR] Invalid regex $ruleId: $detail", true);
            say("[RULE-ERROR] Pattern: $pattern", true);
            return null;
        }

        $rule['_match_mode'] = 'regex';
        $rule['_regex'] = $regex;
    }

    // Optional cheap prefilters. Rule authors can provide either:
    //   "anchor": "base64_decode"
    // or
    //   "anchors": ["eval", "base64_decode"]
    // Every listed anchor must be present before the more expensive matcher runs.
    $anchors = [];
    if (isset($rule['anchor']) && is_string($rule['anchor']) && $rule['anchor'] !== '') {
        $anchors[] = $rule['anchor'];
    }
    if (isset($rule['anchors']) && is_array($rule['anchors'])) {
        foreach ($rule['anchors'] as $anchor) {
            if (is_string($anchor) && $anchor !== '') {
                $anchors[] = $anchor;
            }
        }
    }
    if ($anchors) {
        $rule['_anchors'] = array_values(array_unique($anchors));
    }

    return $rule;
}

function load_policy(string $intelDir, string $policyId): array {
    $default = json_file("$intelDir/policy/default.json");
    if ($policyId === 'default') {
        return $default;
    }

    $policy = json_file("$intelDir/policy/$policyId.json");
    if (!$policy) {
        say("WARN: policy not found, using default: $policyId", true);
        return $default;
    }
    return array_replace_recursive($default, $policy);
}

function json_file(string $path): array {
    if (!is_file($path)) {
        return [];
    }
    $raw = file_get_contents($path);
    if (!is_string($raw)) {
        say("WARN: could not read JSON: $path", true);
        return [];
    }
    $raw = preg_replace('/^\xEF\xBB\xBF/', '', $raw);
    $raw = preg_replace('/^\x00\x00\xFE\xFF|\xFF\xFE\x00\x00|\xFE\xFF|\xFF\xFE/', '', $raw);
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        say("WARN: could not parse JSON: $path (" . json_last_error_msg() . ")", true);
        return [];
    }
    return $data;
}

function rule_enabled(array $rule): bool {
    return !array_key_exists('enabled', $rule) || $rule['enabled'] === true;
}

function add_whitelist_entry(array &$index, array $entry): void {
    foreach (['sha256', 'md5', 'hash'] as $key) {
        if (!empty($entry[$key])) {
            $index[strtolower($entry[$key])] = $entry;
        }
    }
}

function detect_wp_version(string $root): ?string {
    $versionFile = "$root/wp-includes/version.php";
    if (!is_file($versionFile)) {
        return null;
    }
    $data = file_get_contents($versionFile);
    if (warden_preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $data, $m)) {
        return $m[1];
    }
    return null;
}

function detect_wp_locale(string $root): string {
    $config = "$root/wp-config.php";
    if (!is_file($config)) {
        return 'en_US';
    }
    $data = file_get_contents($config);
    if (warden_preg_match('/define\s*\(\s*[\'"]WPLANG[\'"]\s*,\s*[\'"]([^\'"]*)[\'"]\s*\)/', $data, $m) && $m[1] !== '') {
        return $m[1];
    }
    return 'en_US';
}

function audit_wordpress_admins(string $root, array $intel): void {
    global $state, $opts, $apply, $interactive, $nonInteractive, $cleanupMalwareUsersAuto, $promptUnknownAdmins;

    if (isset($opts['no-db-audit'])) {
        $state['db_audit']['error'] = 'Skipped by --no-db-audit.';
        say("DB admin audit skipped by --no-db-audit", true);
        return;
    }

    if ((bool)($intel['policy']['db']['audit_admins'] ?? true) !== true) {
        return;
    }

    $knownAdmins = known_admin_logins($intel);
    $state['db_audit']['known_admins'] = $knownAdmins;

    $config = parse_wp_config_db($root);
    if (!$config) {
        $state['db_audit']['error'] = 'Could not read database settings from wp-config.php.';
        say("WARN: DB admin audit skipped; could not read wp-config.php", true);
        return;
    }

    if (!class_exists('mysqli')) {
        $state['db_audit']['error'] = 'PHP mysqli extension is not available.';
        say("WARN: DB admin audit skipped; mysqli extension is not available", true);
        return;
    }

    $hostInfo = parse_mysql_host($config['DB_HOST'] ?? 'localhost');
    mysqli_report(MYSQLI_REPORT_OFF);
    $db = mysqli_init();
    if (!$db) {
        $state['db_audit']['error'] = 'Could not initialize mysqli.';
        say("WARN: DB admin audit skipped; could not initialize mysqli", true);
        return;
    }
    @$db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 5);
    @$db->real_connect(
        $hostInfo['host'],
        $config['DB_USER'] ?? '',
        $config['DB_PASSWORD'] ?? '',
        $config['DB_NAME'] ?? '',
        $hostInfo['port'],
        $hostInfo['socket']
    );

    if ($db->connect_errno) {
        $state['db_audit']['error'] = 'Database connection failed: ' . $db->connect_error;
        say("WARN: DB admin audit skipped; database connection failed", true);
        return;
    }

    $prefix = $config['table_prefix'] ?? 'wp_';
    if (!warden_preg_match('/^[A-Za-z0-9_]+$/', $prefix)) {
        $state['db_audit']['error'] = 'Unsafe table_prefix in wp-config.php.';
        say("WARN: DB admin audit skipped; unsafe table_prefix", true);
        $db->close();
        return;
    }

    $usersTable = "`{$prefix}users`";
    $metaTable = "`{$prefix}usermeta`";
    $capKey = $db->real_escape_string($prefix . 'capabilities');
    $sql = "
        SELECT u.ID, u.user_login, u.user_email, u.user_registered, m.meta_value
        FROM {$usersTable} u
        INNER JOIN {$metaTable} m ON m.user_id = u.ID
        WHERE m.meta_key = '{$capKey}'
          AND m.meta_value LIKE '%administrator%'
        ORDER BY u.ID ASC
    ";

    $result = @$db->query($sql);
    if (!$result) {
        $state['db_audit']['error'] = 'Admin user query failed: ' . $db->error;
        say("WARN: DB admin audit skipped; admin user query failed", true);
        $db->close();
        return;
    }

    $knownIndex = array_fill_keys(array_map('strtolower', $knownAdmins), true);
    while ($row = $result->fetch_assoc()) {
        $login = (string)($row['user_login'] ?? '');
        $email = (string)($row['user_email'] ?? '');
        $isKnown = $knownAdmins === [] ? null : ($login !== '' && isset($knownIndex[strtolower($login)]));
        $entry = [
            'id' => (int)($row['ID'] ?? 0),
            'login' => $login,
            'email' => $email,
            'registered' => (string)($row['user_registered'] ?? ''),
            'known' => $isKnown,
        ];

        $malwareRule = detect_malware_admin_user($entry);
        if ($malwareRule !== null) {
            $entry['malware'] = true;
            $entry['malware_rule_id'] = $malwareRule['id'];
        }
        $state['db_audit']['admin_users'][] = $entry;

        if ($malwareRule !== null) {
            $finding = [
                'severity' => $malwareRule['severity'],
                'type' => 'malicious_admin_user',
                'rule_id' => $malwareRule['id'],
                'path' => 'database',
                'relative_path' => 'database:admin-user/' . $login,
                'reason' => $malwareRule['reason'],
                'db_user' => $entry,
                'file_action' => false,
                'recommended_action' => 'Remove this administrator unless you have independently confirmed it is legitimate.',
            ];
            add_finding($finding, false);

            if ($cleanupMalwareUsersAuto && $apply) {
                remove_malicious_admin_user($db, $prefix, $entry, $finding, 'auto');
            } elseif (!$nonInteractive && $interactive) {
                offer_malicious_admin_user_action($db, $prefix, $entry, $finding);
            }
            continue;
        }

        $suspiciousRule = detect_suspicious_admin_user($entry);
        if ($suspiciousRule !== null) {
            $finding = [
                'severity' => $suspiciousRule['severity'],
                'type' => 'suspicious_admin_user',
                'rule_id' => $suspiciousRule['id'],
                'path' => 'database',
                'relative_path' => 'database:admin-user/' . $login,
                'reason' => $suspiciousRule['reason'],
                'db_user' => $entry,
                'file_action' => false,
                'recommended_action' => 'Manually confirm this administrator. It is suspicious but is not automatically removed.',
            ];
            add_finding($finding, false);
        }

        if ($isKnown === false) {
            $finding = [
                'severity' => $intel['policy']['severity']['rogue_admin'] ?? 'critical',
                'type' => 'unknown_admin_user',
                'rule_id' => 'DB_UNKNOWN_ADMIN_001',
                'path' => 'database',
                'relative_path' => 'database:admin-user/' . $login,
                'reason' => 'Administrator account is not in the known admin list.',
                'db_user' => $entry,
                'file_action' => false,
                'recommended_action' => 'Confirm this WordPress administrator is legitimate; remove it or add it to known_admins if approved.',
            ];
            add_finding($finding, false);
            if ($promptUnknownAdmins) {
                offer_unknown_admin_user_action($db, $prefix, $entry, $finding, true);
            }
        } elseif ($isKnown === null && $promptUnknownAdmins) {
            // No known-admin list exists. Do not flag every administrator as malicious,
            // but allow an explicit operator-requested review prompt for each account.
            $finding = [
                'severity' => 'medium',
                'type' => 'unverified_admin_user',
                'rule_id' => 'DB_UNVERIFIED_ADMIN_001',
                'path' => 'database',
                'relative_path' => 'database:admin-user/' . $login,
                'reason' => 'Known admin list is not configured; administrator requires operator review.',
                'db_user' => $entry,
                'file_action' => false,
                'recommended_action' => 'Confirm this WordPress administrator is legitimate before removing it.',
            ];
            offer_unknown_admin_user_action($db, $prefix, $entry, $finding, false);
        }
    }

    $result->free();

    // Audit database-backed persistence after administrator enumeration while
    // the same authenticated DB connection is still available.
    audit_database_persistence($db, $prefix);

    $db->close();
}

function detect_suspicious_admin_user(array $entry): ?array {
    $login = strtolower(trim((string)($entry['login'] ?? $entry['user_login'] ?? '')));
    $email = strtolower(trim((string)($entry['email'] ?? $entry['user_email'] ?? '')));

    // Observed service-style hidden administrators. This is intentionally
    // review-only until the persistence family is independently confirmed.
    if (
        warden_preg_match('/^wp_service_[a-f0-9]{4,}$/i', $login)
        && warden_preg_match('/@service\.localhost$/i', $email)
    ) {
        return [
            'id' => 'DB_SUSPICIOUS_WP_SERVICE_ADMIN_001',
            'severity' => 'high',
            'reason' => 'Administrator matches the wp_service_<hex>@service.localhost hidden-service account pattern; manual verification required.',
        ];
    }

    return null;
}

function audit_database_persistence(mysqli $db, string $prefix): void {
    global $state, $apply, $quarantineDir, $cleanupDatabasePersistenceAuto;

    $optionsTable = "`{$prefix}options`";
    $metaTable = "`{$prefix}usermeta`";

    // 1) Active plugin inventory and known malicious persistence plugin names.
    $sql = "SELECT option_value FROM {$optionsTable} WHERE option_name='active_plugins' LIMIT 1";
    $res = @$db->query($sql);
    if ($res && ($row = $res->fetch_assoc())) {
        $raw = (string)($row['option_value'] ?? '');
        $plugins = [];
        if (warden_preg_match_all('/s:\d+:"([^"]+\.php)"/', $raw, $m)) {
            $plugins = array_values(array_unique($m[1]));
        }
        $state['db_audit']['active_plugins'] = $plugins;

        foreach ($plugins as $plugin) {
            if (warden_preg_match('#(?:^|/)wordpress-cache-optimizer/#i', '/' . ltrim($plugin, '/'))) {
                $finding = [
                    'severity' => 'critical',
                    'type' => 'database_persistence',
                    'rule_id' => 'DB_ACTIVE_MALICIOUS_PLUGIN_001',
                    'path' => 'database',
                    'relative_path' => 'database:option/active_plugins',
                    'reason' => 'Known malicious wordpress-cache-optimizer persistence plugin is present in active_plugins.',
                    'file_action' => false,
                    'recommended_action' => 'Quarantine the plugin directory and remove the malicious administrator account.',
                ];
                $state['db_audit']['persistence_findings'][] = $finding;
                add_finding($finding, false);
            }
        }
        $res->free();
    }

    // 2) Known persistence metadata left on user accounts.
    $knownMeta = [
        '_wp_cache_optimizer_flag' => ['critical', 'DB_WPHIDDENBOT_META_001', 'Known wphiddenbot cache-optimizer persistence metadata is present.'],
    ];
    foreach ($knownMeta as $metaKey => [$severity, $ruleId, $reason]) {
        $safe = $db->real_escape_string($metaKey);
        $sql = "SELECT umeta_id, user_id, meta_key, meta_value FROM {$metaTable} WHERE meta_key='{$safe}' LIMIT 100";
        $res = @$db->query($sql);
        if (!$res) {
            continue;
        }
        while ($row = $res->fetch_assoc()) {
            $record = [
                'umeta_id' => (int)($row['umeta_id'] ?? 0),
                'user_id' => (int)($row['user_id'] ?? 0),
                'meta_key' => (string)($row['meta_key'] ?? ''),
                'meta_value' => (string)($row['meta_value'] ?? ''),
            ];
            $state['db_audit']['usermeta_iocs'][] = $record;
            $finding = [
                'severity' => $severity,
                'type' => 'database_persistence',
                'rule_id' => $ruleId,
                'path' => 'database',
                'relative_path' => 'database:usermeta/' . $metaKey,
                'reason' => $reason . ' user_id=' . $record['user_id'],
                'file_action' => false,
                'recommended_action' => 'Review the associated user and remove malicious persistence metadata.',
            ];
            $state['db_audit']['persistence_findings'][] = $finding;
            add_finding($finding, false);

            if ($cleanupDatabasePersistenceAuto && $apply && $quarantineDir && $record['umeta_id'] > 0) {
                $qRoot = rtrim(normalize_path($quarantineDir), '/') . '/database-persistence-' . gmdate('Ymd-His');
                if (!is_dir($qRoot) && !@mkdir($qRoot, 0700, true) && !is_dir($qRoot)) {
                    say("WARN: could not create persistence quarantine directory: $qRoot", true);
                    continue;
                }
                $backupPath = $qRoot . '/usermeta-' . $record['umeta_id'] . '.json';
                $backupPayload = json_encode([
                    'umeta_id' => $record['umeta_id'],
                    'user_id' => $record['user_id'],
                    'meta_key' => $record['meta_key'],
                    'meta_value_base64' => base64_encode($record['meta_value']),
                ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                if (!is_string($backupPayload) || @file_put_contents($backupPath, $backupPayload, LOCK_EX) === false) {
                    say("WARN: could not back up persistence usermeta {$record['umeta_id']}; it was not deleted", true);
                    continue;
                }
                @chmod($backupPath, 0600);
                $metaId = $record['umeta_id'];
                if (@$db->query("DELETE FROM {$metaTable} WHERE umeta_id={$metaId} AND meta_key='{$safe}' LIMIT 1")) {
                    $state['actions'][] = [
                        'type' => 'delete_database_persistence_usermeta',
                        'umeta_id' => $metaId,
                        'user_id' => $record['user_id'],
                        'meta_key' => $record['meta_key'],
                        'backup' => $backupPath,
                    ];
                    $state['summary']['actions_taken']++;
                    say("[CLEANED] Deleted confirmed persistence usermeta {$record['meta_key']} for user_id={$record['user_id']}; backup: $backupPath", true);
                }
            }
        }
        $res->free();
    }

    // 3) Confirmed database-to-/tmp loader payload family. The option name is
    // intentionally disguised as a site transient but is read directly from
    // the normal options table by injected wp-config.php code.
    $sql = "
        SELECT option_id, option_name, option_value
        FROM {$optionsTable}
        WHERE option_name REGEXP '^_site_transient_(timeout_)?health_[a-f0-9]{6,64}$'
        LIMIT 100
    ";
    $res = @$db->query($sql);
    if ($res) {
        $confirmedConfigOptions = array_values(array_filter(array_map(
            static function ($ioc): string { return is_array($ioc) ? (string)($ioc['option_name'] ?? '') : ''; },
            $state['db_audit']['config_iocs'] ?? []
        )));
        while ($row = $res->fetch_assoc()) {
            $optionId = (int)($row['option_id'] ?? 0);
            $optionName = (string)($row['option_name'] ?? '');
            $optionValue = (string)($row['option_value'] ?? '');
            $mainOptionName = str_replace('_site_transient_timeout_', '_site_transient_', $optionName);
            $decoded = base64_decode($optionValue, true);
            $payloadLooksPhp = is_string($decoded) && warden_preg_match('/<\?(?:php|=|\s)/i', substr($decoded, 0, 4096)) === 1;
            $confirmedByConfig = in_array($mainOptionName, $confirmedConfigOptions, true);
            if (!$confirmedByConfig && !$payloadLooksPhp) {
                continue;
            }
            $finding = [
                'severity' => 'critical',
                'type' => 'database_persistence',
                'rule_id' => 'DB_SITE_TRANSIENT_HEALTH_PAYLOAD_001',
                'path' => 'database',
                'relative_path' => 'database:option/' . $optionName,
                'reason' => $confirmedByConfig
                    ? 'Database option is referenced by a confirmed WP_Core_Integrity wp-config.php loader.'
                    : 'Database option uses the persistence-family name and Base64-decodes to PHP code.',
                'file_action' => false,
                'db_option' => ['option_id' => $optionId, 'option_name' => $optionName],
                'recommended_action' => 'Back up and delete this payload option together with the injected wp-config.php loader.',
            ];
            $state['db_audit']['option_iocs'][] = $finding['db_option'];
            $state['db_audit']['persistence_findings'][] = $finding;
            add_finding($finding, false);

            if (!$cleanupDatabasePersistenceAuto || !$apply || !$quarantineDir || $optionId <= 0) {
                continue;
            }
            $qRoot = rtrim(normalize_path($quarantineDir), '/') . '/database-persistence-' . gmdate('Ymd-His');
            if (!is_dir($qRoot) && !@mkdir($qRoot, 0700, true) && !is_dir($qRoot)) {
                say("WARN: could not create persistence quarantine directory: $qRoot", true);
                continue;
            }
            $backupPath = $qRoot . '/option-' . $optionId . '-' . preg_replace('/[^a-zA-Z0-9._-]/', '_', $optionName) . '.json';
            $backupPayload = json_encode([
                'option_id' => $optionId,
                'option_name' => $optionName,
                'option_value_base64' => base64_encode($optionValue),
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            if (!is_string($backupPayload) || @file_put_contents($backupPath, $backupPayload, LOCK_EX) === false) {
                say("WARN: could not back up database persistence option $optionName; it was not deleted", true);
                continue;
            }
            @chmod($backupPath, 0600);
            $safeName = $db->real_escape_string($optionName);
            if (@$db->query("DELETE FROM {$optionsTable} WHERE option_id={$optionId} AND option_name='{$safeName}' LIMIT 1")) {
                $state['actions'][] = [
                    'type' => 'delete_database_persistence_option',
                    'option_id' => $optionId,
                    'option_name' => $optionName,
                    'backup' => $backupPath,
                ];
                $state['summary']['actions_taken']++;
                say("[CLEANED] Deleted confirmed persistence option $optionName; backup: $backupPath", true);
            }
        }
        $res->free();
    }

    // 4) Search option values for high-confidence persistence IOCs or embedded
    // executable PHP patterns. Keep the SQL bounded and exclude transients.
    $patterns = [
        ['%wphiddenbot%', 'critical', 'DB_OPTION_WPHIDDENBOT_001', 'Option value contains the known wphiddenbot persistence IOC.'],
        ['%wp2shell.invalid%', 'critical', 'DB_OPTION_WP2SHELL_001', 'Option value contains the known wp2shell.invalid persistence IOC.'],
        ['%wp2shell.local%', 'critical', 'DB_OPTION_WP2SHELL_002', 'Option value contains the known wp2shell.local persistence IOC.'],
        ['%nx.invalid%', 'critical', 'DB_OPTION_NX_001', 'Option value contains the known nx.invalid persistence IOC.'],
        ['%_wp_cache_optimizer_flag%', 'critical', 'DB_OPTION_CACHE_OPT_001', 'Option value contains known cache-optimizer persistence metadata.'],
        ['%wp_insert_user%', 'high', 'DB_OPTION_USER_CREATE_CODE_001', 'Option value contains wp_insert_user(), which can indicate database-backed user-creation persistence.'],
        ['%wp_create_user%', 'high', 'DB_OPTION_USER_CREATE_CODE_002', 'Option value contains wp_create_user(), which can indicate database-backed user-creation persistence.'],
        ['%eval(base64_decode%', 'critical', 'DB_OPTION_OBFUSCATED_CODE_001', 'Option value contains eval(base64_decode(...)) style executable obfuscation.'],
    ];

    foreach ($patterns as [$like, $severity, $ruleId, $reason]) {
        $safeLike = $db->real_escape_string($like);
        $sql = "
            SELECT option_id, option_name, autoload, LEFT(option_value,2048) AS option_value
            FROM {$optionsTable}
            WHERE option_name NOT LIKE '\\_transient\\_%'
              AND option_name NOT LIKE '\\_site\\_transient\\_%'
              AND option_value LIKE '{$safeLike}'
            LIMIT 50
        ";
        $res = @$db->query($sql);
        if (!$res) {
            continue;
        }
        while ($row = $res->fetch_assoc()) {
            $record = [
                'option_id' => (int)($row['option_id'] ?? 0),
                'option_name' => (string)($row['option_name'] ?? ''),
                'autoload' => (string)($row['autoload'] ?? ''),
                'sample' => shorten_text((string)($row['option_value'] ?? ''), 400),
                'rule_id' => $ruleId,
            ];
            $state['db_audit']['option_iocs'][] = $record;
            $finding = [
                'severity' => $severity,
                'type' => 'database_persistence',
                'rule_id' => $ruleId,
                'path' => 'database',
                'relative_path' => 'database:option/' . $record['option_name'],
                'reason' => $reason,
                'db_option' => $record,
                'file_action' => false,
                'recommended_action' => 'Inspect this WordPress option and determine which plugin/theme created it before removal.',
            ];
            $state['db_audit']['persistence_findings'][] = $finding;
            add_finding($finding, false);
        }
        $res->free();
    }

    // 5) Cron is serialized data, so inspect its raw option for confirmed IOC
    // strings. Do not flag generic hook names to avoid noisy false positives.
    $sql = "SELECT LEFT(option_value,65535) AS cron_value FROM {$optionsTable} WHERE option_name='cron' LIMIT 1";
    $res = @$db->query($sql);
    if ($res && ($row = $res->fetch_assoc())) {
        $cron = (string)($row['cron_value'] ?? '');
        $cronRules = [
            'wphiddenbot' => 'DB_CRON_WPHIDDENBOT_001',
            'wp2shell' => 'DB_CRON_WP2SHELL_001',
            'wordpress-cache-optimizer' => 'DB_CRON_CACHE_OPT_001',
            'service.localhost' => 'DB_CRON_SERVICE_LOCALHOST_001',
            'nx.invalid' => 'DB_CRON_NX_001',
        ];
        foreach ($cronRules as $literal => $ruleId) {
            if (stripos($cron, $literal) === false) {
                continue;
            }
            $record = ['literal' => $literal, 'rule_id' => $ruleId];
            $state['db_audit']['cron_iocs'][] = $record;
            $finding = [
                'severity' => 'critical',
                'type' => 'database_persistence',
                'rule_id' => $ruleId,
                'path' => 'database',
                'relative_path' => 'database:option/cron',
                'reason' => "WordPress cron data contains confirmed persistence IOC: {$literal}",
                'file_action' => false,
                'recommended_action' => 'Inspect and remove the malicious cron hook after identifying its owning code.',
            ];
            $state['db_audit']['persistence_findings'][] = $finding;
            add_finding($finding, false);
        }
        $res->free();
    }
}

function detect_malware_admin_user(array $entry): ?array {
    $login = strtolower(trim((string)($entry['login'] ?? $entry['user_login'] ?? '')));
    $email = strtolower(trim((string)($entry['email'] ?? $entry['user_email'] ?? '')));

    if ($login === '' && $email === '') {
        return null;
    }

    if ($login === 'warnight6413' && $email === 'warnight6413@proton.me') {
        return [
            'id' => 'BUILTIN_WARNIGHT_ADMIN_001',
            'severity' => 'critical',
            'reason' => 'Administrator login and email exactly match the confirmed warnight6413 compromise account IOC.',
        ];
    }

    if ($login === 'wphiddenbot') {
        return [
            'id' => 'BUILTIN_WPHIDDENBOT_ADMIN_001',
            'severity' => 'critical',
            'reason' => 'Administrator login wphiddenbot matches a known malicious persistence account IOC.',
        ];
    }

    // Strong WP2Shell/W2S IOC domains. This also catches variants such as ngx_.
    if (warden_preg_match('/@wp2shell\.(?:invalid|local)$/i', $email)) {
        return [
            'id' => 'BUILTIN_WP2SHELL_ADMIN_DOMAIN_002',
            'severity' => 'critical',
            'reason' => 'Administrator email uses a known WP2Shell persistence domain.',
        ];
    }

    // Catch the characteristic login family even if the attacker changes email.
    if (warden_preg_match('/^(?:wp2|w2s)_[a-f0-9]{4,}$/i', $login)) {
        return [
            'id' => 'BUILTIN_WP2SHELL_ADMIN_FAMILY_001',
            'severity' => 'critical',
            'reason' => 'Administrator login matches the WP2Shell/W2S hidden-admin family.',
        ];
    }

    // Nx persistence family.
    if (warden_preg_match('/@nx\.invalid$/i', $email)) {
        return [
            'id' => 'BUILTIN_NX_ADMIN_EMAIL_001',
            'severity' => 'critical',
            'reason' => 'Administrator email uses the synthetic nx.invalid malware IOC domain.',
        ];
    }

    if (warden_preg_match('/^nx_[a-f0-9]{6,}$/i', $login)) {
        return [
            'id' => 'BUILTIN_NX_ADMIN_001',
            'severity' => 'critical',
            'reason' => 'Administrator login matches the Nx hidden-admin persistence family.',
        ];
    }

    return null;
}

function offer_malicious_admin_user_action(mysqli $db, string $prefix, array $entry, array $finding): void {
    global $apply, $interactive, $nonInteractive;

    if (!$interactive || $nonInteractive) {
        return;
    }

    $login = (string)($entry['login'] ?? $entry['user_login'] ?? '');
    $email = (string)($entry['email'] ?? $entry['user_email'] ?? '');
    $id = (int)($entry['id'] ?? $entry['ID'] ?? 0);

    echo PHP_EOL;
    echo "[MALICIOUS ADMIN] {$login} (id={$id}, email={$email})" . PHP_EOL;
    echo "Rule: " . (string)($finding['rule_id'] ?? '') . PHP_EOL;
    echo "Reason: " . (string)($finding['reason'] ?? '') . PHP_EOL;

    if (!$apply) {
        echo "Report-only mode: use --apply to permit removal." . PHP_EOL;
        return;
    }

    echo "Remove this malicious administrator? [y/N] ";
    $answer = strtolower(trim((string)fgets(STDIN)));
    if ($answer === 'y' || $answer === 'yes') {
        remove_malicious_admin_user($db, $prefix, $entry, $finding, 'interactive');
    } else {
        say("[USER-LEFT] {$login} (id={$id})", true);
    }
}

function offer_unknown_admin_user_action(mysqli $db, string $prefix, array $entry, array $finding, bool $flagged): void {
    global $apply, $interactive, $nonInteractive;

    if (!$interactive || $nonInteractive) {
        return;
    }

    $login = (string)($entry['login'] ?? $entry['user_login'] ?? '');
    $email = (string)($entry['email'] ?? $entry['user_email'] ?? '');
    $id = (int)($entry['id'] ?? $entry['ID'] ?? 0);
    $label = $flagged ? 'UNKNOWN ADMIN' : 'UNVERIFIED ADMIN';

    echo PHP_EOL;
    echo "[{$label}] {$login} (id={$id}, email={$email})" . PHP_EOL;
    echo "Reason: " . (string)($finding['reason'] ?? '') . PHP_EOL;

    if (!$apply) {
        echo "Report-only mode: use --apply to permit removal." . PHP_EOL;
        return;
    }

    echo "Remove this administrator? [y/N] ";
    $answer = strtolower(trim((string)fgets(STDIN)));
    if ($answer === 'y' || $answer === 'yes') {
        remove_admin_user($db, $prefix, $entry, $finding, 'interactive-review');
    } else {
        say("[USER-LEFT] {$login} (id={$id})", true);
    }
}

function remove_admin_user(mysqli $db, string $prefix, array $entry, array $finding, string $mode): bool {
    global $state;

    $userId = (int)($entry['id'] ?? 0);
    if ($userId <= 0) {
        say("[USER-REMOVE-FAIL] Invalid user id for {$entry['login']}", true);
        return false;
    }

    $usersTable = "`{$prefix}users`";
    $metaTable = "`{$prefix}usermeta`";

    @$db->begin_transaction();
    $okMeta = @$db->query("DELETE FROM {$metaTable} WHERE user_id = {$userId}");
    $okUser = @$db->query("DELETE FROM {$usersTable} WHERE ID = {$userId} LIMIT 1");

    if (!$okMeta || !$okUser || $db->affected_rows < 1) {
        @$db->rollback();
        say("[USER-REMOVE-FAIL] Could not remove {$entry['login']} (id={$userId}): {$db->error}", true);
        return false;
    }
    @$db->commit();

    $action = [
        'type' => 'remove_admin_user',
        'finding_id' => finding_id($finding),
        'mode' => $mode,
        'user' => [
            'id' => $userId,
            'login' => (string)($entry['login'] ?? ''),
            'email' => (string)($entry['email'] ?? ''),
            'registered' => (string)($entry['registered'] ?? ''),
        ],
        'rule_id' => (string)($finding['rule_id'] ?? ''),
        'at' => gmdate('c'),
    ];
    $state['actions'][] = $action;
    $state['summary']['actions_taken']++;
    say("[USER-REMOVED] {$entry['login']} (id={$userId}) [{$finding['rule_id']}]", true);
    return true;
}

function remove_malicious_admin_user(mysqli $db, string $prefix, array $entry, array $finding, string $mode): bool {
    return remove_admin_user($db, $prefix, $entry, $finding, $mode);
}

function known_admin_logins(array $intel): array {
    global $knownAdminsOverride;

    $admins = $knownAdminsOverride;
    if ($admins === null) {
        $admins = $intel['policy']['db']['known_admins'] ?? [];
    }
    if (!is_array($admins)) {
        return [];
    }

    $clean = [];
    foreach ($admins as $admin) {
        $admin = trim((string)$admin);
        if ($admin !== '') {
            $clean[strtolower($admin)] = $admin;
        }
    }
    return array_values($clean);
}

function parse_wp_config_db(string $root): ?array {
    $path = "$root/wp-config.php";
    if (!is_file($path)) {
        return null;
    }

    $data = file_get_contents($path);
    $config = [];
    foreach (['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST'] as $key) {
        if (warden_preg_match('/define\s*\(\s*[\'"]' . preg_quote($key, '/') . '[\'"]\s*,\s*([\'"])(.*?)\1\s*\)/s', $data, $m)) {
            $config[$key] = stripcslashes($m[2]);
        }
    }
    if (warden_preg_match('/\$table_prefix\s*=\s*([\'"])(.*?)\1\s*;/', $data, $m)) {
        $config['table_prefix'] = stripcslashes($m[2]);
    } else {
        $config['table_prefix'] = 'wp_';
    }

    foreach (['DB_NAME', 'DB_USER', 'DB_HOST'] as $required) {
        if (($config[$required] ?? '') === '') {
            return null;
        }
    }
    $config['DB_PASSWORD'] = $config['DB_PASSWORD'] ?? '';
    return $config;
}

function parse_mysql_host(string $host): array {
    $out = [
        'host' => $host !== '' ? $host : 'localhost',
        'port' => (int)ini_get('mysqli.default_port'),
        'socket' => null,
    ];

    if (strpos($host, ':/') !== false) {
        [$hostPart, $socket] = explode(':', $host, 2);
        $out['host'] = $hostPart !== '' ? $hostPart : 'localhost';
        $out['socket'] = '/' . ltrim($socket, '/');
        return $out;
    }

    if (warden_preg_match('/^(.+):(\d+)$/', $host, $m)) {
        $out['host'] = $m[1];
        $out['port'] = (int)$m[2];
    }

    return $out;
}

function load_core_checksums(string $intelDir, ?string $wpVersion, string $locale, bool $fetchOfficial): array {
    if (!$wpVersion) {
        return [];
    }

    $candidates = [
        "$intelDir/checksums/wordpress-core/$wpVersion-$locale.json",
        "$intelDir/checksums/wordpress-core/$wpVersion.json",
        "$intelDir/checksums/wordpress-core/core_{$wpVersion}_{$locale}.json",
    ];

    foreach ($candidates as $path) {
        if (!is_file($path)) {
            continue;
        }
        $data = json_file($path);
        if (isset($data['checksums']) && is_array($data['checksums'])) {
            return normalize_checksum_map($data['checksums']);
        }
        if (isset($data['files']) && is_array($data['files'])) {
            return normalize_checksum_map($data['files']);
        }
        return normalize_checksum_map($data);
    }

    if ($fetchOfficial) {
        $fetched = fetch_core_checksums($wpVersion, $locale);
        if ($fetched) {
            $cachePath = "$intelDir/checksums/wordpress-core/$wpVersion-$locale.json";
            cache_checksum_file($cachePath, [
                'schema' => 'wp-warden.checksums.wordpress-core.v1',
                'type' => 'wordpress-core',
                'version' => $wpVersion,
                'locale' => $locale,
                'source' => 'https://api.wordpress.org/core/checksums/1.0/ with http://wpmd5.mattjung.net fallback',
                'created_at' => gmdate('c'),
                'files' => $fetched,
            ]);
            return normalize_checksum_map($fetched);
        }
    }

    say("WARN: no local core checksum map found for WordPress $wpVersion/$locale", true);
    return [];
}

function fetch_core_checksums(string $wpVersion, string $locale): array {
    $url = 'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode($wpVersion) . '&locale=' . rawurlencode($locale);
    $data = http_get_json($url);
    if (isset($data['checksums']) && is_array($data['checksums'])) {
        say("Fetched official core checksums: " . count($data['checksums']));
        return $data['checksums'];
    }
    say("WARN: official core checksum fetch failed for $wpVersion/$locale", true);

    $fallback = fetch_wpmd5_checksums("core/$wpVersion/$locale");
    if ($fallback) {
        say("Fetched wpmd5 fallback core checksums: " . count($fallback));
    }
    return $fallback;
}

function load_component_checksums(string $wpRoot, string $intelDir, bool $fetchOfficial): array {
    return [
        'plugins' => load_plugin_checksum_sets($wpRoot, $intelDir, $fetchOfficial),
        'themes' => load_theme_checksum_sets($wpRoot, $intelDir, $fetchOfficial),
    ];
}

function load_plugin_checksum_sets(string $wpRoot, string $intelDir, bool $fetchOfficial): array {
    global $state;
    $sets = [];
    $pluginsDir = "$wpRoot/wp-content/plugins";
    if (!is_dir($pluginsDir)) {
        return $sets;
    }

    foreach (glob("$pluginsDir/*", GLOB_ONLYDIR) ?: [] as $pluginPath) {
        $slug = basename($pluginPath);

        if (malicious_plugin_slug_ioc($slug) !== null) {
            // The malware audit owns this directory. Do not mislabel a known IOC
            // as merely missing checksum intelligence.
            continue;
        }

        if (is_backup_component_directory($slug)) {
            say("WARN: backup/old plugin directory detected: $slug", true);
            $state['checksum_intel']['backup_plugin_dirs'][] = ['slug' => $slug];
            continue;
        }

        $version = detect_plugin_version($pluginPath, $slug);
        if (!$version) {
            say("WARN: plugin version not detected for $slug");
            $state['checksum_intel']['unknown_plugin_versions'][] = ['slug' => $slug];
            continue;
        }

        $local = "$intelDir/checksums/plugins/$slug/$version.json";
        $payload = load_component_checksum_payload($local);
        $map = $payload['files'];
        $cleanZip = $payload['clean_zip'];
        $source = $payload['source'];

        // Prefer an exact trusted local clean ZIP over any network lookup.
        $exactZip = find_existing_local_clean_zip(local_clean_zip_candidates('plugins', $slug, $version));
        if ($exactZip) {
            $exactSha256 = strtolower((string)@hash_file('sha256', $exactZip));
            $cachedZipSha256 = strtolower((string)($cleanZip['sha256'] ?? ''));
            $cachedZipPath = normalize_path((string)($cleanZip['path'] ?? ''));
            if (!$map || $source !== 'local-clean-zip' || $cachedZipSha256 !== $exactSha256 || $cachedZipPath !== normalize_path($exactZip)) {
                $map = build_component_checksums_from_zip($exactZip, $slug);
                if ($map) {
                    $source = 'local-clean-zip';
                    $cleanZip = [
                        'path' => $exactZip,
                        'sha256' => $exactSha256,
                        'source' => 'locally-approved-exact-package',
                        'acquired_at' => gmdate('c', (int)(@filemtime($exactZip) ?: time())),
                    ];
                    cache_checksum_file($local, [
                        'schema' => 'wp-warden.checksums.component.v1',
                        'type' => 'plugin',
                        'slug' => $slug,
                        'version' => $version,
                        'source' => 'local-clean-zip',
                        'created_at' => gmdate('c'),
                        'clean_zip' => $cleanZip,
                        'files' => $map,
                    ]);
                    $state['checksum_intel']['built_from_local_zip'][] = [
                        'type' => 'plugin', 'slug' => $slug, 'version' => $version, 'zip' => $exactZip,
                    ];
                    say("Built plugin checksum intel from local clean ZIP: $slug $version (" . count($map) . " files)", true);
                }
            }
        }

        // Migrate older API-only manifests to the exact release package when
        // network fetching is enabled. This is a one-time conversion because
        // the rewritten manifest records official-wordpress-zip as its source.
        if ($map && $fetchOfficial && $source === 'official-wordpress-checksum-api') {
            $official = official_component_zip('plugin', $slug, $version, $intelDir);
            if ($official) {
                $comparison = compare_checksum_maps($map, $official['files']);
                $map = $official['files'];
                $source = 'official-wordpress-zip';
                $cleanZip = [
                    'path'=>$official['zip'], 'sha256'=>$official['sha256'],
                    'source'=>'official-wordpress-release-package',
                    'source_url'=>$official['url'], 'acquired_at'=>gmdate('c'),
                ];
                cache_checksum_file($local, [
                    'schema'=>'wp-warden.checksums.component.v1', 'type'=>'plugin',
                    'slug'=>$slug, 'version'=>$version, 'source'=>$source,
                    'created_at'=>gmdate('c'), 'clean_zip'=>$cleanZip,
                    'upstream_comparison'=>$comparison, 'files'=>$map,
                ]);
                if ($comparison['different'] || $comparison['api_only'] || $comparison['zip_only']) {
                    say(sprintf(
                        '[SOURCE-MISMATCH] Migrated %s %s from API checksums to exact ZIP: different=%d api-only=%d zip-only=%d',
                        $slug, $version, $comparison['different'], $comparison['api_only'], $comparison['zip_only']
                    ), true);
                }
            }
        }

        if (!$map && $fetchOfficial && checksum_fetch_allowed($intelDir, 'plugin', $slug, $version)) {
            $fetched = fetch_plugin_checksums($slug, $version, $intelDir);
            $map = $fetched['files'];
            $source = $fetched['source'];
            $builtZip = $fetched['clean_zip'];

            if ($map) {
                checksum_fetch_clear_failure($intelDir, 'plugin', $slug, $version);
                if ($builtZip) {
                    $cleanZip = $builtZip;
                }
                cache_checksum_file($local, [
                    'schema' => 'wp-warden.checksums.component.v1',
                    'type' => 'plugin',
                    'slug' => $slug,
                    'version' => $version,
                    'source' => $source,
                    'created_at' => gmdate('c'),
                    'clean_zip' => $cleanZip,
                    'upstream_comparison' => $fetched['upstream_comparison'] ?? null,
                    'files' => $map,
                ]);
                if ($source === 'official-wordpress-zip') {
                    $state['checksum_intel']['built_from_official_zip'][] = [
                        'type' => 'plugin', 'slug' => $slug, 'version' => $version,
                    ];
                }
            } else {
                checksum_fetch_mark_failure($intelDir, 'plugin', $slug, $version);
            }
        }

        if ($map) {
            $sets[$slug] = [
                'version' => $version,
                'files' => normalize_checksum_map($map),
                'clean_zip' => $cleanZip,
                'source' => $source,
            ];
        } else {
            $state['checksum_intel']['missing_plugins'][] = [
                'slug' => $slug,
                'version' => $version,
                'expected_intel' => $local,
                'newer_local_versions' => local_component_versions('plugins', $slug, $version),
            ];
        }
    }

    return $sets;
}

function load_theme_checksum_sets(string $wpRoot, string $intelDir, bool $fetchOfficial): array {
    global $state;
    $sets = [];
    $themesDir = "$wpRoot/wp-content/themes";
    if (!is_dir($themesDir)) {
        return $sets;
    }

    foreach (glob("$themesDir/*", GLOB_ONLYDIR) ?: [] as $themePath) {
        $slug = basename($themePath);

        if (is_backup_component_directory($slug)) {
            say("WARN: backup/old theme directory detected: $slug", true);
            $state['checksum_intel']['backup_theme_dirs'][] = ['slug' => $slug];
            continue;
        }

        $version = detect_theme_version($themePath);
        if (!$version) {
            $state['checksum_intel']['unknown_theme_versions'][] = ['slug' => $slug];
            continue;
        }

        $local = "$intelDir/checksums/themes/$slug/$version.json";
        $payload = load_component_checksum_payload($local);
        $map = $payload['files'];
        $cleanZip = $payload['clean_zip'];
        $source = $payload['source'];

        // Exact local clean ZIP is the strongest/cheapest private theme source.
        $exactZip = find_existing_local_clean_zip(local_clean_zip_candidates('themes', $slug, $version));
        if ($exactZip) {
            $exactSha256 = strtolower((string)@hash_file('sha256', $exactZip));
            $cachedZipSha256 = strtolower((string)($cleanZip['sha256'] ?? ''));
            $cachedZipPath = normalize_path((string)($cleanZip['path'] ?? ''));
            if (!$map || $source !== 'local-clean-zip' || $cachedZipSha256 !== $exactSha256 || $cachedZipPath !== normalize_path($exactZip)) {
                $map = build_component_checksums_from_zip($exactZip, $slug);
                if ($map) {
                    $source = 'local-clean-zip';
                    $cleanZip = [
                        'path' => $exactZip,
                        'sha256' => $exactSha256,
                        'source' => 'locally-approved-exact-package',
                        'acquired_at' => gmdate('c', (int)(@filemtime($exactZip) ?: time())),
                    ];
                    cache_checksum_file($local, [
                        'schema' => 'wp-warden.checksums.component.v1',
                        'type' => 'theme',
                        'slug' => $slug,
                        'version' => $version,
                        'source' => 'local-clean-zip',
                        'created_at' => gmdate('c'),
                        'clean_zip' => $cleanZip,
                        'files' => $map,
                    ]);
                    $state['checksum_intel']['built_from_local_zip'][] = [
                        'type' => 'theme', 'slug' => $slug, 'version' => $version, 'zip' => $exactZip,
                    ];
                    say("Built theme checksum intel from local clean ZIP: $slug $version (" . count($map) . " files)", true);
                }
            }
        }

        if (!$map && $fetchOfficial && checksum_fetch_allowed($intelDir, 'theme', $slug, $version)) {
            $fetched = fetch_theme_checksums($slug, $version, $intelDir);
            $map = $fetched['files'];
            $source = $fetched['source'];
            $builtZip = $fetched['clean_zip'];

            if ($map) {
                checksum_fetch_clear_failure($intelDir, 'theme', $slug, $version);
                if ($builtZip) {
                    $cleanZip = $builtZip;
                }
                cache_checksum_file($local, [
                    'schema' => 'wp-warden.checksums.component.v1',
                    'type' => 'theme',
                    'slug' => $slug,
                    'version' => $version,
                    'source' => $source,
                    'created_at' => gmdate('c'),
                    'clean_zip' => $cleanZip,
                    'files' => $map,
                ]);
                if ($source === 'official-wordpress-zip') {
                    $state['checksum_intel']['built_from_official_zip'][] = [
                        'type' => 'theme', 'slug' => $slug, 'version' => $version,
                    ];
                }
            } else {
                checksum_fetch_mark_failure($intelDir, 'theme', $slug, $version);
            }
        }

        if ($map) {
            $sets[$slug] = [
                'version' => $version,
                'files' => normalize_checksum_map($map),
                'clean_zip' => $cleanZip,
                'source' => $source,
            ];
        } else {
            $state['checksum_intel']['missing_themes'][] = [
                'slug' => $slug,
                'version' => $version,
                'expected_intel' => $local,
                'newer_local_versions' => local_component_versions('themes', $slug, $version),
            ];
        }
    }

    return $sets;
}

function is_backup_component_directory(string $slug): bool {
    if ($slug === '__MACOSX' || $slug === '.' || $slug === '..') {
        return true;
    }

    // backup-backup is the published slug of the legitimate Backup Migration
    // plugin. Malware has been observed inside copies of it, so scan its files
    // normally instead of hiding it behind the generic "-backup" warning.
    if (strcasecmp($slug, 'backup-backup') === 0) {
        return false;
    }

    return warden_preg_match(
        '/(?:[._-](?:old|bak|backup|copy|disabled|orig|original|previous|temp|tmp)|~)$/i',
        $slug
    ) === 1;
}

function build_component_checksums_from_zip(string $zipPath, string $expectedSlug): array {
    if (!class_exists('ZipArchive') || !is_file($zipPath)) {
        return [];
    }

    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        return [];
    }

    $names = [];
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $name = str_replace('\\', '/', (string)$zip->getNameIndex($i));
        if ($name === '' || substr($name, -1) === '/') {
            continue;
        }
        if (strpos($name, '__MACOSX/') === 0 || basename($name) === '.DS_Store') {
            continue;
        }
        $names[] = ltrim($name, '/');
    }

    if (!$names) {
        $zip->close();
        return [];
    }

    // Most WordPress packages contain one top-level slug directory. Strip it
    // only when all files share that directory; otherwise preserve paths.
    $firstParts = [];
    foreach ($names as $name) {
        $parts = explode('/', $name, 2);
        if (count($parts) === 2) {
            $firstParts[$parts[0]] = true;
        } else {
            $firstParts[''] = true;
        }
    }
    $stripPrefix = count($firstParts) === 1 && !isset($firstParts[''])
        ? array_key_first($firstParts) . '/'
        : '';

    $map = [];
    foreach ($names as $name) {
        $rel = $stripPrefix !== '' && strpos($name, $stripPrefix) === 0
            ? substr($name, strlen($stripPrefix))
            : $name;
        if ($rel === '') {
            continue;
        }
        $data = $zip->getFromName($name);
        if ($data === false) {
            continue;
        }
        $map[$rel] = [
            'md5' => strtolower(hash('md5', $data)),
            'sha256' => strtolower(hash('sha256', $data)),
        ];
    }

    $zip->close();
    ksort($map);
    return $map;
}

function official_component_zip(string $type, string $slug, string $version, string $intelDir): ?array {
    global $packageCacheDir;

    if (!in_array($type, ['plugin', 'theme'], true)) {
        return null;
    }

    if (!is_dir($packageCacheDir) && !@mkdir($packageCacheDir, 0755, true) && !is_dir($packageCacheDir)) {
        return null;
    }

    // Use only the exact versioned package for checksum generation. Never use
    // the unversioned/latest ZIP to verify an older installed version.
    $url = $type === 'plugin'
        ? "https://downloads.wordpress.org/plugin/" . rawurlencode($slug) . "." . rawurlencode($version) . ".zip"
        : "https://downloads.wordpress.org/theme/" . rawurlencode($slug) . "." . rawurlencode($version) . ".zip";

    $cache = rtrim($packageCacheDir, '/') . "/checksum-$type-$slug-$version.zip";
    if (!is_file($cache) || filesize($cache) <= 0) {
        say("Fetching official $type package for checksum build: $url");
        $body = http_get_body($url);
        if (!is_string($body) || strlen($body) < 1000 || @file_put_contents($cache, $body, LOCK_EX) === false) {
            @unlink($cache);
            return null;
        }
    }

    $map = build_component_checksums_from_zip($cache, $slug);
    if (!$map) {
        return null;
    }

    return [
        'files' => $map,
        'zip' => $cache,
        'sha256' => strtolower((string)@hash_file('sha256', $cache)),
        'url' => $url,
    ];
}

function local_component_versions(string $kind, string $slug, string $installedVersion): array {
    global $intelDir;

    $versions = [];
    $roots = [
        rtrim($intelDir, '/') . '/clean-zips/' . trim($kind, '/'),
        dirname(rtrim($intelDir, '/')) . '/clean-zips/' . trim($kind, '/'),
    ];
    $home = getenv('HOME');
    if (is_string($home) && $home !== '') {
        $roots[] = normalize_path($home) . '/clean-zips/' . trim($kind, '/');
    }

    foreach (array_unique($roots) as $root) {
        if (!is_dir($root)) {
            continue;
        }
        foreach (glob(rtrim($root, '/') . '/' . $slug . '*.zip') ?: [] as $path) {
            $base = basename($path, '.zip');
            foreach ([
                '/^' . preg_quote($slug, '/') . '\.([0-9][A-Za-z0-9._+-]*)$/',
                '/^' . preg_quote($slug, '/') . '-([0-9][A-Za-z0-9._+-]*)$/',
            ] as $rx) {
                if (warden_preg_match($rx, $base, $m)) {
                    $v = $m[1];
                    if (version_compare($v, $installedVersion, '>')) {
                        $versions[$v] = true;
                    }
                }
            }
        }
        $dir = rtrim($root, '/') . '/' . $slug;
        if (is_dir($dir)) {
            foreach (glob($dir . '/*.zip') ?: [] as $path) {
                $v = basename($path, '.zip');
                if (version_compare($v, $installedVersion, '>')) {
                    $versions[$v] = true;
                }
            }
        }
    }

    $list = array_keys($versions);
    usort($list, 'version_compare');
    return array_reverse($list);
}

function checksum_failure_path(string $intelDir, string $type, string $slug, string $version): string {
    return rtrim($intelDir, '/') . '/cache/fetch-failures/' . $type . '-' . sha1($slug . '|' . $version) . '.json';
}
function checksum_fetch_allowed(string $intelDir, string $type, string $slug, string $version): bool {
    $p = checksum_failure_path($intelDir,$type,$slug,$version);
    if (!is_file($p)) return true;
    return (time() - (int)@filemtime($p)) >= 86400;
}
function checksum_fetch_mark_failure(string $intelDir, string $type, string $slug, string $version): void {
    $p=checksum_failure_path($intelDir,$type,$slug,$version); @mkdir(dirname($p),0755,true);
    @file_put_contents($p,json_encode(['type'=>$type,'slug'=>$slug,'version'=>$version,'failed_at'=>gmdate('c')],JSON_PRETTY_PRINT));
}
function checksum_fetch_clear_failure(string $intelDir, string $type, string $slug, string $version): void {
    @unlink(checksum_failure_path($intelDir,$type,$slug,$version));
}

function load_component_checksum_payload(string $path): array {
    if (!is_file($path)) {
        return ['files' => [], 'clean_zip' => null, 'source' => null];
    }
    $data = json_file($path);
    $cleanZip = normalize_clean_zip_intel($data['clean_zip'] ?? $data['package_zip'] ?? null);
    if (isset($data['files']) && is_array($data['files'])) {
        return ['files' => $data['files'], 'clean_zip' => $cleanZip, 'source' => $data['source'] ?? null];
    }
    return ['files' => $data, 'clean_zip' => $cleanZip, 'source' => $data['source'] ?? null];
}

function normalize_clean_zip_intel($value): ?array {
    if (is_string($value) && trim($value) !== '') {
        return ['path' => trim($value)];
    }
    if (is_array($value) && !empty($value['path'])) {
        return [
            'path' => (string)$value['path'],
            'sha256' => isset($value['sha256']) ? strtolower((string)$value['sha256']) : null,
            'source' => $value['source'] ?? null,
            'source_url' => $value['source_url'] ?? null,
            'acquired_at' => $value['acquired_at'] ?? null,
        ];
    }
    return null;
}

function fetch_plugin_checksums(string $slug, string $version, string $intelDir): array {
    // First use the official checksum endpoint when WordPress.org provides it.
    $url = "https://downloads.wordpress.org/plugin-checksums/" . rawurlencode($slug) . "/" . rawurlencode($version) . ".json";
    $data = http_get_json($url);

    if (isset($data['files']) && is_array($data['files'])) {
        $map = [];
        foreach ($data['files'] as $relPath => $info) {
            if (!is_array($info)) {
                continue;
            }
            $md5 = checksum_string($info['md5'] ?? null);
            $sha256 = checksum_string($info['sha256'] ?? null);
            if ($md5 || $sha256) {
                $entry = [];
                if ($md5) $entry['md5'] = $md5;
                if ($sha256) $entry['sha256'] = $sha256;
                $map[$relPath] = $entry;
            }
        }
        say("Fetched official plugin checksums: $slug $version (" . count($map) . " files)");
        // Use one exact release ZIP as both the verification and repair source.
        // Comparing the API is still valuable diagnostics, but mixing API
        // checksums with ZIP/SVN replacement bytes can make valid repairs fail.
        $official = official_component_zip('plugin', $slug, $version, $intelDir);
        if ($official) {
            $comparison = compare_checksum_maps($map, $official['files']);
            if ($comparison['different'] > 0 || $comparison['api_only'] > 0 || $comparison['zip_only'] > 0) {
                say(sprintf(
                    '[SOURCE-MISMATCH] WordPress checksum API and exact ZIP differ for %s %s: different=%d api-only=%d zip-only=%d; using exact ZIP',
                    $slug, $version, $comparison['different'], $comparison['api_only'], $comparison['zip_only']
                ), true);
            }
            return [
                'files' => $official['files'],
                'source' => 'official-wordpress-zip',
                'clean_zip' => [
                    'path' => $official['zip'],
                    'sha256' => $official['sha256'],
                    'source' => 'official-wordpress-release-package',
                    'source_url' => $official['url'],
                    'acquired_at' => gmdate('c'),
                ],
                'upstream_comparison' => $comparison,
            ];
        }
        return ['files'=>$map, 'source'=>'official-wordpress-checksum-api', 'clean_zip'=>null, 'upstream_comparison'=>null];
    }

    say("WARN: official plugin checksum fetch failed for $slug $version");

    // WordPress.org may serve an exact historical ZIP even when its checksum
    // endpoint lacks that release. Build trusted checksums from that ZIP.
    $official = official_component_zip('plugin', $slug, $version, $intelDir);
    if ($official) {
        say("Built official plugin checksums from WordPress ZIP: $slug $version (" . count($official['files']) . " files)", true);
        return [
            'files' => $official['files'],
            'source' => 'official-wordpress-zip',
            'clean_zip' => [
                'path'=>$official['zip'], 'sha256'=>$official['sha256'],
                'source'=>'official-wordpress-release-package',
                'source_url'=>$official['url'], 'acquired_at'=>gmdate('c'),
            ],
            'upstream_comparison' => null,
        ];
    }

    // Last resort for old/public releases.
    $fallback = fetch_wpmd5_checksums("plugin/$slug/$version");
    if ($fallback) {
        say("Fetched wpmd5 fallback plugin checksums: $slug $version (" . count($fallback) . " files)");
        return ['files'=>$fallback, 'source'=>'wpmd5-fallback', 'clean_zip'=>null];
    }

    return ['files'=>[], 'source'=>'none', 'clean_zip'=>null];
}

function fetch_theme_checksums(string $slug, string $version, string $intelDir): array {
    // WordPress.org does not expose the same theme checksum JSON endpoint used
    // for plugins, but it does serve exact official theme ZIPs. Prefer those.
    $official = official_component_zip('theme', $slug, $version, $intelDir);
    if ($official) {
        say("Built official theme checksums from WordPress ZIP: $slug $version (" . count($official['files']) . " files)", true);
        return [
            'files' => $official['files'],
            'source' => 'official-wordpress-zip',
            'clean_zip' => [
                'path'=>$official['zip'], 'sha256'=>$official['sha256'],
                'source'=>'official-wordpress-release-package',
                'source_url'=>$official['url'], 'acquired_at'=>gmdate('c'),
            ],
        ];
    }

    // wpmd5 remains a final fallback for historical themes no longer served.
    $fallback = fetch_wpmd5_checksums("theme/$slug/$version");
    if ($fallback) {
        say("Fetched wpmd5 theme checksums: $slug $version (" . count($fallback) . " files)");
        return ['files'=>$fallback, 'source'=>'wpmd5-fallback', 'clean_zip'=>null];
    }

    say("WARN: no theme checksum source found for $slug $version");
    return ['files'=>[], 'source'=>'none', 'clean_zip'=>null];
}

function detect_plugin_version(string $pluginPath, string $slug): ?string {
    $candidates = [];
    $main = "$pluginPath/$slug.php";
    if (is_file($main)) {
        $candidates[] = $main;
    }
    foreach (glob("$pluginPath/*.php") ?: [] as $file) {
        if (!in_array($file, $candidates, true)) {
            $candidates[] = $file;
        }
    }

    foreach ($candidates as $file) {
        $head = @file_get_contents($file, false, null, 0, 8192);
        if (!is_string($head)) {
            continue;
        }
        if (warden_preg_match('/^[ \t\/*#@]*Version:\s*(.+)$/mi', $head, $m)) {
            return trim($m[1]);
        }
    }

    $readme = "$pluginPath/readme.txt";
    if (is_file($readme)) {
        $head = @file_get_contents($readme, false, null, 0, 8192);
        if (is_string($head) && warden_preg_match('/^[ \t]*Stable tag:\s*(.+)$/mi', $head, $m)) {
            $version = trim($m[1]);
            return strtolower($version) === 'trunk' ? null : $version;
        }
    }
    return null;
}

function detect_theme_version(string $themePath): ?string {
    $style = "$themePath/style.css";
    if (!is_file($style)) {
        return null;
    }
    $head = @file_get_contents($style, false, null, 0, 8192);
    if (is_string($head) && warden_preg_match('/^[ \t\/*#@]*Version:\s*(.+)$/mi', $head, $m)) {
        return trim($m[1]);
    }
    return null;
}

function cache_checksum_file(string $path, array $payload): void {
    $dir = dirname($path);
    if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
        say("WARN: could not create checksum cache directory: $dir", true);
        return;
    }
    if (@file_put_contents($path, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) === false) {
        say("WARN: could not write checksum cache: $path", true);
    }
}

function maybe_offer_original_repair(string $type, ?string $slug, ?string $version, string $relativePath, string $absPath, array $expected, ?array $cleanZip = null): bool {
    global $repairOriginal, $repairOriginalAuto, $apply, $interactive, $nonInteractive;

    if (!$repairOriginal) {
        return false;
    }

    $package = repair_package_info($type, $slug, $version, $cleanZip);
    if (!$package) {
        say("[REPAIR-SKIP] No clean package source available for $relativePath");
        return false;
    }

    if (!$apply) {
        say("[REPAIR-DRY-RUN] Would replace from {$package['url']}: $relativePath");
        return false;
    }

    if (!$repairOriginalAuto) {
        if (!$interactive || $nonInteractive) {
            say("[REPAIR-SKIP] Interactive repair needed for $relativePath; use --repair-original-auto with --apply for noninteractive repair");
            return false;
        }

        echo "Repair from clean {$package['label']} package? $relativePath [y/N] ";
        $answer = strtolower(trim((string)fgets(STDIN)));
        if ($answer !== 'y' && $answer !== 'yes') {
            say("[REPAIR-SKIP] Left unchanged: $relativePath");
            return false;
        }
    }

    return repair_from_package($package, $relativePath, $absPath, $expected);
}

function should_offer_repair_after_finding(): bool {
    global $apply, $interactive, $nonInteractive, $repairOriginalAuto;

    if (!$apply) {
        return true;
    }
    if ($repairOriginalAuto || $nonInteractive || !$interactive) {
        return true;
    }
    return false;
}

function repair_package_info(string $type, ?string $slug, ?string $version, ?array $cleanZip = null): ?array {
    global $wpVersion, $intelDir;

    if ($cleanZip && !empty($cleanZip['path'])) {
        $zipPath = normalize_path((string)$cleanZip['path']);
        if (!warden_preg_match('#^([A-Za-z]:)?/#', $zipPath)) {
            $zipPath = rtrim($intelDir, '/') . '/' . ltrim($zipPath, '/');
        }

        return [
            'type' => $type,
            'label' => "$type $slug $version local clean ZIP",
            'url' => $zipPath,
            'local_path' => $zipPath,
            'clean_zip_sha256' => $cleanZip['sha256'] ?? null,
            'package_source' => $cleanZip['source'] ?? 'checksum-intel-clean-zip',
            'source_url' => $cleanZip['source_url'] ?? null,
            'cache_name' => basename($zipPath),
            'zip_prefix' => $type === 'core' ? 'wordpress/' : (($slug ?: '') . '/'),
        ];
    }

    if ($type === 'core') {
        if (!$wpVersion) {
            return null;
        }
        return [
            'type' => 'core',
            'label' => 'WordPress core',
            'url' => "https://wordpress.org/wordpress-$wpVersion.zip",
            'cache_name' => "wordpress-$wpVersion.zip",
            'zip_prefix' => 'wordpress/',
        ];
    }

    if ($type === 'plugin' && $slug && $version) {
        return [
            'type' => 'plugin',
            'label' => "plugin $slug $version",
            'url' => "https://downloads.wordpress.org/plugin/$slug.$version.zip",
            'alternate_urls' => [
                "https://downloads.wordpress.org/plugin/$slug.zip",
            ],
            'cache_name' => "plugin-$slug-$version.zip",
            'zip_prefix' => "$slug/",
            'fallback_local_paths' => local_clean_zip_candidates('plugins', $slug, $version),
            'svn_base_url' => "https://plugins.svn.wordpress.org/$slug/tags/$version/",
        ];
    }

    if ($type === 'theme' && $slug && $version) {
        return [
            'type' => 'theme',
            'label' => "theme $slug $version",
            'url' => "https://downloads.wordpress.org/theme/$slug.$version.zip",
            'alternate_urls' => [
                "https://downloads.wordpress.org/theme/$slug.zip",
            ],
            'cache_name' => "theme-$slug-$version.zip",
            'zip_prefix' => "$slug/",
            'fallback_local_paths' => local_clean_zip_candidates('themes', $slug, $version),
            'svn_base_url' => "https://themes.svn.wordpress.org/$slug/$version/",
        ];
    }

    return null;
}

function local_clean_zip_candidates(string $kind, string $slug, string $version): array {
    global $intelDir;

    $kind = trim($kind, '/');
    $roots = [
        rtrim($intelDir, '/') . '/clean-zips',
        dirname(rtrim($intelDir, '/')) . '/clean-zips',
    ];

    $home = getenv('HOME');
    if (is_string($home) && $home !== '') {
        $roots[] = normalize_path($home) . '/clean-zips';
    }
    $cwd = getcwd();
    if (is_string($cwd) && $cwd !== '') {
        $roots[] = normalize_path($cwd) . '/clean-zips';
    }

    $paths = [];
    foreach (array_unique($roots) as $root) {
        $base = rtrim($root, '/') . '/' . $kind;
        foreach ([
            "$base/$slug.$version.zip",
            "$base/$slug-$version.zip",
            "$base/$slug/$version.zip",
            "$base/$slug/$slug.$version.zip",
            "$base/$slug/$slug-$version.zip",
        ] as $path) {
            $paths[$path] = true;
        }
    }
    return array_keys($paths);
}

function repair_from_package(array $package, string $relativePath, string $absPath, array $expected): bool {
    global $state;
    $started = microtime(true);
    $state['timing']['repair_attempts'] = (int)($state['timing']['repair_attempts'] ?? 0) + 1;
    $ok = repair_from_package_impl($package, $relativePath, $absPath, $expected);
    $state['timing']['repair_seconds'] = round((float)($state['timing']['repair_seconds'] ?? 0) + (microtime(true)-$started), 3);
    if (!$ok) $state['timing']['repair_failures'] = (int)($state['timing']['repair_failures'] ?? 0) + 1;
    return $ok;
}

function repair_from_package_impl(array $package, string $relativePath, string $absPath, array $expected): bool {
    global $state;

    if (!class_exists('ZipArchive')) {
        say("[REPAIR-FAIL] PHP ZipArchive extension is not available; cannot repair $relativePath", true);
        if (in_array(($package['type'] ?? ''), ['plugin', 'theme'], true)) {
            return false;
        }
        return repair_from_svn_file($package, $relativePath, $absPath, $expected);
    }

    $zipPath = ensure_package_zip($package);
    if (!$zipPath) {
        say("[REPAIR] Could not get clean ZIP package: {$package['url']}", true);
        if (!empty($package['fallback_local_paths'])) {
            say("[REPAIR] Local clean ZIP paths checked:", true);
            foreach ($package['fallback_local_paths'] as $path) {
                say("  - $path", true);
            }
        }
        if (in_array(($package['type'] ?? ''), ['plugin', 'theme'], true)) {
            return false;
        }
        return repair_from_svn_file($package, $relativePath, $absPath, $expected);
    }

    $zipInnerPath = package_inner_path($package, $relativePath);
    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        say("[REPAIR-FAIL] Could not open package ZIP: $zipPath", true);
        return false;
    }

    $data = $zip->getFromName($zipInnerPath);
    if ($data === false && in_array(($package['type'] ?? ''), ['plugin', 'theme'], true)) {
        $resolved = resolve_component_zip_entry_by_checksum($zip, $relativePath, $expected);
        if ($resolved !== null) {
            $zipInnerPath = $resolved['path'];
            $data = $resolved['data'];
            say("[REPAIR] Resolved clean package path: $zipInnerPath", true);
        }
    }
    $zip->close();
    if ($data === false) {
        say("[REPAIR-FAIL] Clean package does not contain $zipInnerPath", true);
        return false;
    }

    $candidate = [
        'md5' => strtolower(hash('md5', $data)),
        'sha256' => strtolower(hash('sha256', $data)),
    ];
    if (!hash_matches($candidate, $expected)) {
        if (in_array(($package['type'] ?? ''), ['plugin', 'theme'], true)) {
            record_upstream_source_mismatch($package, $relativePath, $absPath, $expected, $candidate);
            return false;
        }
        say("[REPAIR] Package file checksum did not match intel for $relativePath; trying SVN fallback", true);
        return repair_from_svn_file($package, $relativePath, $absPath, $expected);
    }

    $backup = backup_before_repair($absPath, $relativePath);
    if ($backup === null) {
        say("[REPAIR-FAIL] Could not backup original file before repair: $relativePath", true);
        return false;
    }

    if (@file_put_contents($absPath, $data, LOCK_EX) === false) {
        say("[REPAIR-FAIL] Could not write repaired file: $absPath", true);
        return false;
    }

    $action = [
        'type' => 'repair_original',
        'path' => $absPath,
        'relative_path' => $relativePath,
        'backup' => $backup,
        'package' => $zipPath,
        'package_source' => $package['url'],
        'at' => gmdate('c'),
    ];
    $state['actions'][] = $action;
    $state['summary']['actions_taken']++;
    say("[REPAIRED] $relativePath from {$package['label']}", true);
    return true;
}

function resolve_component_zip_entry_by_checksum(ZipArchive $zip, string $relativePath, array $expected): ?array {
    $componentPath = component_relative_path($relativePath);
    if ($componentPath === null || $componentPath === '') {
        return null;
    }

    $suffix = '/' . $componentPath;
    $matches = [];
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $name = ltrim(str_replace('\\', '/', (string)$zip->getNameIndex($i)), '/');
        if ($name === '' || substr($name, -1) === '/' || strpos($name, "\0") !== false) {
            continue;
        }
        if ($name !== $componentPath && substr($name, -strlen($suffix)) !== $suffix) {
            continue;
        }

        // Reject traversal-style archive names even though this code reads the
        // entry into memory rather than extracting it directly.
        foreach (explode('/', $name) as $part) {
            if ($part === '..') {
                continue 2;
            }
        }

        $data = $zip->getFromIndex($i);
        if (!is_string($data)) {
            continue;
        }
        $candidate = [
            'md5' => strtolower(hash('md5', $data)),
            'sha256' => strtolower(hash('sha256', $data)),
        ];
        if (hash_matches($candidate, $expected)) {
            $matches[] = ['path' => $name, 'data' => $data];
        }
    }

    if (!$matches) {
        return null;
    }
    usort($matches, static function (array $a, array $b): int {
        $lengthOrder = strlen($a['path']) <=> strlen($b['path']);
        return $lengthOrder !== 0 ? $lengthOrder : strcmp($a['path'], $b['path']);
    });
    return $matches[0];
}

function component_relative_path(string $relativePath): ?string {
    foreach (['wp-content/plugins/', 'wp-content/themes/'] as $prefix) {
        if (strpos($relativePath, $prefix) !== 0) {
            continue;
        }
        $parts = explode('/', substr($relativePath, strlen($prefix)), 2);
        return isset($parts[1]) && $parts[1] !== '' ? $parts[1] : null;
    }
    return null;
}

function repair_from_svn_file(array $package, string $relativePath, string $absPath, array $expected): bool {
    global $state;
    $started = microtime(true);
    $state['timing']['svn_attempts'] = (int)($state['timing']['svn_attempts'] ?? 0) + 1;
    $ok = repair_from_svn_file_impl($package, $relativePath, $absPath, $expected);
    $state['timing']['svn_seconds'] = round((float)($state['timing']['svn_seconds'] ?? 0) + (microtime(true)-$started), 3);
    if (!$ok) $state['timing']['svn_failures'] = (int)($state['timing']['svn_failures'] ?? 0) + 1;
    return $ok;
}

function repair_from_svn_file_impl(array $package, string $relativePath, string $absPath, array $expected): bool {
    global $state;

    if (empty($package['svn_base_url'])) {
        say("[REPAIR-FAIL] No SVN fallback source available for $relativePath", true);
        return false;
    }

    $inner = package_inner_path($package, $relativePath);
    $prefix = $package['zip_prefix'] ?? '';
    if ($prefix !== '' && strpos($inner, $prefix) === 0) {
        $inner = substr($inner, strlen($prefix));
    }
    $svnUrl = rtrim($package['svn_base_url'], '/') . '/' . rawurlencode_path($inner);
    say("[REPAIR] Fetching clean file from SVN: $svnUrl", true);

    $data = http_get_body($svnUrl);
    if (!is_string($data) || $data === '') {
        say("[REPAIR-FAIL] Could not fetch clean file from SVN: $svnUrl", true);
        return false;
    }

    $candidate = [
        'md5' => strtolower(hash('md5', $data)),
        'sha256' => strtolower(hash('sha256', $data)),
    ];
    if (!hash_matches($candidate, $expected)) {
        say("[REPAIR-FAIL] SVN file checksum did not match intel for $relativePath", true);
        return false;
    }

    $backup = backup_before_repair($absPath, $relativePath);
    if ($backup === null) {
        say("[REPAIR-FAIL] Could not backup original file before SVN repair: $relativePath", true);
        return false;
    }

    if (@file_put_contents($absPath, $data, LOCK_EX) === false) {
        say("[REPAIR-FAIL] Could not write SVN repaired file: $absPath", true);
        return false;
    }

    $action = [
        'type' => 'repair_svn',
        'path' => $absPath,
        'relative_path' => $relativePath,
        'backup' => $backup,
        'package' => $svnUrl,
        'package_source' => $package['svn_base_url'],
        'at' => gmdate('c'),
    ];
    $state['actions'][] = $action;
    $state['summary']['actions_taken']++;
    say("[REPAIRED] $relativePath from SVN {$package['label']}", true);
    return true;
}

function ensure_package_zip(array $package): ?string {
    global $packageCacheDir;

    if (!empty($package['local_path'])) {
        $zipPath = $package['local_path'];
        if (!is_file($zipPath) || filesize($zipPath) <= 0) {
            return null;
        }
        if (!empty($package['clean_zip_sha256'])) {
            $actual = strtolower((string)@hash_file('sha256', $zipPath));
            if (!$actual || !hash_equals($package['clean_zip_sha256'], $actual)) {
                say("[REPAIR-FAIL] Clean ZIP SHA-256 did not match intel: $zipPath", true);
                return null;
            }
        }
        return $zipPath;
    }

    $fallback = find_existing_local_clean_zip($package['fallback_local_paths'] ?? []);
    if ($fallback) {
        say("[REPAIR] Using local clean ZIP: $fallback");
        return $fallback;
    }

    if (!is_dir($packageCacheDir) && !@mkdir($packageCacheDir, 0755, true) && !is_dir($packageCacheDir)) {
        return null;
    }

    $zipPath = rtrim($packageCacheDir, '/') . '/' . $package['cache_name'];
    if (is_file($zipPath) && filesize($zipPath) > 0) {
        return $zipPath;
    }

    $urls = array_values(array_unique(array_merge([$package['url']], $package['alternate_urls'] ?? [])));
    foreach ($urls as $idx => $url) {
        $candidatePath = $idx === 0
            ? $zipPath
            : rtrim($packageCacheDir, '/') . '/' . alternate_package_cache_name($package, $url);
        $downloaded = download_package_zip($url, $candidatePath);
        if ($downloaded) {
            return $downloaded;
        }
    }

    $fallback = find_existing_local_clean_zip($package['fallback_local_paths'] ?? []);
    if ($fallback) {
        say("[REPAIR] Download failed; using local clean ZIP: $fallback", true);
        return $fallback;
    }
    return null;
}

function download_package_zip(string $url, string $zipPath): ?string {
    say("[REPAIR] Downloading clean package: $url");
    $body = http_get_body($url);
    if (!is_string($body) || strlen($body) < 1000) {
        return null;
    }
    if (@file_put_contents($zipPath, $body, LOCK_EX) === false) {
        return null;
    }
    return $zipPath;
}

function alternate_package_cache_name(array $package, string $url): string {
    $base = basename(parse_url($url, PHP_URL_PATH) ?: $url);
    $base = preg_replace('/[^A-Za-z0-9._-]+/', '-', $base);
    if (!is_string($base) || $base === '' || strtolower($base) === '.zip') {
        $base = 'alternate-' . ($package['cache_name'] ?? 'package.zip');
    }
    return 'alternate-' . $base;
}

function rawurlencode_path(string $path): string {
    return implode('/', array_map('rawurlencode', explode('/', ltrim($path, '/'))));
}

function find_existing_local_clean_zip(array $paths): ?string {
    foreach ($paths as $path) {
        $path = normalize_path((string)$path);
        if (is_file($path) && filesize($path) > 0) {
            return $path;
        }
    }
    return null;
}

function package_inner_path(array $package, string $relativePath): string {
    if ($package['zip_prefix'] === 'wordpress/') {
        return 'wordpress/' . $relativePath;
    }

    if (strpos($relativePath, 'wp-content/plugins/') === 0) {
        $parts = explode('/', substr($relativePath, strlen('wp-content/plugins/')), 2);
        return $package['zip_prefix'] . ($parts[1] ?? '');
    }

    if (strpos($relativePath, 'wp-content/themes/') === 0) {
        $parts = explode('/', substr($relativePath, strlen('wp-content/themes/')), 2);
        return $package['zip_prefix'] . ($parts[1] ?? '');
    }

    return $package['zip_prefix'] . basename($relativePath);
}

function backup_before_repair(string $absPath, string $relativePath): ?string {
    global $repairBackupDir;

    if (!is_file($absPath)) {
        return null;
    }
    $dest = rtrim($repairBackupDir, '/') . '/' . $relativePath;
    $dir = dirname($dest);
    if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
        return null;
    }
    if (is_file($dest)) {
        $dest .= '.bak-' . gmdate('His');
    }
    return @copy($absPath, $dest) ? $dest : null;
}

function http_get_json(string $url): array {
    say("Fetching: $url");
    $body = http_get_body($url);
    $data = is_string($body) ? json_decode($body, true) : null;
    return is_array($data) ? $data : [];
}

function http_get_body(string $url) {
    global $state;
    $started = microtime(true);
    $state['timing']['http_requests'] = (int)($state['timing']['http_requests'] ?? 0) + 1;

    $body = false;
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 7,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'WP-Warden/' . WP_WARDEN_VERSION,
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if (!(is_string($body) && $body !== '' && $code >= 200 && $code < 400)) {
            $body = false;
        }
    } else {
        $context = stream_context_create(['http'=>[
            'ignore_errors'=>true,
            'timeout'=>7,
            'header'=>"User-Agent: WP-Warden/" . WP_WARDEN_VERSION . "\\r\\n",
        ]]);
        $body = @file_get_contents($url,false,$context);
    }

    $elapsed = microtime(true) - $started;
    $state['timing']['http_seconds'] = round((float)($state['timing']['http_seconds'] ?? 0) + $elapsed, 3);
    if ($body === false) {
        $state['timing']['http_failures'] = (int)($state['timing']['http_failures'] ?? 0) + 1;
    }
    return $body;
}

function fetch_wpmd5_checksums(string $path): array {
    $url = 'http://wpmd5.mattjung.net/' . trim($path, '/') . '/';
    say("Fetching fallback: $url");
    $body = http_get_body($url);
    if (!is_string($body) || trim($body) === '') {
        return [];
    }

    $json = json_decode($body, true);
    if (is_array($json) && !empty($json)) {
        return normalize_wpmd5_payload($json);
    }

    return parse_md5sum_listing($body);
}

function normalize_wpmd5_payload(array $payload): array {
    if (isset($payload['files']) && is_array($payload['files'])) {
        $payload = $payload['files'];
    }

    $map = [];
    foreach ($payload as $path => $value) {
        if (is_string($value)) {
            $hash = checksum_string($value);
            if ($hash) {
                $map[$path] = ['md5' => $hash];
            }
            continue;
        }
        if (is_array($value)) {
            $md5 = checksum_string($value['md5'] ?? $value['hash'] ?? $value);
            $sha256 = checksum_string($value['sha256'] ?? null);
            if ($md5 || $sha256) {
                $entry = [];
                if ($md5) {
                    $entry['md5'] = $md5;
                }
                if ($sha256) {
                    $entry['sha256'] = $sha256;
                }
                $map[$path] = $entry;
            }
        }
    }
    return $map;
}

function parse_md5sum_listing(string $body): array {
    $map = [];
    foreach (preg_split('/\r?\n/', $body) as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        if (warden_preg_match('/^([0-9a-f]{32})\s+\.(\/.+)$/i', $line, $m)) {
            $map[ltrim($m[2], './')] = ['md5' => strtolower($m[1])];
            continue;
        }
        if (warden_preg_match('/^([0-9a-f]{32})\s+(.+)$/i', $line, $m)) {
            $map[ltrim($m[2], './')] = ['md5' => strtolower($m[1])];
        }
    }
    return $map;
}

function normalize_checksum_map(array $files): array {
    $map = [];
    foreach ($files as $path => $value) {
        $rel = normalize_relative($path);
        if (is_string($value)) {
            $map[$rel] = ['md5' => strtolower($value)];
        } elseif (is_array($value)) {
            $md5 = checksum_string($value['md5'] ?? null);
            $sha256 = checksum_string($value['sha256'] ?? null);
            $map[$rel] = [
                'md5' => $md5,
                'sha256' => $sha256,
            ];
        }
    }
    return $map;
}

function checksum_string($value): ?string {
    if (is_string($value) && warden_preg_match('/^[a-f0-9]{32,64}$/i', $value)) {
        return strtolower($value);
    }
    if (is_array($value)) {
        foreach ($value as $candidate) {
            $hash = checksum_string($candidate);
            if ($hash !== null) {
                return $hash;
            }
        }
    }
    return null;
}

function build_file_cache_context(array $intel, array $coreChecksums, array $componentChecksums, bool $verifyAll, int $maxSizeMb, int $maxTextSizeMb, bool $excludePdf): array {
    $ruleFingerprint = [];
    foreach (($intel['php_rules'] ?? []) as $rule) {
        $ruleFingerprint[] = [
            'id' => $rule['id'] ?? null,
            'enabled' => $rule['enabled'] ?? true,
            'severity' => $rule['severity'] ?? null,
            'type' => $rule['type'] ?? null,
            'pattern' => $rule['pattern'] ?? null,
            'anchors' => $rule['anchors'] ?? ($rule['anchor'] ?? null),
        ];
    }

    $pluginHashes = [];
    foreach (($componentChecksums['plugins'] ?? []) as $slug => $data) {
        $pluginHashes[(string)$slug] = hash('sha256', serialize([
            'version' => $data['version'] ?? null,
            'files' => $data['files'] ?? [],
        ]));
    }

    $themeHashes = [];
    foreach (($componentChecksums['themes'] ?? []) as $slug => $data) {
        $themeHashes[(string)$slug] = hash('sha256', serialize([
            'version' => $data['version'] ?? null,
            'files' => $data['files'] ?? [],
        ]));
    }

    return [
        // Base inputs can affect malware/policy treatment independent of component
        // checksum maps, so a base change deliberately invalidates all clean files.
        'base' => hash('sha256', serialize([
            'cache_version' => WP_WARDEN_CACHE_VERSION,
            'verify_all' => $verifyAll,
            'max_size_mb' => $maxSizeMb,
            'max_text_size_mb' => $maxTextSizeMb,
            'exclude_pdf' => $excludePdf,
            'policy' => $intel['policy'] ?? [],
            'rules' => $ruleFingerprint,
            'whitelist_keys' => array_keys($intel['file_whitelist'] ?? []),
        ])),
        'core' => hash('sha256', serialize($coreChecksums)),
        'plugins' => $pluginHashes,
        'themes' => $themeHashes,
    ];
}

function file_cache_signature_for_path(string $rel, array $context): string {
    $rel = normalize_relative($rel);
    $parts = [
        'base' => $context['base'] ?? '',
    ];

    // Core checksum changes should invalidate only WordPress core files.
    if (
        strpos($rel, 'wp-admin/') === 0
        || strpos($rel, 'wp-includes/') === 0
        || in_array($rel, [
            'index.php',
            'wp-activate.php',
            'wp-blog-header.php',
            'wp-comments-post.php',
            'wp-config-sample.php',
            'wp-cron.php',
            'wp-links-opml.php',
            'wp-load.php',
            'wp-login.php',
            'wp-mail.php',
            'wp-settings.php',
            'wp-signup.php',
            'wp-trackback.php',
            'xmlrpc.php',
        ], true)
    ) {
        $parts['core'] = $context['core'] ?? '';
    }

    // Component checksum changes are scoped to the affected plugin/theme only.
    if (warden_preg_match('#^wp-content/plugins/([^/]+)/#', $rel, $m)) {
        $slug = $m[1];
        $parts['plugin'] = $context['plugins'][$slug] ?? 'no-checksum-intel';
    }

    if (warden_preg_match('#^wp-content/themes/([^/]+)/#', $rel, $m)) {
        $slug = $m[1];
        $parts['theme'] = $context['themes'][$slug] ?? 'no-checksum-intel';
    }

    return hash('sha256', serialize($parts));
}

function file_cache_path(string $cacheDir, string $wpRoot): string {
    $real = normalize_path(realpath($wpRoot) ?: $wpRoot);
    return rtrim($cacheDir, '/') . '/site-' . sha1($real) . '.json';
}

function load_file_cache(string $path, string $signature, string $wpRoot): array {
    if (!is_file($path)) {
        return [];
    }

    $data = json_file($path);
    if (($data['schema'] ?? '') !== 'wp-warden.file-cache.v1') {
        return [];
    }
    if (!hash_equals((string)($data['signature'] ?? ''), $signature)) {
        say("Cache intel changed; cached files will be validated individually", true);
    }

    $cachedTarget = normalize_path((string)($data['target'] ?? ''));
    $target = normalize_path(realpath($wpRoot) ?: $wpRoot);
    if ($cachedTarget !== $target) {
        return [];
    }

    return is_array($data['entries'] ?? null) ? $data['entries'] : [];
}

function file_cache_stat(string $path): ?array {
    clearstatcache(true, $path);
    $st = @stat($path);
    if (!is_array($st)) {
        return null;
    }

    return [
        'dev' => (string)($st['dev'] ?? ''),
        'ino' => (string)($st['ino'] ?? ''),
        'size' => (string)($st['size'] ?? ''),
        'mtime' => (string)($st['mtime'] ?? ''),
        'ctime' => (string)($st['ctime'] ?? ''),
    ];
}

function file_cache_is_clean(string $path, string $rel): bool {
    global $fileCacheEntries, $fileCacheSeen, $fileCacheContext, $fileCacheDirty, $scanRuntime;

    if (!empty($scanRuntime['global_pcre_error'])) {
        return false;
    }

    $rel = normalize_relative($rel);
    $fileCacheSeen[$rel] = true;
    $entry = $fileCacheEntries[$rel] ?? null;
    if (!is_array($entry) || ($entry['status'] ?? '') !== 'clean') {
        return false;
    }

    $currentSignature = file_cache_signature_for_path($rel, $fileCacheContext);
    $cachedSignature = (string)($entry['scan_signature'] ?? '');

    if ($cachedSignature !== '') {
        // v0.1.42+ entry: only reuse it when the intel applicable to this path
        // is unchanged.
        if (!hash_equals($cachedSignature, $currentSignature)) {
            unset($fileCacheEntries[$rel]);
            $fileCacheDirty = true;
            return false;
        }
    } else {
        // Legacy v0.1.41 migration: reuse an unchanged clean entry once, then
        // stamp it with the new per-file signature. This preserves the existing
        // cache without leaving permanently unsigned entries behind.
        $fileCacheEntries[$rel]['scan_signature'] = $currentSignature;
        $fileCacheEntries[$rel]['migrated_at'] = gmdate('c');
        $fileCacheDirty = true;
    }

    $st = file_cache_stat($path);
    if ($st === null) {
        return false;
    }

    foreach (['dev', 'ino', 'size', 'mtime', 'ctime'] as $key) {
        if ((string)($entry[$key] ?? '') !== $st[$key]) {
            unset($fileCacheEntries[$rel]);
            $fileCacheDirty = true;
            return false;
        }
    }

    // Take a second metadata snapshot before accepting the cache hit. This is
    // intentionally cheap and prevents a file changing during cache validation
    // from being silently treated as clean.
    $verified = file_cache_stat($path);
    if ($verified === null || !file_metadata_equal($st, $verified)) {
        unset($fileCacheEntries[$rel]);
        $fileCacheDirty = true;
        return false;
    }

    return true;
}

function record_upstream_source_mismatch(array $package, string $relativePath, string $absPath, array $expected, array $candidate): void {
    $severity = component_checksum_mismatch_severity($relativePath);
    say("[SOURCE-MISMATCH] Package bytes disagree with checksum intel; repair skipped: $relativePath", true);
    add_finding([
        'severity' => $severity,
        'type' => 'upstream_source_mismatch',
        'rule_id' => 'BUILTIN_UPSTREAM_PACKAGE_CHECKSUM_MISMATCH_001',
        'path' => $absPath,
        'relative_path' => $relativePath,
        'package_type' => $package['type'] ?? null,
        'package_source' => $package['package_source'] ?? $package['url'] ?? null,
        'package_url' => $package['source_url'] ?? $package['url'] ?? null,
        'expected' => $expected,
        'package_file_hashes' => $candidate,
        'reason' => 'The exact package file does not match the stored checksum source. WP-Warden refused to mix sources or overwrite the installed file.',
        'file_action' => false,
        'recommended_action' => 'Refresh checksum intel from the exact approved release ZIP and review upstream packaging differences.',
    ], false);
}

function compare_checksum_maps(array $apiMap, array $zipMap): array {
    $apiMap = normalize_checksum_map($apiMap);
    $zipMap = normalize_checksum_map($zipMap);
    $out = ['different'=>0, 'api_only'=>0, 'zip_only'=>0];
    foreach ($apiMap as $path => $expected) {
        if (!isset($zipMap[$path])) {
            $out['api_only']++;
        } elseif (!hash_matches($zipMap[$path], $expected)) {
            $out['different']++;
        }
    }
    foreach ($zipMap as $path => $_) {
        if (!isset($apiMap[$path])) $out['zip_only']++;
    }
    return $out;
}

function run_self_test(string $intelDir, int $slowRuleThresholdMs): int {
    global $state, $quiet, $slowRuleMs, $slowFileMs, $scanRuntime, $apply,
           $interactive, $nonInteractive, $quarantineDir, $quarantineMalwareAuto,
           $handledInteractivePaths;

    $quiet = false;
    $slowRuleMs = $slowRuleThresholdMs;
    $slowFileMs = 1000;
    $apply = false;
    $interactive = false;
    $nonInteractive = true;
    $quarantineDir = null;
    $quarantineMalwareAuto = false;
    $handledInteractivePaths = [];
    $scanRuntime = ['pcre_error_paths' => [], 'generic_rule_paths' => []];
    $state = [
        'findings' => [],
        'actions' => [],
        'timing' => ['pcre_errors'=>0,'slow_rules'=>0,'slow_files'=>0,'slowest_rule'=>null,'slowest_file'=>null],
        'summary' => ['findings_total'=>0,'critical'=>0,'high'=>0,'medium'=>0,'low'=>0,'info'=>0,'actions_taken'=>0],
    ];

    $failures = [];
    $passes = [];
    $warnings = [];
    $require = static function (bool $ok, string $label) use (&$failures, &$passes): void {
        if ($ok) $passes[] = $label; else $failures[] = $label;
    };

    $require(version_compare(PHP_VERSION, '7.4.0', '>='), 'PHP >= 7.4');
    foreach (['json', 'pcre', 'tokenizer', 'hash'] as $extension) {
        $require(extension_loaded($extension), "PHP extension: $extension");
    }
    if (class_exists('ZipArchive')) {
        $passes[] = 'PHP ZIP support';
    } else {
        $warnings[] = 'PHP ZIP support unavailable; scanning works, but ZIP-based repair/package verification is unavailable';
    }

    // Source checkouts keep the bundled intelligence in ../intel, while
    // installed hosts conventionally expose it as ../wp-warden-intel.
    if (!is_dir(rtrim($intelDir, '/') . '/patterns')) {
        $checkoutIntel = normalize_path(__DIR__ . '/../intel');
        if (is_dir($checkoutIntel . '/patterns')) {
            $intelDir = $checkoutIntel;
        }
    }

    $jsonFiles = glob(rtrim($intelDir, '/') . '/patterns/*.json') ?: [];
    $require(count($jsonFiles) > 0, 'intel pattern JSON files found');
    foreach ($jsonFiles as $jsonPath) {
        $raw = @file_get_contents($jsonPath);
        if (is_string($raw)) {
            $raw = preg_replace('/^\xEF\xBB\xBF/', '', $raw);
        }
        $decoded = is_string($raw) ? json_decode($raw, true) : null;
        $require(is_array($decoded), 'intel JSON parses: ' . basename($jsonPath));
    }

    $compiled = 0;
    $invalid = 0;
    foreach (['php-malware-rules.json', 'community-malware-rules.json'] as $name) {
        $raw = @file_get_contents(rtrim($intelDir, '/') . '/patterns/' . $name);
        if (is_string($raw)) {
            $raw = preg_replace('/^\xEF\xBB\xBF/', '', $raw);
        }
        $decoded = is_string($raw) ? json_decode($raw, true) : null;
        foreach (($decoded['rules'] ?? []) as $rule) {
            if (!is_array($rule) || !rule_enabled($rule)) continue;
            $prepared = prepare_php_pattern_rule($rule);
            if ($prepared === null) $invalid++; else $compiled++;
        }
    }
    $require($compiled > 0 && $invalid === 0, "enabled malware regexes compile ($compiled checked)");

    $controlled = '~\beval\s*\(\s*base64_decode\s*\(~i';
    $dummy = null;
    $require(warden_preg_match($controlled, '<?php echo "hello";', $dummy, 0, 0, ['rule_id'=>'SELFTEST_CONTROLLED','path'=>'clean-fixture.php']) === 0,
        'known clean fixture does not trigger controlled malware rule');
    $require(warden_preg_match($controlled, '<?php eval(base64_decode($x));', $dummy, 0, 0, ['rule_id'=>'SELFTEST_CONTROLLED','path'=>'malicious-fixture.php']) === 1,
        'known malicious fixture triggers controlled malware rule');
    $require(!is_backup_component_directory('backup-backup'),
        'legitimate backup-backup plugin slug is not treated as an old backup');
    foreach ([
        'cache-optimizer-394f' => 'BUILTIN_RANDOMIZED_CACHE_OPTIMIZER_PLUGIN_DIR_001',
        'site-health-cc95459ffe03' => 'BUILTIN_RANDOMIZED_SITE_HEALTH_PLUGIN_DIR_001',
        'wp2s_up_88835050' => 'BUILTIN_WP2S_UP_PLUGIN_DIR_001',
        'smtpxf609c584' => 'BUILTIN_RANDOMIZED_SMTPX_PLUGIN_DIR_001',
    ] as $slug => $expectedRuleId) {
        $ioc = malicious_plugin_slug_ioc($slug);
        $require(($ioc['rule_id'] ?? null) === $expectedRuleId,
            "randomized plugin IOC detected: $slug");
    }
    $comparison = compare_checksum_maps(
        ['same.php'=>['sha256'=>str_repeat('a', 64)], 'api-only.pot'=>['md5'=>str_repeat('b', 32)], 'different.php'=>['md5'=>str_repeat('c', 32)]],
        ['same.php'=>['sha256'=>str_repeat('a', 64)], 'zip-only.txt'=>['md5'=>str_repeat('d', 32)], 'different.php'=>['md5'=>str_repeat('e', 32)]]
    );
    $require($comparison === ['different'=>1, 'api_only'=>1, 'zip_only'=>1],
        'checksum-source comparison distinguishes changed and source-only files');
    $require(component_checksum_mismatch_severity('languages/example.pot') === 'low'
        && component_checksum_mismatch_severity('includes/loader.php') === 'high'
        && component_checksum_mismatch_severity('assets/app.js') === 'high',
        'generated text mismatches are downgraded while PHP/JS remain significant');
    $pluginPackage = repair_package_info('plugin', 'example-plugin', '1.2.3');
    $themePackage = repair_package_info('theme', 'example-theme', '4.5.6');
    $require(($pluginPackage['type'] ?? null) === 'plugin' && ($themePackage['type'] ?? null) === 'theme',
        'external repair packages retain their source type for no-mix safety');
    $require(!in_array('BUILTIN_EVAL_VARIABLE_001', trusted_builtin_auto_quarantine_rule_ids(), true),
        'generic eval-variable heuristic remains report-only');
    $provenance = normalize_clean_zip_intel([
        'path'=>'/approved/package.zip', 'sha256'=>str_repeat('a', 64),
        'source'=>'vendor-release', 'source_url'=>'https://vendor.invalid/package.zip',
        'acquired_at'=>'2026-09-02T00:00:00Z',
    ]);
    $require(($provenance['source'] ?? null) === 'vendor-release'
        && ($provenance['source_url'] ?? null) === 'https://vendor.invalid/package.zip',
        'clean ZIP provenance metadata survives normalization');

    $tmpRoot = rtrim(normalize_path(sys_get_temp_dir()), '/') . '/wp-warden-self-test-' . getmypid() . '-' . bin2hex(random_bytes(4));
    $l10nDir = $tmpRoot . '/wp-content/languages/plugins';
    $cacheDir = $tmpRoot . '/cache';
    $require(@mkdir($l10nDir, 0700, true) || is_dir($l10nDir), 'self-test temporary directory');
    $l10nPath = $l10nDir . '/fixture.l10n.php';
    $fixture = "<?php\nreturn ['messages'=>['literal'=>'eval(base64_decode(example))']];\n";
    $require(@file_put_contents($l10nPath, $fixture) === strlen($fixture), 'generated .l10n.php fixture created');
    $beforeFindings = count($state['findings']);
    $l10nStarted = microtime(true);
    scan_text_rules($l10nPath, 'wp-content/languages/plugins/fixture.l10n.php', ['sha256'=>hash('sha256', $fixture)], []);
    $l10nMs = (microtime(true) - $l10nStarted) * 1000;
    $require($l10nMs < 1000, 'generated .l10n.php fixture completes quickly');
    $require(empty($scanRuntime['generic_rule_paths']['wp-content/languages/plugins/fixture.l10n.php']),
        'generated .l10n.php bypasses generic PCRE rules');
    $require(count($state['findings']) === $beforeFindings, 'generated .l10n.php string literals are not malware findings');

    $require(@mkdir($cacheDir, 0700, true) || is_dir($cacheDir), 'cache directory can be created');
    $cacheProbe = $cacheDir . '/probe';
    $require(@file_put_contents($cacheProbe, 'ok') === 2 && @file_get_contents($cacheProbe) === 'ok', 'cache directory read/write');

    $zipProbePath = $tmpRoot . '/alternate-root.zip';
    if (class_exists('ZipArchive')) {
        $zipProbe = new ZipArchive();
        $zipCreated = $zipProbe->open($zipProbePath, ZipArchive::CREATE | ZipArchive::OVERWRITE) === true;
        if ($zipCreated) {
            $zipCreated = $zipProbe->addFromString('vendor-archive-root/includes/example.php', 'trusted-package-bytes');
            $zipProbe->close();
        }
        $resolved = null;
        $rejected = null;
        $zipProbe = new ZipArchive();
        if ($zipCreated && $zipProbe->open($zipProbePath) === true) {
            $resolved = resolve_component_zip_entry_by_checksum(
                $zipProbe,
                'wp-content/plugins/installed-slug/includes/example.php',
                ['sha256' => hash('sha256', 'trusted-package-bytes')]
            );
            $rejected = resolve_component_zip_entry_by_checksum(
                $zipProbe,
                'wp-content/plugins/installed-slug/includes/example.php',
                ['sha256' => hash('sha256', 'different-bytes')]
            );
            $zipProbe->close();
        }
        $require(($resolved['path'] ?? null) === 'vendor-archive-root/includes/example.php'
            && ($resolved['data'] ?? null) === 'trusted-package-bytes',
            'component repair resolves an alternate ZIP root by trusted checksum');
        $require($rejected === null,
            'component repair rejects alternate-root ZIP bytes with the wrong checksum');
    }

    if (is_file($cacheProbe)) @unlink($cacheProbe);
    if (is_file($l10nPath)) @unlink($l10nPath);
    if (is_file($zipProbePath)) @unlink($zipProbePath);
    if (is_dir($cacheDir)) @rmdir($cacheDir);
    if (is_dir($l10nDir)) @rmdir($l10nDir);
    if (is_dir(dirname($l10nDir))) @rmdir(dirname($l10nDir));
    if (is_dir(dirname(dirname($l10nDir)))) @rmdir(dirname(dirname($l10nDir)));
    if (is_dir($tmpRoot)) @rmdir($tmpRoot);

    foreach ($passes as $pass) echo "[SELF-TEST PASS] $pass" . PHP_EOL;
    foreach ($warnings as $warning) echo "[SELF-TEST WARN] $warning" . PHP_EOL;
    foreach ($failures as $failure) echo "[SELF-TEST FAIL] $failure" . PHP_EOL;
    echo 'Self-test: ' . ($failures ? 'FAILED' : 'PASSED') . ' (' . count($passes) . ' passed, ' . count($warnings) . ' warning(s), ' . count($failures) . ' failed)' . PHP_EOL;
    return $failures ? 1 : 0;
}

function file_metadata_equal(?array $left, ?array $right): bool {
    if ($left === null || $right === null) {
        return false;
    }
    foreach (['dev', 'ino', 'size', 'mtime', 'ctime'] as $key) {
        if ((string)($left[$key] ?? '') !== (string)($right[$key] ?? '')) {
            return false;
        }
    }
    return true;
}

function file_cache_forget(string $rel): void {
    global $fileCacheEntries, $fileCacheSeen, $fileCacheDirty;
    $rel = normalize_relative($rel);
    $fileCacheSeen[$rel] = true;
    if (isset($fileCacheEntries[$rel])) {
        unset($fileCacheEntries[$rel]);
        $fileCacheDirty = true;
    }
}

function file_cache_mark_clean(string $path, string $rel): void {
    global $fileCacheEntries, $fileCacheSeen, $fileCacheDirty, $fileCacheContext;

    $st = file_cache_stat($path);
    if ($st === null) {
        return;
    }

    $rel = normalize_relative($rel);
    $fileCacheSeen[$rel] = true;
    $fileCacheEntries[$rel] = $st + [
        'status' => 'clean',
        'scan_signature' => file_cache_signature_for_path($rel, $fileCacheContext),
        'checked_at' => gmdate('c'),
    ];
    $fileCacheDirty = true;
}

function save_file_cache(): void {
    global $fileCacheEnabled, $fileCacheDir, $fileCachePath, $fileCacheSignature,
           $fileCacheEntries, $fileCacheSeen, $fileCacheDirty, $wpRoot, $state;

    if (!$fileCacheEnabled || !$fileCachePath || !$fileCacheSignature) {
        return;
    }

    // Prune files no longer encountered during this walk.
    foreach (array_keys($fileCacheEntries) as $rel) {
        if (!isset($fileCacheSeen[$rel])) {
            unset($fileCacheEntries[$rel]);
            $fileCacheDirty = true;
        }
    }

    $state['summary']['cache_entries'] = count($fileCacheEntries);

    if (!$fileCacheDirty && is_file($fileCachePath)) {
        return;
    }

    if (!is_dir($fileCacheDir) && !@mkdir($fileCacheDir, 0700, true) && !is_dir($fileCacheDir)) {
        say("WARN: could not create file cache directory: $fileCacheDir", true);
        return;
    }

    $payload = [
        'schema' => 'wp-warden.file-cache.v1',
        'scanner_version' => WP_WARDEN_VERSION,
        'cache_version' => WP_WARDEN_CACHE_VERSION,
        'signature_mode' => 'per-file-v1',
        'signature' => $fileCacheSignature,
        'target' => normalize_path(realpath($wpRoot) ?: $wpRoot),
        'updated_at' => gmdate('c'),
        'entries' => $fileCacheEntries,
    ];

    $tmp = $fileCachePath . '.tmp.' . getmypid();
    $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (!is_string($json) || @file_put_contents($tmp, $json, LOCK_EX) === false) {
        @unlink($tmp);
        say("WARN: could not write file cache: $fileCachePath", true);
        return;
    }

    @chmod($tmp, 0600);
    if (!@rename($tmp, $fileCachePath)) {
        @unlink($tmp);
        say("WARN: could not install file cache: $fileCachePath", true);
        return;
    }

    $fileCacheDirty = false;
}

function wp_root_owner_account(string $root): ?string {
    // CWP has a stable /home/account/... layout. Prefer it because an infected
    // or manually restored wp-config.php can temporarily have the wrong owner.
    if (warden_preg_match('#^/home/([^/]+)/#', normalize_path($root) . '/', $match) === 1
        && warden_preg_match('/^[A-Za-z0-9._-]+$/', $match[1]) === 1
        && $match[1] !== 'virtual') {
        return $match[1];
    }

    // ApisCP and custom layouts are resolved from filesystem ownership.
    $ownerId = @fileowner($root . '/wp-config.php');
    if ($ownerId === false) {
        $ownerId = @fileowner($root);
    }
    if ($ownerId !== false && function_exists('posix_getpwuid')) {
        $record = @posix_getpwuid((int)$ownerId);
        $name = is_array($record) ? (string)($record['name'] ?? '') : '';
        if (warden_preg_match('/^[A-Za-z0-9._-]+$/', $name) === 1) {
            return $name;
        }
    }

    return null;
}

function pcre_error_category(int $code): string {
    $map = [
        PREG_BACKTRACK_LIMIT_ERROR => 'BACKTRACK_LIMIT',
        PREG_RECURSION_LIMIT_ERROR => 'RECURSION_LIMIT',
        PREG_BAD_UTF8_ERROR => 'BAD_UTF8',
        PREG_BAD_UTF8_OFFSET_ERROR => 'BAD_UTF8_OFFSET',
        PREG_INTERNAL_ERROR => 'INTERNAL',
    ];
    if (defined('PREG_JIT_STACKLIMIT_ERROR')) {
        $map[PREG_JIT_STACKLIMIT_ERROR] = 'JIT_STACK_LIMIT';
    }
    return $map[$code] ?? 'OTHER';
}

function pcre_error_message(int $code): string {
    if (function_exists('preg_last_error_msg')) {
        return preg_last_error_msg();
    }
    return pcre_error_category($code);
}

function record_regex_timing(float $elapsedMs, array $context): void {
    global $state, $slowRuleMs;
    $ruleId = (string)($context['rule_id'] ?? '');
    if ($ruleId === '' || !isset($state['timing'])) {
        return;
    }
    $path = (string)($context['path'] ?? '(no path)');
    $slowest = $state['timing']['slowest_rule'] ?? null;
    if (!is_array($slowest) || $elapsedMs > (float)($slowest['milliseconds'] ?? -1)) {
        $state['timing']['slowest_rule'] = [
            'milliseconds' => round($elapsedMs, 3),
            'rule_id' => $ruleId,
            'path' => $path,
        ];
    }
    if ($slowRuleMs > 0 && $elapsedMs >= $slowRuleMs) {
        $state['timing']['slow_rules'] = (int)($state['timing']['slow_rules'] ?? 0) + 1;
        say(sprintf('[SLOW-RULE] %dms %s %s', (int)round($elapsedMs), $ruleId, $path), true);
    }
}

function record_slow_stage(float $elapsedMs, string $stage, string $path): void {
    global $slowFileMs;
    if ($slowFileMs > 0 && $elapsedMs >= $slowFileMs) {
        say(sprintf('[SLOW-STAGE] %.2fs %s %s', $elapsedMs / 1000, $stage, $path), true);
    }
}

function record_file_timing(float $elapsedMs, string $path): void {
    global $state, $slowFileMs;
    $slowest = $state['timing']['slowest_file'] ?? null;
    if (!is_array($slowest) || $elapsedMs > (float)($slowest['milliseconds'] ?? -1)) {
        $state['timing']['slowest_file'] = [
            'milliseconds' => round($elapsedMs, 3),
            'path' => $path,
        ];
    }
    if ($slowFileMs > 0 && $elapsedMs >= $slowFileMs) {
        $state['timing']['slow_files'] = (int)($state['timing']['slow_files'] ?? 0) + 1;
        say(sprintf('[SLOW-FILE] %.2fs %s', $elapsedMs / 1000, $path), true);
    }
}

function record_pcre_error(int $code, ?string $warning, array $context): void {
    global $state, $scanRuntime;
    $category = pcre_error_category($code);
    $message = $warning ?: pcre_error_message($code);
    $ruleId = (string)($context['rule_id'] ?? '(unlabelled regex)');
    $path = (string)($context['path'] ?? '(no path)');
    if (isset($state['timing'])) {
        $state['timing']['pcre_errors'] = (int)($state['timing']['pcre_errors'] ?? 0) + 1;
    }
    if ($path === '(intel compile)' || $path === '(no path)') {
        $scanRuntime['global_pcre_error'] = true;
    } else {
        $scanRuntime['pcre_error_paths'][normalize_relative($path)] = true;
    }
    say("[PCRE-ERROR] $category $ruleId $path: $message", true);
}

function warden_preg_match(string $pattern, string $subject, ?array &$matches = null, int $flags = 0, int $offset = 0, array $context = []) {
    $started = microtime(true);
    // Avoid installing an error handler for every rule. Two monotonic clock
    // reads are the only timing overhead on the hot path; PCRE provides the
    // diagnostic through preg_last_error()/preg_last_error_msg() on failure.
    $result = @preg_match($pattern, $subject, $matches, $flags, $offset);
    $elapsedMs = (microtime(true) - $started) * 1000;
    record_regex_timing($elapsedMs, $context);
    if ($result === false) {
        record_pcre_error(preg_last_error(), null, $context);
    }
    return $result;
}

function warden_preg_match_all(string $pattern, string $subject, ?array &$matches = null, int $flags = PREG_PATTERN_ORDER, int $offset = 0, array $context = []) {
    $started = microtime(true);
    $result = @preg_match_all($pattern, $subject, $matches, $flags, $offset);
    $elapsedMs = (microtime(true) - $started) * 1000;
    record_regex_timing($elapsedMs, $context);
    if ($result === false) {
        record_pcre_error(preg_last_error(), null, $context);
    }
    return $result;
}

function malicious_php_recreation_cron(string $line, string $root): ?array {
    $pattern = '#\[\s+-f\s+[' . "'\"" . ']?([^\]\s' . "'\"" . ']+\.php)[' . "'\"" . ']?\s*\]\s*\|\|\s*echo\s+[' . "'\"" . ']?([A-Za-z0-9+/=]{80,})[' . "'\"" . ']?\s*\|\s*(?:/[A-Za-z0-9._/-]+/)?base64\s+(?:-d|--decode)\s*>\s*[' . "'\"" . ']?([^\s;&|' . "'\"" . ']+\.php)#i';
    if (warden_preg_match($pattern, $line, $match) !== 1) {
        return null;
    }

    $checkedPath = normalize_path($match[1]);
    $outputPath = normalize_path($match[3]);
    $rootPrefix = rtrim(normalize_path($root), '/') . '/';
    if ($checkedPath !== $outputPath || strpos($outputPath, $rootPrefix) !== 0) {
        return null;
    }

    return [
        'path' => $outputPath,
        'payload_sha256' => hash('sha256', $match[2]),
    ];
}

function audit_system_cron_persistence(string $root): void {
    global $state, $apply, $quarantineDir, $cleanupMalwareCronAuto;

    $account = wp_root_owner_account($root);
    if ($account === null || !command_exists('crontab')) {
        return;
    }

    // A CWP account can host its primary site in public_html plus add-on domains
    // in sibling directories. Audit confirmed PHP-recreation jobs across that
    // account's home tree; retain site-root scope for ApisCP/custom layouts.
    $cronScopeRoot = $root;
    if (warden_preg_match('#^/home/' . preg_quote($account, '#') . '/#', normalize_path($root) . '/') === 1) {
        $cronScopeRoot = '/home/' . $account;
    }

    $lines = [];
    $exitCode = 0;
    @exec('crontab -u ' . escapeshellarg($account) . ' -l 2>/dev/null', $lines, $exitCode);
    if ($exitCode !== 0 || $lines === []) {
        return;
    }

    $maliciousIndexes = [];
    foreach ($lines as $index => $line) {
        $ioc = malicious_php_recreation_cron($line, $cronScopeRoot);
        if ($ioc === null) {
            continue;
        }

        $record = [
            'account' => $account,
            'line_number' => $index + 1,
            'command' => $line,
            'target_path' => $ioc['path'],
            'payload_sha256' => $ioc['payload_sha256'],
        ];
        $state['db_audit']['system_cron_iocs'][] = $record;
        $maliciousIndexes[$index] = true;
        add_finding([
            'type' => 'system_cron_persistence',
            'severity' => 'critical',
            'confidence' => 'high',
            'rule_id' => 'SYSTEM_CRON_BASE64_PHP_RECREATE_001',
            'path' => $ioc['path'],
            'relative_path' => "system-cron:{$account}:line-" . ($index + 1),
            'reason' => 'System cron recreates a PHP file from an embedded Base64 payload whenever the file is missing.',
            'cron' => $record,
            'file_action' => false,
            'recommended_action' => 'Remove this exact cron entry and quarantine the recreated PHP file.',
        ]);
    }

    if ($maliciousIndexes === [] || !$cleanupMalwareCronAuto || !$apply || !$quarantineDir) {
        return;
    }

    $backupDir = rtrim(normalize_path($quarantineDir), '/') . '/cron-persistence-' . gmdate('Ymd-His');
    if (!is_dir($backupDir) && !@mkdir($backupDir, 0700, true) && !is_dir($backupDir)) {
        say("WARN: could not create cron backup directory: $backupDir; crontab was not changed", true);
        return;
    }
    $backupPath = $backupDir . '/' . $account . '.crontab';
    $original = implode(PHP_EOL, $lines) . PHP_EOL;
    if (@file_put_contents($backupPath, $original) === false) {
        say("WARN: could not back up the {$account} crontab; crontab was not changed", true);
        return;
    }
    @chmod($backupPath, 0600);

    $kept = [];
    foreach ($lines as $index => $line) {
        if (!isset($maliciousIndexes[$index])) {
            $kept[] = $line;
        }
    }
    $tempPath = @tempnam(sys_get_temp_dir(), 'wpw-cron-');
    if (!is_string($tempPath) || @file_put_contents($tempPath, $kept === [] ? '' : implode(PHP_EOL, $kept) . PHP_EOL) === false) {
        say("WARN: could not prepare cleaned crontab; crontab was not changed", true);
        return;
    }
    @chmod($tempPath, 0600);
    $installOutput = [];
    $installCode = 0;
    @exec('crontab -u ' . escapeshellarg($account) . ' ' . escapeshellarg($tempPath) . ' 2>&1', $installOutput, $installCode);
    @unlink($tempPath);
    if ($installCode !== 0) {
        say("WARN: failed to install cleaned {$account} crontab; backup: $backupPath", true);
        return;
    }

    $removed = count($maliciousIndexes);
    $state['actions'][] = [
        'type' => 'remove_system_cron_persistence',
        'relative_path' => "system-cron:$account",
        'account' => $account,
        'removed_entries' => $removed,
        'backup' => $backupPath,
        'at' => gmdate('c'),
    ];
    $state['summary']['actions_taken'] += $removed;
    say("[CLEANED] Removed {$removed} confirmed malicious cron job(s) for {$account}; backup: $backupPath", true);
}

function audit_wp_config_persistence(string $root): void {
    global $state, $apply, $quarantineDir, $cleanupDatabasePersistenceAuto;

    $config = rtrim(normalize_path($root), '/') . '/wp-config.php';
    $data = @file_get_contents($config);
    if (!is_string($data) || $data === '') {
        return;
    }

    $blockPattern = '#/\*\s*WP_Core_Integrity\s+([a-f0-9]{6,64})\s*\*/[\s\S]*?/\*\s*End-WP_Core_Integrity\s+\1\s*\*/#i';
    if (!warden_preg_match_all($blockPattern, $data, $matches) || empty($matches[0])) {
        return;
    }

    $confirmedBlocks = [];
    $tmpPaths = [];
    foreach ($matches[0] as $block) {
        if (stripos($block, 'new PDO') === false
            || stripos($block, 'DB_HOST') === false
            || stripos($block, 'base64_decode') === false
            || stripos($block, 'file_put_contents') === false
            || !warden_preg_match('/_site_transient_health_[a-f0-9]{6,64}/i', $block, $optionMatch)) {
            continue;
        }

        $tmpPath = null;
        if (warden_preg_match("#file_put_contents\\s*\\(\\s*['\"](/tmp/php[a-zA-Z0-9._-]+)['\"]#i", $block, $tmpMatch)) {
            $tmpPath = normalize_path($tmpMatch[1]);
            $tmpPaths[] = $tmpPath;
        }
        $confirmedBlocks[] = $block;
        $finding = [
            'severity' => 'critical',
            'type' => 'wp_config_persistence_loader',
            'rule_id' => 'BUILTIN_WP_CONFIG_DB_TMP_LOADER_001',
            'path' => $config,
            'relative_path' => 'wp-config.php',
            'reason' => 'wp-config.php contains a disguised loader that decodes a database option into a /tmp PHP payload.',
            'file_action' => false,
            'persistence' => [
                'option_name' => $optionMatch[0],
                'tmp_path' => $tmpPath,
            ],
            'recommended_action' => 'Back up and remove the injected block, delete the matching database option, and quarantine the dropped /tmp payload.',
        ];
        $state['db_audit']['config_iocs'][] = $finding['persistence'];
        add_finding($finding, false);
    }

    if (!$confirmedBlocks || !$cleanupDatabasePersistenceAuto) {
        return;
    }
    if (!$apply || !$quarantineDir) {
        say('WARN: --cleanup-database-persistence-auto requires --apply and --quarantine=DIR; wp-config.php was not changed.', true);
        return;
    }

    $qRoot = rtrim(normalize_path($quarantineDir), '/') . '/database-persistence-' . gmdate('Ymd-His');
    if (!is_dir($qRoot) && !@mkdir($qRoot, 0700, true) && !is_dir($qRoot)) {
        say("WARN: could not create persistence quarantine directory: $qRoot", true);
        return;
    }
    $backup = $qRoot . '/wp-config.php.infected';
    if (!@copy($config, $backup)) {
        say("WARN: could not back up wp-config.php; persistence cleanup aborted", true);
        return;
    }
    @chmod($backup, 0600);

    $clean = str_replace($confirmedBlocks, '', $data);
    $tmpConfig = $config . '.wp-warden-clean-' . getmypid();
    $mode = @fileperms($config);
    $owner = @fileowner($config);
    $group = @filegroup($config);
    if (@file_put_contents($tmpConfig, $clean, LOCK_EX) === false) {
        @unlink($tmpConfig);
        say("WARN: could not write cleaned wp-config.php; original preserved", true);
        return;
    }
    if (is_int($mode)) {
        @chmod($tmpConfig, $mode & 0777);
    }
    if (is_int($owner)) {
        @chown($tmpConfig, $owner);
    }
    if (is_int($group)) {
        @chgrp($tmpConfig, $group);
    }
    if (!@rename($tmpConfig, $config)) {
        @unlink($tmpConfig);
        say("WARN: could not install cleaned wp-config.php; original preserved", true);
        return;
    }

    foreach (array_unique($tmpPaths) as $tmpPayload) {
        $real = realpath($tmpPayload);
        if ($real === false || dirname(normalize_path($real)) !== '/tmp' || !warden_preg_match('/^php[a-zA-Z0-9._-]+$/', basename($real))) {
            continue;
        }
        $dest = $qRoot . '/' . basename($real) . '.payload';
        if (@rename($real, $dest)) {
            @chmod($dest, 0600);
        }
    }

    $state['actions'][] = [
        'type' => 'cleanup_wp_config_persistence',
        'path' => $config,
        'backup' => $backup,
        'blocks_removed' => count($confirmedBlocks),
    ];
    $state['summary']['actions_taken']++;
    say("[CLEANED] Removed confirmed database-to-/tmp persistence loader from wp-config.php; backup: $backup", true);
}

function audit_wp_content_directories(string $root): void {
    global $allowedWpContentDirsOverride, $quarantineWpContentAuto, $apply, $quarantineDir, $state;

    $wpContent = rtrim(normalize_path($root), '/') . '/wp-content';
    if (!is_dir($wpContent)) {
        return;
    }

    // Standard WordPress directories plus common, well-known runtime/backup
    // directories. Site-specific legitimate directories can be supplied with
    // --allow-wp-content-dir=a,b,c.
    $allowed = [
        'plugins',
        'themes',
        'uploads',
        'mu-plugins',
        'languages',
        'upgrade',
        'upgrade-temp-backup',
        'cache',
        'wflogs',
        'litespeed',
        'et-cache',
        'elementor',
        'updraft',
        'ai1wm-backups',
        'wpvividbackups',
    ];

    foreach ($allowedWpContentDirsOverride as $name) {
        $name = strtolower(trim((string)$name));
        if ($name !== '' && strpos($name, '/') === false && strpos($name, '\\') === false) {
            $allowed[] = $name;
        }
    }
    $allowed = array_fill_keys(array_unique(array_map('strtolower', $allowed)), true);

    $entries = @scandir($wpContent);
    if (!is_array($entries)) {
        return;
    }

    foreach ($entries as $name) {
        if ($name === '.' || $name === '..') {
            continue;
        }

        $path = $wpContent . '/' . $name;
        if (!is_dir($path) || is_link($path)) {
            continue;
        }

        if (isset($allowed[strtolower($name)])) {
            continue;
        }

        $randomLike = looks_random_wp_content_dir($name);
        $signals = inspect_unexpected_wp_content_dir($path);

        $severity = $randomLike ? 'high' : 'medium';
        if ($signals['php_files'] > 0 || $signals['script_files'] > 0) {
            $severity = 'critical';
        } elseif ($randomLike && $signals['encoded_extensionless_files'] > 0) {
            $severity = 'critical';
        } elseif ($signals['extensionless_files'] > 0 && $randomLike) {
            $severity = 'high';
        }

        $reason = 'Unexpected top-level directory under wp-content.';
        if ($randomLike) {
            $reason .= ' Directory name is random-looking.';
        }
        if ($signals['php_files'] > 0) {
            $reason .= ' Contains ' . $signals['php_files'] . ' PHP-like file(s).';
        }
        if ($signals['script_files'] > 0) {
            $reason .= ' Contains ' . $signals['script_files'] . ' executable/script file(s).';
        }
        if ($signals['extensionless_files'] > 0) {
            $reason .= ' Contains ' . $signals['extensionless_files'] . ' extensionless file(s).';
        }
        if ($signals['encoded_extensionless_files'] > 0) {
            $reason .= ' Contains ' . $signals['encoded_extensionless_files'] . ' extensionless file(s) dominated by a long Base64-like/encoded payload.';
        }

        $dirAction = null;
        if ($quarantineWpContentAuto && $apply && $quarantineDir && in_array($severity, ['high', 'critical'], true)) {
            $dirAction = quarantine_unexpected_wp_content_directory($path, $root, $quarantineDir);
            if (is_array($dirAction) && !empty($dirAction['success'])) {
                $state['summary']['actions']++;
                say("[action] quarantined suspicious wp-content directory: " . $path . " -> " . $dirAction['destination'], true);
            } elseif (is_array($dirAction)) {
                say("WARN: could not quarantine suspicious wp-content directory: " . $path . " (" . ($dirAction['error'] ?? 'unknown error') . ")", true);
            }
        }

        add_finding([
            'severity' => $severity,
            'type' => 'unexpected_wp_content_directory',
            'rule_id' => $randomLike
                ? 'BUILTIN_WP_CONTENT_RANDOM_DIR_001'
                : 'BUILTIN_WP_CONTENT_UNKNOWN_DIR_001',
            'path' => $path,
            'relative_path' => 'wp-content/' . $name . '/',
            'reason' => $reason,
            'file_action' => false,
            'directory' => [
                'name' => $name,
                'random_like' => $randomLike,
                'files_sampled' => $signals['files_sampled'],
                'php_files' => $signals['php_files'],
                'script_files' => $signals['script_files'],
                'extensionless_files' => $signals['extensionless_files'],
                'encoded_extensionless_files' => $signals['encoded_extensionless_files'],
                'encoded_extensionless_samples' => $signals['encoded_extensionless_samples'],
            ],
            'recommended_action' => 'Review this directory. If legitimate, add it with --allow-wp-content-dir; otherwise inspect its contents and remove/quarantine as appropriate.',
            'directory_action' => $dirAction,
        ], false);
    }
}

function audit_malicious_plugin_directories(string $root): void {
    $pluginsDir = rtrim(normalize_path($root), '/') . '/wp-content/plugins';
    if (!is_dir($pluginsDir)) {
        return;
    }

    $entries = @scandir($pluginsDir);
    if (!is_array($entries)) {
        return;
    }

    foreach ($entries as $slug) {
        if ($slug === '.' || $slug === '..') {
            continue;
        }

        $pluginDir = $pluginsDir . '/' . $slug;
        if (!is_dir($pluginDir) || is_link($pluginDir)) {
            continue;
        }

        $ioc = malicious_plugin_slug_ioc($slug);
        if ($ioc === null && randomized_protect_uploads_plugin_ioc($pluginDir, $slug)) {
            $ioc = [
                'rule_id' => 'BUILTIN_RANDOMIZED_PROTECT_UPLOADS_PLUGIN_001',
                'family' => 'randomized Protect Uploads malware carrier',
            ];
        }
        if ($ioc === null) {
            continue;
        }
        $ruleId = $ioc['rule_id'];
        $family = $ioc['family'];

        $sampleFile = first_regular_file_in_directory($pluginDir);
        if ($sampleFile === null) {
            add_finding([
                'severity' => 'critical',
                'type' => 'malicious_plugin_directory',
                'rule_id' => $ruleId,
                'path' => $pluginDir,
                'relative_path' => 'wp-content/plugins/' . $slug . '/',
                'reason' => "Plugin directory name matches the known {$family} malware family.",
                'file_action' => false,
                'recommended_action' => 'Quarantine the entire plugin directory and investigate the site for persistence and credential compromise.',
            ], false);
            continue;
        }

        $relativeFile = 'wp-content/plugins/' . $slug . '/' . ltrim(substr(normalize_path($sampleFile), strlen(normalize_path($pluginDir))), '/');
        add_finding([
            'severity' => 'critical',
            'type' => 'malicious_plugin_directory',
            'rule_id' => $ruleId,
            'path' => $sampleFile,
            'relative_path' => $relativeFile,
            'reason' => "Plugin directory name matches the known {$family} malware family.",
            'hashes' => file_hashes($sampleFile) ?? [],
            'recommended_action' => 'Quarantine the entire plugin directory and investigate the site for persistence and credential compromise.',
        ], true);
    }
}

function malicious_plugin_slug_ioc(string $slug): ?array {
    if (warden_preg_match('/^wp2shell-[a-f0-9]{6,64}$/i', $slug) === 1) {
        return [
            'rule_id' => 'BUILTIN_WP2SHELL_PLUGIN_DIR_001',
            'family' => 'WP2Shell',
        ];
    }
    if (warden_preg_match('/^galex_[a-f0-9]{6,64}$/i', $slug) === 1) {
        return [
            'rule_id' => 'BUILTIN_GALEX_WEBSHELL_PLUGIN_DIR_001',
            'family' => 'Galex command-webshell',
        ];
    }
    if (warden_preg_match('/^cache-optimizer-[a-f0-9]{4,32}$/i', $slug) === 1) {
        return [
            'rule_id' => 'BUILTIN_RANDOMIZED_CACHE_OPTIMIZER_PLUGIN_DIR_001',
            'family' => 'randomized cache-optimizer persistence',
        ];
    }
    if (warden_preg_match('/^site-health-[a-f0-9]{8,32}$/i', $slug) === 1) {
        return [
            'rule_id' => 'BUILTIN_RANDOMIZED_SITE_HEALTH_PLUGIN_DIR_001',
            'family' => 'randomized site-health persistence',
        ];
    }
    if (warden_preg_match('/^wp2s_up_[a-f0-9]{6,32}$/i', $slug) === 1) {
        return [
            'rule_id' => 'BUILTIN_WP2S_UP_PLUGIN_DIR_001',
            'family' => 'WP2Shell updater persistence',
        ];
    }
    if (warden_preg_match('/^smtpx[a-f0-9]{8,32}$/i', $slug) === 1) {
        return [
            'rule_id' => 'BUILTIN_RANDOMIZED_SMTPX_PLUGIN_DIR_001',
            'family' => 'randomized SMTPX malware loader',
        ];
    }

    return null;
}

function first_regular_file_in_directory(string $dir): ?string {
    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        foreach ($it as $file) {
            if ($file->isFile() && !$file->isLink()) {
                return normalize_path($file->getPathname());
            }
        }
    } catch (UnexpectedValueException $e) {
        return null;
    }

    return null;
}

function quarantine_unexpected_wp_content_directory(string $dir, string $root, string $quarantineRoot): array {
    $realDir = realpath($dir);
    $realRoot = realpath($root);
    if ($realDir === false || $realRoot === false || !is_dir($realDir)) {
        return ['success' => false, 'error' => 'directory does not exist'];
    }

    $realDir = rtrim(normalize_path($realDir), '/');
    $realRoot = rtrim(normalize_path($realRoot), '/');
    $expectedPrefix = $realRoot . '/wp-content/';
    if (strpos($realDir . '/', $expectedPrefix) !== 0 || dirname($realDir) !== $realRoot . '/wp-content') {
        return ['success' => false, 'error' => 'refusing to quarantine directory outside top-level wp-content'];
    }

    $qRoot = rtrim(normalize_path($quarantineRoot), '/');
    if (!is_dir($qRoot) && !@mkdir($qRoot, 0700, true) && !is_dir($qRoot)) {
        return ['success' => false, 'error' => 'could not create quarantine directory'];
    }

    $name = basename($realDir);
    $stamp = gmdate('Ymd-His');
    $dest = $qRoot . '/wp-content-dir-' . $name . '-' . $stamp;
    $n = 1;
    while (file_exists($dest)) {
        $dest = $qRoot . '/wp-content-dir-' . $name . '-' . $stamp . '-' . $n++;
    }

    if (!@rename($realDir, $dest)) {
        return ['success' => false, 'error' => 'rename/move failed'];
    }

    return ['success' => true, 'destination' => $dest];
}

function looks_random_wp_content_dir(string $name): bool {
    $len = strlen($name);
    if ($len < 6 || $len > 32) {
        return false;
    }

    // Strong signal for names such as br19c432, a8d912, xk29f8a.
    if (warden_preg_match('/^[a-z0-9]+$/i', $name)
        && warden_preg_match('/[a-z]/i', $name)
        && warden_preg_match('/[0-9]/', $name)) {
        return true;
    }

    // Long hex-only directory names are also commonly used by droppers.
    if ($len >= 8 && warden_preg_match('/^[a-f0-9]+$/i', $name)) {
        return true;
    }

    return false;
}

function inspect_unexpected_wp_content_dir(string $dir): array {
    $out = [
        'files_sampled' => 0,
        'php_files' => 0,
        'script_files' => 0,
        'extensionless_files' => 0,
        'encoded_extensionless_files' => 0,
        'encoded_extensionless_samples' => [],
    ];

    // Keep this audit cheap. The normal file scanner will inspect contents later.
    $maxFiles = 250;
    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($it as $file) {
            if (!$file->isFile()) {
                continue;
            }

            $out['files_sampled']++;
            $filename = $file->getFilename();
            $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

            if (in_array($ext, ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'inc'], true)) {
                $out['php_files']++;
            }

            if (in_array($ext, ['sh', 'bash', 'pl', 'py', 'cgi'], true)) {
                $out['script_files']++;
            }

            if ($ext === '') {
                $out['extensionless_files']++;
                if (looks_like_long_encoded_payload($file->getPathname())) {
                    $out['encoded_extensionless_files']++;
                    if (count($out['encoded_extensionless_samples']) < 5) {
                        $out['encoded_extensionless_samples'][] = $file->getPathname();
                    }
                }
            }

            if ($out['files_sampled'] >= $maxFiles) {
                break;
            }
        }
    } catch (UnexpectedValueException $e) {
        // Permission/race errors should not abort the main malware scan.
    }

    return $out;
}

function looks_like_long_encoded_payload(string $path): bool {
    $size = @filesize($path);
    if (!is_int($size) || $size < 4096) {
        return false;
    }

    // Sample enough data to identify long encoded blobs without reading an
    // unexpectedly large file into memory. This is deliberately heuristic:
    // it only contributes CRITICAL severity when the parent wp-content
    // directory is itself unexpected and random-looking.
    $sample = @file_get_contents($path, false, null, 0, min($size, 262144));
    if (!is_string($sample) || strlen($sample) < 4096) {
        return false;
    }

    // Ignore whitespace and a short trailing marker/hash line often appended
    // by packed payload families.
    $compact = preg_replace('/\s+/', '', $sample);
    if (!is_string($compact) || strlen($compact) < 4096) {
        return false;
    }

    $len = strlen($compact);
    $base64Chars = warden_preg_match_all('/[A-Za-z0-9+\/=]/', $compact, $m);
    if (!is_int($base64Chars)) {
        return false;
    }

    $ratio = $base64Chars / max(1, $len);
    if ($ratio < 0.96) {
        return false;
    }

    // Require a substantial uninterrupted Base64-like run so ordinary text,
    // hashes, JSON, minified JS, etc. do not trip this heuristic easily.
    return warden_preg_match('/[A-Za-z0-9+\/]{2048,}={0,2}/', $compact) === 1;
}

function classify_scan_file(string $rel): string {
    $rel = normalize_relative($rel);
    $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
    if (is_wordpress_l10n_php($rel)) return 'php-generated-data';
    if (is_php_like_extension($ext)) return 'php-executable';
    if (in_array($ext, ['js', 'mjs', 'cjs'], true)) return 'javascript';
    if (in_array($ext, ['html', 'htm', 'xhtml'], true)) return 'html';
    if ($ext === 'css') return 'css';
    if ($ext === 'json') return 'json';
    if (in_array($ext, ['mo', 'po', 'pot'], true)) return 'gettext/translation';
    if (in_array($ext, ['zip', 'gz', 'tgz', 'bz2', 'xz', '7z', 'rar', 'tar'], true)) return 'archive';
    if (in_array($ext, ['so', 'dll', 'exe', 'bin', 'dat', 'woff', 'woff2', 'ttf', 'otf', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf'], true)) return 'binary';
    if (in_array($ext, ['txt', 'md', 'log', 'xml', 'yml', 'yaml', 'ini', 'conf', 'htaccess'], true) || $ext === '') return 'text';
    return 'text';
}

function audit_wordpress_symlinks(string $root, array $intel): void {
    global $state;
    $rootNorm = normalize_path(realpath($root) ?: $root);
    try {
        $directory = new RecursiveDirectoryIterator($rootNorm, FilesystemIterator::SKIP_DOTS);
        $filter = new RecursiveCallbackFilterIterator($directory, static function ($current) use ($rootNorm, $intel): bool {
            $rel = normalize_relative(fast_relative_path($rootNorm, $current->getPathname()));
            if ($current->isLink()) return true;
            return !($current->isDir() && should_skip_path($rel . '/', $intel));
        });
        $iterator = new RecursiveIteratorIterator($filter, RecursiveIteratorIterator::SELF_FIRST);
        foreach ($iterator as $entry) {
            if (!$entry->isLink()) continue;
            $path = normalize_path($entry->getPathname());
            $rel = normalize_relative(fast_relative_path($rootNorm, $path));
            $target = @readlink($path);
            $resolved = @realpath($path);
            $state['summary']['symlinks_detected'] = (int)($state['summary']['symlinks_detected'] ?? 0) + 1;
            add_finding([
                'severity' => 'medium',
                'type' => 'symlink_in_wordpress_tree',
                'rule_id' => 'BUILTIN_SYMLINK_IN_WORDPRESS_TREE_001',
                'path' => $path,
                'relative_path' => $rel,
                'symlink_target' => $target === false ? null : $target,
                'symlink_resolved_target' => $resolved === false ? null : normalize_path($resolved),
                'reason' => 'Symbolic link found in the WordPress tree; its target was not scanned.',
                'file_action' => false,
                'recommended_action' => 'Verify that this link and target are intentional. Scan the target separately if it is trusted and in scope.',
            ], false);
        }
    } catch (UnexpectedValueException $e) {
        say('WARN: symlink audit could not read part of the WordPress tree: ' . $e->getMessage(), true);
    }
}

function scan_tree(string $root, array $intel, array $coreChecksums, array $componentChecksums): void {
    global $maxSizeMb, $verifyAll, $state, $debugProgress, $fileCacheEnabled, $excludePdf, $newestFirst, $recentPhpDays, $scanRuntime;

    $rootNorm = normalize_path(realpath($root) ?: $root);
    $iterator = make_scan_tree_iterator($rootNorm, $intel);

    if ($newestFirst) {
        $iterator = newest_first_scan_iterable($iterator, $rootNorm, $intel, $recentPhpDays);
    }

    foreach ($iterator as $file) {
        if (!$file->isFile()) {
            continue;
        }

        $path = $file->getPathname();
        if ($recentPhpDays !== null && !is_recent_php_candidate($path, $recentPhpDays)) {
            continue;
        }
        $rel = normalize_relative(fast_relative_path($rootNorm, $path));
        stats_inc('files_seen');
        $classification = classify_scan_file($rel);
        $state['summary']['file_classifications'][$classification] =
            (int)($state['summary']['file_classifications'][$classification] ?? 0) + 1;

        if (($state['summary']['files_seen'] % 1000) === 0) {
            $findingCount = count($state['findings']);
            $hits = (int)($state['summary']['cache_hits'] ?? 0);
            say("Scan progress: {$state['summary']['files_seen']} files seen, {$state['summary']['files_scanned']} fully scanned, $hits cache hits, $findingCount findings");
        }

        if (should_skip_path($rel, $intel)) {
            stats_inc('files_skipped');
            continue;
        }

        // Optional performance mode: skip PDFs before hashing or malware inspection.
        if ($excludePdf && strtolower(pathinfo($rel, PATHINFO_EXTENSION)) === 'pdf') {
            stats_inc('files_skipped');
            if ($debugProgress) { say("Excluded PDF: $rel", true); }
            continue;
        }

        // Skip only exact, known-benign index.php placeholders:
        //   - zero-byte index.php
        //   - "<?php // Silence is golden." (or equivalent block-comment form)
        // This runs before hashing/rule evaluation for a small recurring speed win.
        if (is_benign_index_placeholder($path, $rel)) {
            stats_inc('files_skipped');
            stats_inc('benign_index_skipped');
            if ($debugProgress) {
                say("Benign index placeholder skipped: $rel", true);
            }
            continue;
        }

        if ($fileCacheEnabled && file_cache_is_clean($path, $rel)) {
            stats_inc('cache_hits');
            if ($debugProgress) {
                say("Cache hit: $rel", true);
            }
            continue;
        }

        if ($fileCacheEnabled) {
            stats_inc('cache_misses');
            file_cache_forget($rel);
        }

        stats_inc('files_scanned');
        if ($debugProgress) {
            say("Scanning file: $rel", true);
        }

        $findingsBefore = count($state['findings']);
        $actionsBefore = count($state['actions']);

        $fileStarted = microtime(true);
        $metadataBefore = file_cache_stat($path);
        scan_one_file($root, $path, $rel, $intel, $coreChecksums, $componentChecksums, $verifyAll);
        $metadataAfter = is_file($path) ? file_cache_stat($path) : null;
        $changedDuringScan = false;
        if (count($state['actions']) === $actionsBefore
            && $metadataBefore !== null
            && ($metadataAfter === null || !file_metadata_equal($metadataBefore, $metadataAfter))) {
            $changedDuringScan = true;
            file_cache_forget($rel);
            say("[RACE] File changed during scan: $rel", true);
            add_finding([
                'severity' => 'medium',
                'type' => 'file_changed_during_scan',
                'rule_id' => 'BUILTIN_FILE_SCAN_RACE_001',
                'path' => $path,
                'relative_path' => $rel,
                'metadata_before' => $metadataBefore,
                'metadata_after' => $metadataAfter,
                'reason' => 'File metadata changed while it was being scanned; the result is not considered clean.',
                'file_action' => false,
                'recommended_action' => 'Investigate the writer and rescan the site when file activity has stopped.',
            ], false);

            // Make one bounded retry when no earlier finding/action complicates
            // interpretation. The race finding remains and prevents caching.
            if (is_file($path)
                && count($state['findings']) === $findingsBefore + 1
                && count($state['actions']) === $actionsBefore) {
                $retryBefore = file_cache_stat($path);
                scan_one_file($root, $path, $rel, $intel, $coreChecksums, $componentChecksums, $verifyAll);
                $retryAfter = is_file($path) ? file_cache_stat($path) : null;
                if (!file_metadata_equal($retryBefore, $retryAfter)) {
                    say("[RACE] File changed again during retry: $rel", true);
                }
            }
        }
        record_file_timing((microtime(true) - $fileStarted) * 1000, $rel);

        // Only cache files that completed with no finding/action at all. Files that
        // were repaired, quarantined, suspicious, or unresolved are rescanned next
        // time. This deliberately favours safety over a larger hit rate.
        if ($fileCacheEnabled
            && is_file($path)
            && !$changedDuringScan
            && empty($scanRuntime['global_pcre_error'])
            && empty($scanRuntime['pcre_error_paths'][$rel])
            && count($state['findings']) === $findingsBefore
            && count($state['actions']) === $actionsBefore) {
            file_cache_mark_clean($path, $rel);
        }
    }
}

function randomized_protect_uploads_plugin_ioc(string $pluginDir, string $slug): bool {
    // The legitimate plugin uses the protect-uploads slug. This malware family
    // clones it into a random seven-letter directory and adds a hostile php.ini.
    if (warden_preg_match('/^[a-z]{7}$/i', $slug) !== 1) {
        return false;
    }

    $main = $pluginDir . '/protect-uploads.php';
    $admin = $pluginDir . '/admin/class-protect-uploads-admin.php';
    $ini = $pluginDir . '/php.ini';
    if (!is_file($main) || !is_file($admin) || !is_file($ini)) {
        return false;
    }

    $mainData = @file_get_contents($main, false, null, 0, 32768);
    $adminData = @file_get_contents($admin, false, null, 0, 32768);
    $iniData = @file_get_contents($ini, false, null, 0, 4096);
    if (!is_string($mainData) || !is_string($adminData) || !is_string($iniData)) {
        return false;
    }

    $isProtectUploads = stripos($mainData, 'Protect Uploads') !== false
        && stripos($mainData, 'Alti_ProtectUploads') !== false
        && stripos($adminData, 'Alti_ProtectUploads_Admin') !== false;
    $hostileIni = warden_preg_match('/disable_functions\s*=\s*(?:none)?\s*$/im', $iniData) === 1
        && warden_preg_match('/open_basedir\s*=\s*(?:off)?\s*$/im', $iniData) === 1
        && warden_preg_match('/shell_exec\s*=\s*on\s*$/im', $iniData) === 1;

    return $isProtectUploads && $hostileIni;
}

function audit_malicious_upload_bundle_directories(string $root): void {
    $uploads = rtrim(normalize_path($root), '/') . '/wp-content/uploads';
    if (!is_dir($uploads)) {
        return;
    }

    $entries = @scandir($uploads);
    if (!is_array($entries)) {
        return;
    }

    foreach ($entries as $name) {
        if ($name === '.' || $name === '..'
            || warden_preg_match('/^[0-9]{4}$/', $name) === 1
            || warden_preg_match('/^[a-z0-9]{6,20}$/i', $name) !== 1) {
            continue;
        }

        $dir = $uploads . '/' . $name;
        if (!is_dir($dir) || is_link($dir)) {
            continue;
        }

        $signals = inspect_malicious_upload_bundle($dir);
        $codeSignal = $signals['query_parent_uploader'] || $signals['fragmented_self_loader'];
        $supportSignal = $signals['permissive_htaccess'] || $signals['hostile_php_ini'];
        if (!$codeSignal || !$supportSignal) {
            continue;
        }

        $sample = $signals['sample'] ?: first_regular_file_in_directory($dir);
        if ($sample === null || !is_file($sample)) {
            continue;
        }

        $found = [];
        foreach (['query_parent_uploader', 'fragmented_self_loader', 'permissive_htaccess', 'hostile_php_ini'] as $key) {
            if ($signals[$key]) {
                $found[] = $key;
            }
        }

        add_finding([
            'severity' => 'critical',
            'type' => 'malicious_upload_bundle_directory',
            'rule_id' => 'BUILTIN_AXIL_UPLOAD_BUNDLE_001',
            'path' => $sample,
            'relative_path' => 'wp-content/uploads/' . $name . '/',
            'reason' => 'Correlated malware bundle under uploads: ' . implode(', ', $found) . '.',
            'directory_path' => $dir,
            'bundle_signals' => $signals,
            'recommended_action' => 'Quarantine the entire uploads bundle directory, including its loader, upload shell, .htaccess and php.ini.',
        ], true);
    }
}

function inspect_malicious_upload_bundle(string $dir): array {
    $out = [
        'files_sampled' => 0,
        'query_parent_uploader' => false,
        'fragmented_self_loader' => false,
        'permissive_htaccess' => false,
        'hostile_php_ini' => false,
        'sample' => null,
    ];

    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        foreach ($it as $file) {
            if (!$file->isFile() || $file->isLink() || $out['files_sampled'] >= 100) {
                continue;
            }
            $out['files_sampled']++;
            $size = $file->getSize();
            if ($size < 1 || $size > 2097152) {
                continue;
            }
            $path = normalize_path($file->getPathname());
            $data = @file_get_contents($path);
            if (!is_string($data)) {
                continue;
            }

            $base = strtolower($file->getFilename());
            if ($base === '.htaccess'
                && stripos($data, 'FilesMatch') !== false
                && stripos($data, 'Allow from all') !== false) {
                $out['permissive_htaccess'] = true;
                $out['sample'] = $out['sample'] ?: $path;
            }
            if ($base === 'php.ini'
                && warden_preg_match('/disable_functions\s*=\s*(?:none)?\s*$/im', $data) === 1
                && warden_preg_match('/open_basedir\s*=\s*(?:off)?\s*$/im', $data) === 1) {
                $out['hostile_php_ini'] = true;
                $out['sample'] = $out['sample'] ?: $path;
            }
            if (warden_preg_match('/\$_GET\s*\[\s*[\'\"]f[\'\"]\s*\][\s\S]{0,400}\$_FILES\s*\[\s*[\'\"]file[\'\"]\s*\]/i', $data) === 1
                && warden_preg_match('/move_uploaded_file\s*\([\s\S]{0,500}[\'\"]\.\.\/[\'\"]\s*\./i', $data) === 1) {
                $out['query_parent_uploader'] = true;
                $out['sample'] = $path;
            }
            if (warden_preg_match('/[\'\"]gzuncompre[\'\"]\s*\.\s*[\'\"]ss[\'\"]/i', $data) === 1
                && stripos($data, '__FILE__') !== false
                && warden_preg_match('/eval\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\(/i', $data) === 1) {
                $out['fragmented_self_loader'] = true;
                $out['sample'] = $path;
            }
        }
    } catch (UnexpectedValueException $e) {
        // Permission and race errors are reported later by the normal scan.
    }

    return $out;
}

function make_scan_tree_iterator(string $rootNorm, array $intel): RecursiveIteratorIterator {
    $directory = new RecursiveDirectoryIterator($rootNorm, FilesystemIterator::SKIP_DOTS);
    $filter = new RecursiveCallbackFilterIterator($directory, function ($current) use ($rootNorm, $intel) {
        $rel = fast_relative_path($rootNorm, $current->getPathname());
        if ($current->isLink()) {
            return false;
        }
        if ($current->isDir() && should_skip_path($rel . '/', $intel)) {
            return false;
        }
        return true;
    });
    return new RecursiveIteratorIterator($filter);
}

function newest_first_scan_iterable(RecursiveIteratorIterator $iterator, string $rootNorm, array $intel, ?int $recentPhpDays): Generator {
    $limit = 5000;
    $eligible = 0;
    $heap = new SplPriorityQueue();
    $heap->setExtractFlags(SplPriorityQueue::EXTR_BOTH);

    foreach ($iterator as $candidate) {
        if (!$candidate->isFile()) {
            continue;
        }
        $path = $candidate->getPathname();
        if ($recentPhpDays !== null && !is_recent_php_candidate($path, $recentPhpDays)) {
            continue;
        }
        $mtime = @filemtime($path);
        $mtime = is_int($mtime) ? $mtime : 0;
        $eligible++;
        // Negative priority makes the oldest retained entry the first evicted,
        // leaving a bounded heap containing only the newest files encountered.
        $heap->insert($path, -$mtime);
        if ($heap->count() > $limit) {
            $heap->extract();
        }
    }

    $newestPaths = [];
    while (!$heap->isEmpty()) {
        $entry = $heap->extract();
        $newestPaths[] = (string)$entry['data'];
    }
    $newestPaths = array_reverse($newestPaths);
    $prioritized = array_fill_keys($newestPaths, true);

    say('Newest-first priority prepared: ' . count($newestPaths) . " newest of {$eligible} eligible files; remaining files follow in normal order.");

    foreach ($newestPaths as $path) {
        if (is_file($path)) {
            yield new SplFileInfo($path);
        }
    }

    foreach (make_scan_tree_iterator($rootNorm, $intel) as $candidate) {
        if (!$candidate->isFile()) {
            continue;
        }
        $path = $candidate->getPathname();
        if (isset($prioritized[$path])) {
            continue;
        }
        if ($recentPhpDays !== null && !is_recent_php_candidate($path, $recentPhpDays)) {
            continue;
        }
        yield $candidate;
    }
}

function is_recent_php_candidate(string $path, int $days): bool {
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    if (!is_php_like_extension($ext)) {
        return false;
    }

    $mtime = @filemtime($path);
    return is_int($mtime) && $mtime >= (time() - ($days * 86400));
}

function is_benign_index_placeholder(string $path, string $rel): bool {
    // Only a file literally named index.php is eligible. Never suppress arbitrary
    // PHP files just because they contain the phrase "Silence is golden".
    if (strtolower(basename($rel)) !== 'index.php') {
        return false;
    }

    $size = @filesize($path);

    // Common empty directory-protection placeholder.
    if ($size === 0) {
        return true;
    }

    // Legitimate placeholder index files are tiny. Keep the read bounded so this
    // remains a cheap pre-scan check.
    if (!is_int($size) || $size < 0 || $size > 256) {
        return false;
    }

    $data = @file_get_contents($path);
    if (!is_string($data)) {
        return false;
    }

    // Normalise UTF-8 BOM, line endings, and harmless surrounding whitespace.
    $data = preg_replace('/^\xEF\xBB\xBF/', '', $data);
    $data = str_replace(["\r\n", "\r"], "\n", $data);
    $trimmed = trim($data);

    // Match only the complete known benign placeholder, optionally with a closing
    // PHP tag. Anything before/after it causes the file to be scanned normally.
    return warden_preg_match(
        '/^<\?php\s*(?:\/\/\s*Silence is golden\.?|\/\*\s*Silence is golden\.?\s*\*\/)\s*(?:\?>)?$/i',
        $trimmed
    ) === 1;
}

function should_skip_path(string $rel, array $intel): bool {
    $rel = normalize_relative($rel);
    foreach (($intel['policy']['paths']['skip_relative_prefixes'] ?? []) as $prefix) {
        $prefix = normalize_relative($prefix);
        if (strpos($rel, rtrim($prefix, '/') . '/') === 0) {
            return true;
        }
    }
    return false;
}

function is_cwp_login_compromise_filename(string $rel): bool {
    return warden_preg_match('/^cwp_login_[a-f0-9]{6,32}\.php$/i', basename($rel)) === 1;
}

function scan_one_file(string $root, string $path, string $rel, array $intel, array $coreChecksums, array $componentChecksums, bool $verifyAll): void {
    global $maxTextSizeMb, $maxSizeMb, $state;

    $hashes = file_hashes($path);
    if (!$hashes) {
        return;
    }

    $rel = normalize_relative($rel);
    $size = @filesize($path);
    $deepScanAllowed = !is_int($size) || $maxSizeMb <= 0 || $size <= ($maxSizeMb * 1024 * 1024);
    if (!$deepScanAllowed) {
        $state['summary']['large_files_deep_scan_skipped'] =
            (int)($state['summary']['large_files_deep_scan_skipped'] ?? 0) + 1;
        say("[LARGE-FILE] Deep scan skipped: $rel", true);
        add_finding([
            'severity' => 'info',
            'type' => 'large_file_deep_scan_skipped',
            'rule_id' => 'BUILTIN_LARGE_FILE_DEEP_SCAN_SKIPPED_001',
            'path' => $path,
            'relative_path' => $rel,
            'size_bytes' => $size,
            'classification' => classify_scan_file($rel),
            'reason' => "File exceeds --max-size={$maxSizeMb}MB. Checksums, location and magic checks continue, but deep content scanning is skipped.",
            'file_action' => false,
            'recommended_action' => 'Review large executable or unexpected files manually, or raise --max-size for a controlled rescan.',
        ], false);
    }
    if (is_whitelisted($hashes, $intel['file_whitelist'])) {
        return;
    }
    if (is_cwp_login_compromise_filename($rel)) {
        add_finding([
            'severity' => 'high',
            'type' => 'suspicious_filename_ioc',
            'rule_id' => 'BUILTIN_CWP_LOGIN_DROPPER_FILENAME_001',
            'path' => $path,
            'relative_path' => $rel,
            'reason' => 'Filename matches the cwp_login_<random>.php IOC reported in the August 2026 CWP compromise campaign.',
            'hashes' => $hashes,
            'recommended_action' => 'Inspect and quarantine the file, then investigate the CWP host for related persistence and credential compromise.',
        ], true);
    }

    if (isset($coreChecksums[$rel])) {
        $expected = $coreChecksums[$rel];
        if (hash_matches($hashes, $expected)) {
            scan_trusted_known_good_file($path, $rel, $hashes, $intel);
            return;
        }

        add_finding([
            'severity' => 'critical',
            'type' => 'modified_official_core',
            'path' => $path,
            'relative_path' => $rel,
            'reason' => 'Core file hash does not match local checksum intel.',
            'hashes' => $hashes,
            'expected' => $expected,
            'repair' => [
                'type' => 'core',
                'slug' => null,
                'version' => null,
                'expected' => $expected,
                'clean_zip' => null,
            ],
            'recommended_action' => 'Replace from a clean WordPress core package after backup.',
        ]);
        if (is_file($path) && should_offer_repair_after_finding()) {
            if (maybe_offer_original_repair('core', null, null, $rel, $path, $expected)) {
                // The replacement bytes were verified against the trusted core
                // checksum before installation. Do not spend time scanning the
                // newly restored known-good file with generic malware regexes.
                return;
            }
        }
    }

    if ($verifyAll && !empty($coreChecksums) && looks_like_core_path($rel) && !isset($coreChecksums[$rel])) {
        add_finding([
            'severity' => 'critical',
            'type' => 'extra_core_file',
            'path' => $path,
            'relative_path' => $rel,
            'reason' => 'File is in a WordPress core location but is not present in the expected core checksum map.',
            'hashes' => $hashes,
            'recommended_action' => 'Inspect immediately. Extra files in wp-admin/wp-includes are commonly malicious unless deliberately placed.',
        ], true);
    }

    $component = component_expected_checksum($rel, $componentChecksums);
    if ($component) {
        if (hash_matches($hashes, $component['expected'])) {
            scan_trusted_known_good_file($path, $rel, $hashes, $intel);
            return;
        }

        add_finding([
            'severity' => component_checksum_mismatch_severity($rel),
            'type' => "modified_official_{$component['type']}",
            'component' => $component['slug'],
            'component_version' => $component['version'],
            'path' => $path,
            'relative_path' => $rel,
            'reason' => ucfirst($component['type']) . ' file hash does not match checksum intel.',
            'hashes' => $hashes,
            'expected' => $component['expected'],
            'checksum_source' => $component['checksum_source'] ?? null,
            'repair' => [
                'type' => $component['type'],
                'slug' => $component['slug'],
                'version' => $component['version'],
                'expected' => $component['expected'],
                'clean_zip' => $component['clean_zip'] ?? null,
            ],
            'recommended_action' => 'Replace from a clean vendor/package copy after backup.',
        ]);
        if (is_file($path) && should_offer_repair_after_finding()) {
            if (maybe_offer_original_repair($component['type'], $component['slug'], $component['version'], $rel, $path, $component['expected'], $component['clean_zip'] ?? null)) {
                // As above, a successful repair is checksum-proven clean. Failed,
                // skipped or declined repairs continue through malware scanning.
                return;
            }
        }
    }

    if ($verifyAll && !$component) {
        $componentContext = component_context_for_path($rel, $componentChecksums);
        if ($componentContext) {
            $extraFinding = [
                'severity' => 'high',
                'type' => "extra_{$componentContext['type']}_file",
                'component' => $componentContext['slug'],
                'component_version' => $componentContext['version'],
                'path' => $path,
                'relative_path' => $rel,
                'reason' => ucfirst($componentContext['type']) . ' has checksum intel, but this file is not listed in that expected file map.',
                'hashes' => $hashes,
                'recommended_action' => 'Inspect the file. If legitimate, regenerate or approve checksum intel from a clean package.',
            ];
            add_finding($extraFinding, true);

            if (maybe_auto_quarantine_extra_file($extraFinding)) {
                return;
            }
        }
    }

    $magic = sniff_magic($path);
    if (in_array($magic, ['ELF', 'PE', 'MACHO'], true)) {
        $severity = binary_location_suspicious($rel) ? 'critical' : 'high';
        add_finding([
            'severity' => $severity,
            'type' => 'unexpected_binary',
            'path' => $path,
            'relative_path' => $rel,
            'reason' => "Executable binary detected in WordPress tree ($magic).",
            'hashes' => $hashes,
            'recommended_action' => 'Inspect and quarantine if not explicitly expected.',
        ], true);
        return;
    }

    if (uploads_executable($rel, $intel)) {
        add_finding([
            'severity' => 'critical',
            'type' => 'executable_in_uploads',
            'path' => $path,
            'relative_path' => $rel,
            'reason' => 'Executable/script extension found under wp-content/uploads.',
            'hashes' => $hashes,
            'recommended_action' => 'Quarantine after confirming it is not a legitimate generated asset.',
        ], true);
    }

    // WordPress generated translation catalogs (*.l10n.php) are commonly one very
    // long PHP line containing a large returned array. Running hundreds of whole-file
    // PCRE malware signatures against those files can cause pathological regex CPU use.
    // Keep normal hashing/integrity handling above, but use a token-based safety scan
    // here instead of the generic regex engine.
    if (!$deepScanAllowed) {
        // Metadata, checksum, location and magic checks above have completed.
        // Do not load an arbitrarily large file into memory for deep inspection.
    } elseif (is_wordpress_l10n_php($rel)) {
        scan_wordpress_l10n_php_safely($path, $rel, $hashes);
    } else {
        $size = @filesize($path);
        if (is_int($size) && $size > ($maxTextSizeMb * 1024 * 1024)) {
            stats_inc('files_skipped');
            say("[TEXT-SKIP] Regex scan skipped for large text candidate: $rel (" . round($size / 1048576, 2) . " MB)");
        } else {
            $textData = read_text_candidate($path);
            if ($textData !== null) {
                scan_text_rules($path, $rel, $hashes, $intel['php_rules'], $textData);
            }
        }
    }

    if ($verifyAll && empty($coreChecksums[$rel]) && looks_like_core_path($rel)) {
        add_finding([
            'severity' => 'medium',
            'type' => 'core_file_without_checksum',
            'path' => $path,
            'relative_path' => $rel,
            'reason' => 'File looks like WordPress core, but no checksum intel was available.',
            'hashes' => $hashes,
            'recommended_action' => 'Add local core checksum intel or verify against official package.',
        ]);
    }
}

function component_checksum_mismatch_severity(string $rel): string {
    $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
    // Generated translations and documentation frequently differ between an
    // API manifest, release ZIP and repository tag. They are non-executable;
    // PHP and JavaScript retain the normal HIGH mismatch severity.
    if (in_array($ext, ['pot', 'po', 'mo', 'txt', 'md', 'markdown', 'rst'], true)) {
        return 'low';
    }
    return 'high';
}

function is_wordpress_l10n_php(string $rel): bool {
    $rel = normalize_relative($rel);
    return strpos($rel, 'wp-content/languages/') === 0
        && warden_preg_match('/\.l10n\.php$/i', $rel) === 1;
}

function scan_wordpress_l10n_php_safely(string $path, string $rel, array $hashes): void {
    $data = @file_get_contents($path);
    if (!is_string($data)) {
        return;
    }

    // token_get_all() is linear and, unlike the generic PCRE rule set, ignores
    // dangerous-looking words that merely occur inside translated string literals.
    $tokens = token_get_all($data);
    $dangerousVariables = [
        '$_GET' => true,
        '$_POST' => true,
        '$_REQUEST' => true,
        '$_COOKIE' => true,
        '$_FILES' => true,
        '$_SERVER' => true,
    ];
    $dangerousFunctions = [
        'assert' => true,
        'base64_decode' => true,
        'call_user_func' => true,
        'call_user_func_array' => true,
        'exec' => true,
        'file_put_contents' => true,
        'fopen' => true,
        'fwrite' => true,
        'gzinflate' => true,
        'gzuncompress' => true,
        'passthru' => true,
        'pcntl_exec' => true,
        'popen' => true,
        'proc_open' => true,
        'shell_exec' => true,
        'system' => true,
        'unlink' => true,
    ];
    $dangerousTokenIds = array_fill_keys(array_filter([
        defined('T_EVAL') ? T_EVAL : null,
        defined('T_INCLUDE') ? T_INCLUDE : null,
        defined('T_INCLUDE_ONCE') ? T_INCLUDE_ONCE : null,
        defined('T_REQUIRE') ? T_REQUIRE : null,
        defined('T_REQUIRE_ONCE') ? T_REQUIRE_ONCE : null,
    ], static function ($value): bool { return is_int($value); }), true);

    $hits = [];
    foreach ($tokens as $token) {
        if (!is_array($token)) {
            continue;
        }

        [$tokenId, $tokenText] = $token;
        if ($tokenId === T_VARIABLE && isset($dangerousVariables[$tokenText])) {
            $hits[$tokenText] = true;
            continue;
        }

        if ($tokenId === T_STRING) {
            $name = strtolower($tokenText);
            if (isset($dangerousFunctions[$name])) {
                $hits[$name . '()'] = true;
            }
            continue;
        }

        if (isset($dangerousTokenIds[$tokenId])) {
            $hits[strtolower(trim($tokenText))] = true;
        }
    }

    if (!$hits) {
        return;
    }

    $indicators = array_keys($hits);
    sort($indicators, SORT_STRING);
    add_finding([
        'severity' => 'high',
        'type' => 'suspicious_l10n_php_code',
        'rule_id' => 'BUILTIN_L10N_EXECUTABLE_CODE_001',
        'path' => $path,
        'relative_path' => $rel,
        'reason' => 'WordPress .l10n.php translation file contains executable/request-handling tokens that are not expected in a generated translation catalog: ' . implode(', ', $indicators),
        'hashes' => $hashes,
        'recommended_action' => 'Compare this translation file with a clean WordPress/plugin language package before replacing or quarantining it.',
    ], true);
}

function scan_trusted_known_good_file(string $path, string $rel, array $hashes, array $intel): void {
    return;
}

function component_path_parts(string $rel): ?array {
    $rel = normalize_relative($rel);

    foreach ([
        'wp-content/plugins/' => 'plugin',
        'wp-content/themes/' => 'theme',
    ] as $prefix => $type) {
        if (strpos($rel, $prefix) !== 0) {
            continue;
        }

        $tail = substr($rel, strlen($prefix));
        $slash = strpos($tail, '/');
        if ($slash === false || $slash === 0) {
            return null;
        }

        return [
            'type' => $type,
            'slug' => substr($tail, 0, $slash),
            'inner' => substr($tail, $slash + 1),
        ];
    }

    return null;
}

function component_expected_checksum(string $rel, array $componentChecksums): ?array {
    $parts = component_path_parts($rel);
    if ($parts === null) {
        return null;
    }

    $bucket = $parts['type'] === 'plugin' ? 'plugins' : 'themes';
    $set = $componentChecksums[$bucket][$parts['slug']] ?? null;
    if (!is_array($set) || !isset($set['files'][$parts['inner']])) {
        return null;
    }

    return [
        'type' => $parts['type'],
        'slug' => $parts['slug'],
        'version' => $set['version'] ?? null,
        'expected' => $set['files'][$parts['inner']],
        'clean_zip' => $set['clean_zip'] ?? null,
        'checksum_source' => $set['source'] ?? null,
    ];
}

function component_context_for_path(string $rel, array $componentChecksums): ?array {
    $parts = component_path_parts($rel);
    if ($parts === null) {
        return null;
    }

    $bucket = $parts['type'] === 'plugin' ? 'plugins' : 'themes';
    $set = $componentChecksums[$bucket][$parts['slug']] ?? null;
    if (!is_array($set)) {
        return null;
    }

    return [
        'type' => $parts['type'],
        'slug' => $parts['slug'],
        'version' => $set['version'] ?? null,
    ];
}

function file_hashes(string $path): ?array {
    $fh = @fopen($path, 'rb');
    if (!$fh) {
        return null;
    }

    $md5 = hash_init('md5');
    $sha256 = hash_init('sha256');
    while (!feof($fh)) {
        $chunk = fread($fh, 1048576);
        if ($chunk === false) {
            fclose($fh);
            return null;
        }
        if ($chunk === '') {
            continue;
        }
        hash_update($md5, $chunk);
        hash_update($sha256, $chunk);
    }
    fclose($fh);

    return [
        'md5' => strtolower(hash_final($md5)),
        'sha256' => strtolower(hash_final($sha256)),
    ];
}

function is_whitelisted(array $hashes, array $whitelist): bool {
    return isset($whitelist[$hashes['sha256']]) || isset($whitelist[$hashes['md5']]);
}

function hash_matches(array $actual, array $expected): bool {
    if (!empty($expected['sha256']) && hash_equals($expected['sha256'], $actual['sha256'])) {
        return true;
    }
    if (!empty($expected['md5']) && hash_equals($expected['md5'], $actual['md5'])) {
        return true;
    }
    return false;
}

function sniff_magic(string $path): ?string {
    $fh = @fopen($path, 'rb');
    if (!$fh) {
        return null;
    }
    $head = fread($fh, 8);
    fclose($fh);

    if (substr($head, 0, 4) === "\x7fELF") {
        return 'ELF';
    }
    if (substr($head, 0, 2) === "MZ") {
        return 'PE';
    }
    $hex = bin2hex(substr($head, 0, 4));
    if (in_array($hex, ['feedface', 'feedfacf', 'cefaedfe', 'cffaedfe', 'cafebabe'], true)) {
        return 'MACHO';
    }
    return null;
}

function binary_location_suspicious(string $rel): bool {
    return strpos($rel, 'wp-content/uploads/') === 0
        || strpos($rel, 'wp-content/cache/') === 0
        || strpos($rel, 'wp-content/upgrade/') === 0;
}

function uploads_executable(string $rel, array $intel): bool {
    if (strpos($rel, 'wp-content/uploads/') !== 0) {
        return false;
    }
    $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
    return in_array($ext, $intel['policy']['paths']['suspicious_upload_extensions'] ?? [], true);
}

function read_text_candidate(string $path): ?string {
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    $textExt = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'js', 'htaccess', 'txt', 'html', 'css', 'inc'];
    $knownText = in_array($ext, $textExt, true);

    $fh = @fopen($path, 'rb');
    if (!$fh) {
        return null;
    }

    $first = fread($fh, 512);
    if ($first === false) {
        fclose($fh);
        return null;
    }

    if (!$knownText && strpos($first, "\0") !== false) {
        fclose($fh);
        return null;
    }

    $data = $first;
    while (!feof($fh)) {
        $chunk = fread($fh, 1048576);
        if ($chunk === false) {
            fclose($fh);
            return null;
        }
        if ($chunk !== '') {
            $data .= $chunk;
        }
    }
    fclose($fh);
    return $data;
}

function is_probably_text(string $path): bool {
    return read_text_candidate($path) !== null;
}

function scan_text_rules(string $path, string $rel, array $hashes, array $rules, ?string $data = null): void {
    global $scanRuntime;
    $rel = normalize_relative($rel);
    // Defence in depth: callers normally route these files directly to the
    // token scanner, but this guard prevents any alternate path from sending a
    // generated catalog through whole-file malware PCRE rules.
    if (is_wordpress_l10n_php($rel)) {
        scan_wordpress_l10n_php_safely($path, $rel, $hashes);
        return;
    }
    if ($data === null) {
        $data = @file_get_contents($path);
        if ($data === false) {
            return;
        }
    }

    // Exact, locally reviewed family rules run before generic built-in and
    // community heuristics. This prevents large malware files containing whole
    // vendor libraries from spending minutes in broad regexes before reaching
    // a decisive signature near the start of the file.
    $externalFastStarted = microtime(true);
    $fastMatchedRuleIds = scan_fast_trusted_family_rules($path, $rel, $hashes, $rules, $data);
    $externalStageMs = (microtime(true) - $externalFastStarted) * 1000;
    if (!is_file($path)) {
        record_slow_stage($externalStageMs, 'external-rules', $rel);
        return;
    }

    $builtinStarted = microtime(true);
    scan_builtin_text_heuristics($path, $rel, $hashes, $data);
    record_slow_stage((microtime(true) - $builtinStarted) * 1000, 'builtin-heuristics', $rel);

    // A built-in automatic quarantine may have moved the file. Do not emit
    // secondary external-rule findings for a file that no longer exists.
    if (!is_file($path)) {
        return;
    }

    if (!should_run_external_php_rules($rel, $data)) {
        record_slow_stage($externalStageMs, 'external-rules', $rel);
        return;
    }

    $scanRuntime['generic_rule_paths'][$rel] = true;

    $lines = null;
    $externalRulesStarted = microtime(true);

    foreach ($rules as $rule) {
        if (isset($fastMatchedRuleIds[(string)($rule['id'] ?? '')])) {
            continue;
        }
        $pattern = $rule['pattern'] ?? null;
        if (!is_string($pattern) || $pattern === '') {
            continue;
        }

        // Cheap rule-author supplied prefilters run before either literal or PCRE.
        foreach (($rule['_anchors'] ?? []) as $anchor) {
            if (stripos($data, $anchor) === false) {
                continue 2;
            }
        }

        $mode = $rule['_match_mode'] ?? 'regex';
        $matched = false;
        $matchedText = null;
        $isLineRule = (($rule['type'] ?? '') === 'regex_line');

        if ($isLineRule) {
            // Split the file only once, no matter how many regex_line rules exist.
            if ($lines === null) {
                $lines = preg_split('/\r?\n/', $data);
                if (!is_array($lines)) {
                    $lines = [];
                }
            }

            foreach ($lines as $idx => $line) {
                if (strlen($line) > 20000) {
                    continue;
                }

                if ($mode === 'literal') {
                    $hit = stripos($line, (string)($rule['_literal'] ?? $pattern)) !== false;
                } else {
                    $regex = $rule['_regex'] ?? ('~' . str_replace('~', '\\~', $pattern) . '~i');
                    $ruleMatches = null;
                    $hit = warden_preg_match($regex, $line, $ruleMatches, 0, 0, [
                        'rule_id' => (string)($rule['id'] ?? '(unnamed rule)'),
                        'path' => $rel,
                    ]) === 1;
                }

                if ($hit) {
                    $matched = $idx + 1;
                    $matchedText = trim($line);
                    break;
                }
            }
        } else {
            if ($mode === 'literal') {
                $matched = stripos($data, (string)($rule['_literal'] ?? $pattern)) !== false;
            } else {
                // Regexes were validated and assembled once at intel load time.
                $regex = $rule['_regex'] ?? ('~' . str_replace('~', '\\~', $pattern) . '~i');
                $ruleMatches = null;
                $matched = warden_preg_match($regex, $data, $ruleMatches, 0, 0, [
                    'rule_id' => (string)($rule['id'] ?? '(unnamed rule)'),
                    'path' => $rel,
                ]) === 1;
            }
        }

        if ($matched !== false && $matched !== 0) {
            add_finding([
                'severity' => $rule['severity'] ?? 'medium',
                'type' => 'php_rule_match',
                'rule_id' => $rule['id'] ?? null,
                'rule_pattern' => $pattern,
                'rule_source' => $rule['source'] ?? $rule['category'] ?? null,
                'path' => $path,
                'relative_path' => $rel,
                'line' => is_int($matched) ? $matched : null,
                'matched_text' => $matchedText !== null ? shorten_text($matchedText, 240) : null,
                'reason' => $rule['description'] ?? 'PHP malware detection rule matched.',
                'hashes' => $hashes,
                'recommended_action' => 'Inspect code and quarantine if malicious.',
            ], true);

            // Interactive deletion or automatic quarantine may have removed the
            // file. Do not keep running rules against the stale in-memory copy.
            if (!is_file($path)) {
                break;
            }
        }
    }
    $externalStageMs += (microtime(true) - $externalRulesStarted) * 1000;
    record_slow_stage($externalStageMs, 'external-rules', $rel);
}

function scan_fast_trusted_family_rules(string $path, string $rel, array $hashes, array $rules, string $data): array {
    $fastIds = [
        'PHP_AXIL_QUERY_PARENT_UPLOAD_BACKDOOR_001' => true,
        'PHP_FRAGMENTED_SELF_TAIL_GZIP_EVAL_001' => true,
        'PHP_FRAGMENTED_ROT13_GZINFLATE_EVAL_001' => true,
        'PHP_INDEXED_STRING_TABLE_GOTO_REMOTE_LOADER_001' => true,
        'PHP_TRIPLE_MD5_POST_GZIP_DROPPER_001' => true,
        'PHP_LEAFMAILER_FAMILY_001' => true,
        'PHP_LEAFMAILER_PASSWORD_GATE_001' => true,
        'PHP_CWP_PASSWORDLESS_ADMIN_LOGIN_001' => true,
        'PHP_WP_SYSTEMATIZATION_GOVERNMENT_HIDDEN_PLUGIN_001' => true,
        'PHP_COOKIE_INDEXED_HEX2BIN_INCLUDE_LOADER_001' => true,
    ];
    $matchedIds = [];

    foreach ($rules as $rule) {
        $ruleId = (string)($rule['id'] ?? '');
        if (!isset($fastIds[$ruleId])) {
            continue;
        }
        foreach (($rule['_anchors'] ?? []) as $anchor) {
            if (stripos($data, $anchor) === false) {
                continue 2;
            }
        }

        $pattern = $rule['pattern'] ?? null;
        if (!is_string($pattern) || $pattern === '') {
            continue;
        }
        if (($rule['_match_mode'] ?? 'regex') === 'literal') {
            $matched = stripos($data, (string)($rule['_literal'] ?? $pattern)) !== false;
        } else {
            $regex = $rule['_regex'] ?? ('~' . str_replace('~', '\\~', $pattern) . '~i');
            $ruleMatches = null;
            $matched = warden_preg_match($regex, $data, $ruleMatches, 0, 0, [
                'rule_id' => $ruleId,
                'path' => $rel,
            ]) === 1;
        }
        if (!$matched) {
            continue;
        }

        $matchedIds[$ruleId] = true;
        add_finding([
            'severity' => $rule['severity'] ?? 'critical',
            'type' => 'php_rule_match',
            'rule_id' => $ruleId,
            'rule_pattern' => $pattern,
            'rule_source' => $rule['source'] ?? $rule['category'] ?? null,
            'path' => $path,
            'relative_path' => $rel,
            'line' => null,
            'matched_text' => null,
            'reason' => $rule['description'] ?? 'Reviewed PHP malware family signature matched.',
            'hashes' => $hashes,
            'recommended_action' => 'Quarantine the file and investigate related persistence.',
        ], true);

        if (!is_file($path)) {
            break;
        }
    }

    return $matchedIds;
}

function should_run_external_php_rules(string $rel, string $data): bool {
    $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
    if (is_php_like_extension($ext)) {
        return true;
    }

    return has_php_open_tag($data) || has_php_only_execution_marker($data);
}

function scan_builtin_text_heuristics(string $path, string $rel, array $hashes, string $data): void {
    $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));

    $isPhpLike = is_php_like_extension($ext);
    $hasPhpOpenTag = has_php_open_tag($data);
    if ($hasPhpOpenTag && !$isPhpLike) {
        add_finding([
            'severity' => 'critical',
            'type' => 'php_code_in_non_php_file',
            'rule_id' => 'BUILTIN_PHP_IN_NON_PHP_001',
            'path' => $path,
            'relative_path' => $rel,
            'reason' => "PHP code found in .$ext file.",
            'hashes' => $hashes,
            'recommended_action' => 'Quarantine or remove unless there is a very specific known-good reason.',
        ], true);
    }

    $hasExecutionContext = has_php_only_execution_marker($data);
    if (!$isPhpLike && !$hasPhpOpenTag && !$hasExecutionContext) {
        return;
    }

    $heuristics = [
        [
            'id' => 'BUILTIN_OPENSSL_DECRYPT_EVAL_001',
            'severity' => 'critical',
            'pattern' => '/openssl_decrypt\s*\([\s\S]{0,1200}\beval\s*\(/i',
            'reason' => 'Payload is decrypted with openssl_decrypt() and then executed.',
        ],
        [
            'id' => 'BUILTIN_EVAL_VARIABLE_001',
            'severity' => 'critical',
            'pattern' => '/\beval\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\)/i',
            'reason' => 'eval() executes a variable payload.',
        ],
        [
            'id' => 'BUILTIN_EVAL_BASE64_PAYLOAD_001',
            'severity' => 'critical',
            // Malware often inserts /* junk */ comments between eval, (, and base64_decode
            // to evade simple signatures. Allow comments/whitespace between each token.
            'pattern' => '/\beval\s*(?:\/\*[\s\S]*?\*\/\s*)*\(\s*(?:\/\*[\s\S]*?\*\/\s*)*\bbase64_decode\s*(?:\/\*[\s\S]*?\*\/\s*)*\(/i',
            'reason' => 'Base64-decoded payload is passed directly to eval(), including comment-obfuscated variants.',
        ],
        [
            'id' => 'BUILTIN_HUGE_BASE64_STRING_001',
            'severity' => 'high',
            'pattern' => '/[\'"][A-Za-z0-9+\/]{2000,}={0,2}[\'"]/',
            'reason' => 'Huge base64-like string literal found.',
            'requires_php_or_execution_context' => true,
        ],
        [
            'id' => 'BUILTIN_CHR_DYNAMIC_FUNCTION_001',
            'severity' => 'high',
            'pattern' => '/foreach\s*\([\s\S]{0,400}chr\s*\([\s\S]{0,500}\$[A-Za-z_][A-Za-z0-9_]*\s*\(/i',
            'reason' => 'Function name appears to be assembled with chr() and called dynamically.',
        ],
        [
            'id' => 'BUILTIN_COOKIE_STRROT13_BASE64_DROPPER_001',
            'severity' => 'critical',
            'anchors' => ['$_COOKIE', 'base64_decode', 'str_rot13'],
            'pattern' => '/\$_COOKIE.{0,1200}base64_decode\s*\(\s*str_rot13\s*\(.{0,1200}(tempnam|fopen|fputs|require_once)/is',
            'reason' => 'Cookie-supplied payload is str_rot13/base64 decoded, written to a temp file, and loaded.',
        ],
        [
            'id' => 'BUILTIN_AUTOLOAD_TEMP_REQUIRE_001',
            'severity' => 'critical',
            'anchors' => ['spl_autoload_register', 'tempnam', 'require_once'],
            'pattern' => '/spl_autoload_register\s*\(.{0,1500}tempnam\s*\(.{0,1500}require_once\s*\(/is',
            'reason' => 'Autoload callback writes or loads a temporary PHP payload.',
        ],
        [
            'id' => 'BUILTIN_HEX_PHP_TAG_DROPPER_001',
            'severity' => 'high',
            'pattern' => '/\\\\x3c\\\\x3f\\\\x70\\\\x68p/i',
            'reason' => 'Hex-encoded PHP opening tag used in a dropper.',
        ],
        [
            'id' => 'BUILTIN_COOKIE_NUMERIC_INDEX_GATE_001',
            'severity' => 'medium',
            'pattern' => '/isset\s*\(\s*\$_COOKIE\s*\[\s*\d+\s*[-+]\s*\d+\s*\]\s*\)[\s\S]{0,400}isset\s*\(\s*\$_COOKIE\s*\[\s*\d+\s*[-+]\s*\d+\s*\]/i',
            'reason' => 'Multiple obfuscated numeric cookie-index gates.',
        ],
        [
            'id' => 'BUILTIN_WP_TIMESTOMP_SELF_DELETE_001',
            'severity' => 'critical',
            'anchors' => ['filemtime', 'index.php', 'touch', 'updateFileDates', 'wp-content/', 'STATUS|OK', 'unlink', '__FILE__'],
            'pattern' => '/filemtime\s*\(.{0,200}index\.php|unlink\s*\(\s*__FILE__\s*\)/is',
            'reason' => 'Self-deleting WordPress timestomper resets plugin/theme file dates to hide recently changed files.',
        ],
        [
            'id' => 'BUILTIN_GALEX_REQUEST_COMMAND_SHELL_001',
            'severity' => 'critical',
            'anchors' => ['$_REQUEST', '[S]', '[E]'],
            'pattern' => '/(?=.*\$_REQUEST\s*\[\s*[\'\"]px[\'\"]\s*\])(?=.*\$_REQUEST\s*\[\s*[\'\"](?:b|c)[\'\"]\s*\])(?=.*(?:system|passthru|exec|shell_exec|popen)\s*\()/is',
            'reason' => 'Request-key-gated command shell executes attacker-supplied commands and wraps output in [S]/[E] markers.',
        ],
    ];

    foreach ($heuristics as $rule) {
        if (!empty($rule['requires_php_or_execution_context']) && !$hasPhpOpenTag && !$hasExecutionContext && !$isPhpLike) {
            continue;
        }
        foreach (($rule['anchors'] ?? []) as $anchor) {
            if (stripos($data, $anchor) === false) {
                continue 2;
            }
        }
        $builtinMatches = null;
        if (warden_preg_match($rule['pattern'], $data, $builtinMatches, 0, 0, [
            'rule_id' => $rule['id'],
            'path' => $rel,
        ]) === 1) {
            add_finding([
                'severity' => $rule['severity'],
                'type' => 'builtin_malware_heuristic',
                'rule_id' => $rule['id'],
                'path' => $path,
                'relative_path' => $rel,
                'reason' => $rule['reason'],
                'hashes' => $hashes,
                'recommended_action' => 'Inspect code and quarantine if malicious.',
            ], true);

            // An automatic quarantine may have moved the file. Stop processing the
            // already-loaded contents so we do not emit duplicate post-quarantine hits.
            if (!is_file($path)) {
                break;
            }
        }
    }
}

function has_php_open_tag(string $data): bool {
    return strpos($data, '<?') !== false && warden_preg_match('/<\?(php|=|\s)/i', $data) === 1;
}

function has_php_only_execution_marker(string $data): bool {
    foreach (['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', 'openssl_decrypt(', 'gzinflate(', 'str_rot13(', 'base64_decode(', 'shell_exec(', 'passthru(', 'preg_replace('] as $needle) {
        if (stripos($data, $needle) !== false) {
            return true;
        }
    }
    return false;
}

function is_php_like_extension(string $ext): bool {
    return in_array($ext, ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'inc'], true);
}

function add_finding(array $finding, bool $quarantineCandidate = false): void {
    global $state;

    $severity = strtolower($finding['severity'] ?? 'medium');
    $finding['id'] = finding_id($finding);
    $finding['created_at'] = gmdate('c');
    $finding['action_taken'] = null;
    $state['findings'][] = $finding;

    if (isset($state['summary'][$severity])) {
        $state['summary'][$severity]++;
    }

    $ruleLabel = !empty($finding['rule_id']) ? ' [' . $finding['rule_id'] . ']' : '';
    say("[{$severity}] {$finding['type']}{$ruleLabel}: {$finding['relative_path']}");

    $fileAction = $finding['file_action'] ?? true;

    // Explicit automatic quarantine happens before any interactive prompt.
    if ($fileAction && maybe_auto_quarantine_malware_finding($finding)) {
        return;
    }
    if ($fileAction && maybe_auto_quarantine_extra_core_finding($finding)) {
        return;
    }

    if ($fileAction && ($quarantineCandidate || in_array($severity, ['critical', 'high'], true))) {
        maybe_interactive_action($finding, $quarantineCandidate);
    }
}

function finding_id(array $finding): string {
    $basis = implode('|', [
        $finding['type'] ?? '',
        $finding['relative_path'] ?? '',
        $finding['rule_id'] ?? '',
        $finding['hashes']['sha256'] ?? '',
    ]);
    return substr(hash('sha256', $basis), 0, 16);
}

function maybe_interactive_action(array $finding, bool $quarantineCandidate): void {
    global $apply, $interactive, $nonInteractive, $quarantineDir, $handledInteractivePaths, $quarantineExtraAuto, $quarantineExtraCoreAuto;

    // When automatic quarantine is explicitly enabled, extra plugin/theme files
    // are handled immediately after the finding is recorded. Do not prompt first.
    if ($quarantineExtraAuto && $apply && $quarantineDir
        && in_array((string)($finding['type'] ?? ''), ['extra_plugin_file', 'extra_theme_file'], true)) {
        return;
    }

    if ($quarantineExtraCoreAuto && $apply && $quarantineDir
        && (string)($finding['type'] ?? '') === 'extra_core_file') {
        return;
    }

    if (!$apply) {
        return;
    }
    if ($nonInteractive) {
        return;
    }
    if (!$interactive) {
        return;
    }

    $pathKey = $finding['path'] ?? $finding['relative_path'] ?? null;
    if ($pathKey && isset($handledInteractivePaths[$pathKey])) {
        return;
    }
    if ($pathKey) {
        $handledInteractivePaths[$pathKey] = true;
    }
    $canRepair = !empty($finding['repair']) && is_array($finding['repair']);

    while (true) {
        echo PHP_EOL;
        echo "[ACTION] {$finding['severity']} {$finding['type']}: {$finding['relative_path']}" . PHP_EOL;
        echo "Reason: {$finding['reason']}" . PHP_EOL;
        print_finding_rule_details($finding);
        echo "  V = view preview/details" . PHP_EOL;
        if ($canRepair) {
            echo "  R = replace from clean package/ZIP" . PHP_EOL;
        }
        if ($quarantineDir) {
            echo "  Q = quarantine/move file" . PHP_EOL;
        }
        echo "  D = delete permanently" . PHP_EOL;
        echo "  A = allowlist this file hash for this site" . PHP_EOL;
        echo "  S = skip/leave as-is" . PHP_EOL;
        echo "Choice [V";
        if ($canRepair) {
            echo "/R";
        }
        if ($quarantineDir) {
            echo "/Q";
        }
        echo "/D/A/S]: ";

        $choice = strtoupper(trim((string)fgets(STDIN)));

        if ($choice === 'V') {
            preview_finding_file($finding);
            continue;
        }
        if ($choice === 'R' && $canRepair) {
            repair_finding_file($finding);
            return;
        }
        if ($choice === 'Q' && $quarantineDir) {
            quarantine_file($finding);
            return;
        }
        if ($choice === 'D') {
            delete_finding_file($finding);
            return;
        }
        if ($choice === 'A') {
            allowlist_finding_hash($finding);
            return;
        }
        if ($choice === 'S' || $choice === '') {
            say("[SKIP] Left unchanged: {$finding['relative_path']}", true);
            return;
        }

        echo "Invalid option." . PHP_EOL;
    }
}


function trusted_auto_quarantine_rule_ids(): array {
    return [
        // High-confidence hidden WordPress administrator persistence family.
        // These IDs must be reviewed before being added here. Merely marking an
        // external/community rule CRITICAL is intentionally not sufficient.
        'PHP_WPHIDDENBOT_PERSISTENCE_001',
        'PHP_WPHIDDENBOT_HIDE_USER_003',
        'PHP_AXIL_QUERY_PARENT_UPLOAD_BACKDOOR_001',
        'PHP_FRAGMENTED_SELF_TAIL_GZIP_EVAL_001',
        'PHP_FRAGMENTED_ROT13_GZINFLATE_EVAL_001',
        'PHP_INDEXED_STRING_TABLE_GOTO_REMOTE_LOADER_001',
        'PHP_TRIPLE_MD5_POST_GZIP_DROPPER_001',
        'PHP_LEAFMAILER_FAMILY_001',
        'PHP_LEAFMAILER_PASSWORD_GATE_001',
        'PHP_WP_SYSTEMATIZATION_GOVERNMENT_HIDDEN_PLUGIN_001',
        'PHP_COOKIE_INDEXED_HEX2BIN_INCLUDE_LOADER_001',
    ];
}

function trusted_builtin_auto_quarantine_rule_ids(): array {
    return [
        // Locally reviewed, high-confidence execution/persistence signatures.
        // New builtin_malware_heuristic rules are report-only until explicitly
        // reviewed and added here.
        'BUILTIN_OPENSSL_DECRYPT_EVAL_001',
        // BUILTIN_EVAL_VARIABLE_001 intentionally remains report-only. Some
        // legitimate plugins generate constrained class declarations with
        // eval($code), so that broad signal is unsafe for unattended action.
        'BUILTIN_EVAL_BASE64_PAYLOAD_001',
        'BUILTIN_COOKIE_STRROT13_BASE64_DROPPER_001',
        'BUILTIN_AUTOLOAD_TEMP_REQUIRE_001',
        'BUILTIN_WP_TIMESTOMP_SELF_DELETE_001',
        'BUILTIN_GALEX_REQUEST_COMMAND_SHELL_001',
    ];
}

function maybe_auto_quarantine_malware_finding(array $finding): bool {
    global $apply, $quarantineDir, $quarantineMalwareAuto;

    if ($quarantineMalwareAuto === false || !$apply || !$quarantineDir) {
        return false;
    }

    $type = (string)($finding['type'] ?? '');
    $ruleId = (string)($finding['rule_id'] ?? '');
    $severity = strtolower((string)($finding['severity'] ?? 'medium'));

    if (!in_array($severity, ['critical', 'high'], true)) {
        return false;
    }

    $src = $finding['path'] ?? null;
    if (!$src || !is_file($src)) {
        return false;
    }

    if ($type === 'malicious_upload_bundle_directory'
        && $ruleId === 'BUILTIN_AXIL_UPLOAD_BUNDLE_001') {
        $finding['id'] = finding_id($finding);
        say(
            "[AUTO-QUARANTINE-UPLOAD-BUNDLE] {$finding['relative_path']} " .
            "[$ruleId] - quarantining entire malware bundle directory",
            true
        );
        return quarantine_upload_bundle_directory_for_finding($finding);
    }

    if ($type === 'malicious_plugin_directory' && in_array($ruleId, [
        'BUILTIN_WP2SHELL_PLUGIN_DIR_001',
        'BUILTIN_GALEX_WEBSHELL_PLUGIN_DIR_001',
        'BUILTIN_RANDOMIZED_PROTECT_UPLOADS_PLUGIN_001',
    ], true)) {
        $finding['id'] = finding_id($finding);
        say(
            "[AUTO-QUARANTINE-MALICIOUS-PLUGIN] {$finding['relative_path']} " .
            "[$ruleId] - quarantining containing plugin directory",
            true
        );
        return quarantine_plugin_directory_for_finding($finding);
    }

    if ($type === 'builtin_malware_heuristic'
        && $ruleId === 'BUILTIN_GALEX_REQUEST_COMMAND_SHELL_001'
        && in_array($ruleId, trusted_builtin_auto_quarantine_rule_ids(), true)
        && warden_preg_match('#^wp-content/plugins/[^/]+/#', normalize_relative((string)($finding['relative_path'] ?? ''))) === 1) {
        $finding['id'] = finding_id($finding);
        say(
            "[AUTO-QUARANTINE-GALEX-SHELL] {$finding['relative_path']} " .
            "[$ruleId] - quarantining containing plugin directory",
            true
        );
        return quarantine_plugin_directory_for_finding($finding);
    }

    /*
     * External/community php_rule_match findings normally remain report-only:
     * a broad third-party regex must never be able to remove legitimate code
     * just because it is marked HIGH/CRITICAL.
     *
     * A very small explicit allowlist of locally-reviewed, high-confidence rule
     * IDs may auto-quarantine. For the WPHIDDENBOT persistence family we
     * quarantine the entire containing plugin directory, because leaving another
     * loader/file in that plugin could recreate the hidden administrator.
     */
    if ($type === 'php_rule_match') {
        if (!in_array($ruleId, trusted_auto_quarantine_rule_ids(), true)) {
            return false;
        }

        $finding['id'] = finding_id($finding);

        if (trusted_rule_should_quarantine_plugin_directory($finding)) {
            say(
                "[AUTO-QUARANTINE-TRUSTED-RULE] {$finding['relative_path']} " .
                "[$ruleId] - quarantining containing plugin directory",
                true
            );
            return quarantine_plugin_directory_for_finding($finding);
        }

        // Fail safely if the trusted rule somehow matched outside a normal plugin
        // directory: quarantine only the matched file rather than guessing a wider
        // directory boundary.
        say(
            "[AUTO-QUARANTINE-TRUSTED-RULE] {$finding['relative_path']} " .
            "[$ruleId] - quarantining matched file",
            true
        );
        quarantine_file($finding);
        return !is_file($src);
    }

    /*
     * Existing built-in, high-confidence automatic malware quarantine.
     *
     * A PHP opening tag in a non-PHP file is useful review evidence, but is not
     * sufficient for unattended removal. CodeMirror fixtures, vendor docs and
     * README examples legitimately contain PHP snippets. Stronger built-in
     * execution heuristics are emitted separately and remain eligible here.
     */
    if ($type === 'builtin_malware_heuristic'
        && !in_array($ruleId, trusted_builtin_auto_quarantine_rule_ids(), true)) {
        return false;
    }
    if (!in_array($type, ['builtin_malware_heuristic', 'executable_in_uploads'], true)) {
        return false;
    }

    $finding['id'] = finding_id($finding);
    say("[AUTO-QUARANTINE-MALWARE] {$finding['relative_path']} ({$type}/{$severity})", true);
    quarantine_file($finding);

    return !is_file($src);
}

function trusted_rule_should_quarantine_plugin_directory(array $finding): bool {
    $ruleId = (string)($finding['rule_id'] ?? '');
    if (!in_array($ruleId, [
        'PHP_WPHIDDENBOT_PERSISTENCE_001',
        'PHP_WPHIDDENBOT_HIDE_USER_003',
    ], true)) {
        return false;
    }

    $rel = normalize_relative((string)($finding['relative_path'] ?? ''));
    return warden_preg_match('#^wp-content/plugins/[^/]+/#', $rel) === 1;
}

function quarantine_upload_bundle_directory_for_finding(array $finding): bool {
    global $quarantineDir, $state;

    $rel = normalize_relative((string)($finding['relative_path'] ?? ''));
    $dir = normalize_path((string)($finding['directory_path'] ?? ''));
    if (warden_preg_match('#^wp-content/uploads/([a-z0-9]{6,20})/$#i', $rel, $m) !== 1
        || warden_preg_match('/^[0-9]{4}$/', $m[1]) === 1
        || !is_dir($dir) || is_link($dir)) {
        return false;
    }

    $marker = '/wp-content/uploads/' . $m[1];
    if (substr($dir, -strlen($marker)) !== $marker) {
        return false;
    }

    $dest = rtrim(normalize_path($quarantineDir), '/') . '/wp-content/uploads/' . $m[1];
    if (file_exists($dest)) {
        $dest .= '.quarantine-' . gmdate('Ymd-His') . '-' . getmypid();
    }
    if (!is_dir(dirname($dest))
        && !@mkdir(dirname($dest), 0755, true)
        && !is_dir(dirname($dest))) {
        say("[QUARANTINE-FAIL] Could not create quarantine directory: " . dirname($dest), true);
        return false;
    }
    if (!@rename($dir, $dest)) {
        say("[QUARANTINE-FAIL] Could not move uploads bundle $rel to $dest", true);
        return false;
    }

    $action = [
        'type' => 'quarantine_upload_bundle_directory',
        'finding_id' => $finding['id'],
        'rule_id' => (string)$finding['rule_id'],
        'from' => $dir,
        'to' => $dest,
        'at' => gmdate('c'),
    ];
    $state['actions'][] = $action;
    $state['summary']['actions_taken']++;
    write_quarantine_manifest($action, $finding);
    say("Quarantined uploads malware bundle: $rel", true);
    return !is_dir($dir);
}

function quarantine_plugin_directory_for_finding(array $finding): bool {
    global $quarantineDir, $state;

    $srcFile = normalize_path((string)($finding['path'] ?? ''));
    $relFile = normalize_relative((string)($finding['relative_path'] ?? ''));

    if ($srcFile === '' || $relFile === '' || !is_file($srcFile)) {
        return false;
    }

    if (!warden_preg_match('#^(wp-content/plugins/([^/]+))/#', $relFile, $m)) {
        return false;
    }

    $pluginRel = $m[1];
    $pluginSlug = $m[2];

    // Derive the plugin directory from the matched file/path without trusting
    // arbitrary rule-provided paths outside wp-content/plugins/<slug>/.
    $marker = '/wp-content/plugins/' . $pluginSlug . '/';
    $normalizedSrc = normalize_path($srcFile);
    $pos = strpos($normalizedSrc, $marker);
    if ($pos === false) {
        return false;
    }

    $pluginDir = substr(
        $normalizedSrc,
        0,
        $pos + strlen('/wp-content/plugins/' . $pluginSlug)
    );

    if (!is_dir($pluginDir) || is_link($pluginDir)) {
        return false;
    }

    $dest = rtrim($quarantineDir, '/') . '/' . $pluginRel;

    // Preserve an earlier quarantine rather than overwriting it.
    if (file_exists($dest)) {
        $dest .= '.quarantine-' . gmdate('Ymd-His') . '-' . getmypid();
    }

    $destParent = dirname($dest);
    if (!is_dir($destParent)
        && !@mkdir($destParent, 0755, true)
        && !is_dir($destParent)) {
        say("[QUARANTINE-FAIL] Could not create quarantine directory: $destParent", true);
        return false;
    }

    if (!@rename($pluginDir, $dest)) {
        say(
            "[QUARANTINE-FAIL] Could not move plugin directory $pluginRel to $dest",
            true
        );
        return false;
    }

    $finding['id'] = $finding['id'] ?? finding_id($finding);
    $action = [
        'type' => 'quarantine_plugin_directory',
        'finding_id' => $finding['id'],
        'rule_id' => (string)($finding['rule_id'] ?? ''),
        'plugin' => $pluginSlug,
        'from' => $pluginDir,
        'to' => $dest,
        'at' => gmdate('c'),
    ];

    $state['actions'][] = $action;
    $state['summary']['actions_taken']++;

    // Reuse the normal manifest writer so there is a persistent forensic record
    // associated with the triggering finding.
    write_quarantine_manifest($action, $finding);

    say("Quarantined plugin directory: $pluginRel", true);
    return !is_dir($pluginDir);
}

function maybe_auto_quarantine_extra_core_finding(array $finding): bool {
    global $apply, $quarantineDir, $quarantineExtraCoreAuto;

    if (!$quarantineExtraCoreAuto || !$apply || !$quarantineDir) {
        return false;
    }

    if ((string)($finding['type'] ?? '') !== 'extra_core_file') {
        return false;
    }

    $severity = strtolower((string)($finding['severity'] ?? 'critical'));
    if (!in_array($severity, ['critical', 'high'], true)) {
        return false;
    }

    $src = $finding['path'] ?? null;
    if (!$src || !is_file($src)) {
        return false;
    }

    $finding['id'] = finding_id($finding);
    say("[AUTO-QUARANTINE-EXTRA-CORE] {$finding['relative_path']} ({$severity})", true);
    quarantine_file($finding);

    return !is_file($src);
}

function maybe_auto_quarantine_extra_file(array $finding): bool {
    global $apply, $quarantineDir, $quarantineExtraAuto;

    if (!$quarantineExtraAuto || !$apply || !$quarantineDir) {
        return false;
    }

    $type = (string)($finding['type'] ?? '');
    if (!in_array($type, ['extra_plugin_file', 'extra_theme_file'], true)) {
        return false;
    }

    $src = $finding['path'] ?? null;
    if (!$src || !is_file($src)) {
        return false;
    }

    // quarantine_file() records the finding id in the manifest/action.
    $finding['id'] = finding_id($finding);
    say("[AUTO-QUARANTINE] {$finding['relative_path']}", true);
    quarantine_file($finding);

    return !is_file($src);
}

function print_finding_rule_details(array $finding): void {
    if (!empty($finding['rule_id'])) {
        echo "Rule: {$finding['rule_id']}" . PHP_EOL;
    }
    if (!empty($finding['line'])) {
        echo "Line: {$finding['line']}" . PHP_EOL;
    }
    if (!empty($finding['rule_pattern'])) {
        echo "Pattern: " . shorten_text((string)$finding['rule_pattern'], 180) . PHP_EOL;
    }
    if (!empty($finding['matched_text'])) {
        echo "Matched: " . $finding['matched_text'] . PHP_EOL;
    }
}

function shorten_text(string $text, int $limit): string {
    $text = preg_replace('/\s+/', ' ', trim($text));
    if (!is_string($text) || strlen($text) <= $limit) {
        return is_string($text) ? $text : '';
    }
    return substr($text, 0, max(0, $limit - 3)) . '...';
}

function quarantine_file(array $finding): void {
    global $quarantineDir, $state;

    $src = $finding['path'] ?? null;
    $rel = $finding['relative_path'] ?? basename((string)$src);
    if (!$src || !is_file($src)) {
        return;
    }

    $dest = rtrim($quarantineDir, '/') . '/' . $rel;
    $dir = dirname($dest);
    if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
        say("[QUARANTINE-FAIL] Could not create quarantine directory: $dir", true);
        return;
    }

    if (@rename($src, $dest)) {
        $action = [
            'type' => 'quarantine',
            'finding_id' => $finding['id'],
            'from' => $src,
            'to' => $dest,
            'at' => gmdate('c'),
        ];
        $state['actions'][] = $action;
        $state['summary']['actions_taken']++;
        write_quarantine_manifest($action, $finding);
        say("Quarantined: $rel", true);
    } else {
        say("[QUARANTINE-FAIL] Could not move $rel to $dest", true);
    }
}

function repair_finding_file(array $finding): void {
    $repair = $finding['repair'] ?? null;
    $src = $finding['path'] ?? null;
    $rel = $finding['relative_path'] ?? basename((string)$src);
    if (!$src || !is_file($src) || !is_array($repair)) {
        say("[REPAIR-SKIP] File no longer exists or repair details are missing: $rel", true);
        return;
    }

    $package = repair_package_info(
        (string)($repair['type'] ?? ''),
        $repair['slug'] ?? null,
        $repair['version'] ?? null,
        $repair['clean_zip'] ?? null
    );
    if (!$package) {
        say("[REPAIR-SKIP] No clean package source available for $rel", true);
        return;
    }

    $expected = $repair['expected'] ?? $finding['expected'] ?? null;
    if (!is_array($expected)) {
        say("[REPAIR-SKIP] No expected checksum available for $rel", true);
        return;
    }

    repair_from_package($package, $rel, $src, $expected);
}

function delete_finding_file(array $finding): void {
    global $state;

    $src = $finding['path'] ?? null;
    $rel = $finding['relative_path'] ?? basename((string)$src);
    if (!$src || !is_file($src)) {
        say("[DELETE-SKIP] File no longer exists: $rel", true);
        return;
    }

    if (@unlink($src)) {
        $action = [
            'type' => 'delete',
            'finding_id' => $finding['id'],
            'path' => $src,
            'relative_path' => $rel,
            'at' => gmdate('c'),
        ];
        $state['actions'][] = $action;
        $state['summary']['actions_taken']++;
        say("[DELETED] $rel", true);
        return;
    }

    say("[DELETE-FAIL] Could not delete: $rel", true);
}

function allowlist_finding_hash(array $finding): void {
    global $intelDir, $siteId;

    $hashes = $finding['hashes'] ?? [];
    if (empty($hashes['sha256']) && empty($hashes['md5'])) {
        say("[ALLOWLIST-SKIP] No hash available for {$finding['relative_path']}", true);
        return;
    }

    $siteFile = rtrim($intelDir, '/') . "/whitelists/sites/$siteId.json";
    $site = is_file($siteFile) ? json_file($siteFile) : [
        'schema' => 'wp-warden.whitelist.site.v1',
        'site_id' => $siteId,
        'file_hashes' => [],
        'processes' => [],
        'crons' => [],
    ];

    if (!isset($site['file_hashes']) || !is_array($site['file_hashes'])) {
        $site['file_hashes'] = [];
    }

    $entry = [
        'sha256' => $hashes['sha256'] ?? null,
        'md5' => $hashes['md5'] ?? null,
        'path_hint' => $finding['relative_path'] ?? null,
        'reason' => 'Approved interactively during scan',
        'created_at' => gmdate('c'),
    ];
    $site['file_hashes'][] = $entry;

    $dir = dirname($siteFile);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    file_put_contents($siteFile, json_encode($site, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    say("[ALLOWLISTED] Added hash to $siteFile", true);
}

function preview_finding_file(array $finding): void {
    $path = $finding['path'] ?? null;
    $rel = $finding['relative_path'] ?? basename((string)$path);
    if (!$path || !is_file($path)) {
        say("[PREVIEW-SKIP] File no longer exists: $rel", true);
        return;
    }

    $size = filesize($path);
    $magic = sniff_magic($path) ?: 'text/unknown';
    echo PHP_EOL . "[PREVIEW] $rel" . PHP_EOL;
    echo "Size: $size bytes" . PHP_EOL;
    echo "Magic: $magic" . PHP_EOL;
    echo "SHA256: " . ($finding['hashes']['sha256'] ?? 'unknown') . PHP_EOL;

    $data = @file_get_contents($path, false, null, 0, 4096);
    if ($data === false) {
        echo "[Could not read preview]" . PHP_EOL;
        return;
    }

    if (strpos($data, "\0") !== false) {
        echo "[Binary preview: first bytes]" . PHP_EOL;
        echo trim(chunk_split(bin2hex(substr($data, 0, 128)), 2, ' ')) . PHP_EOL;
        return;
    }

    echo "---- first 80 lines / 4096 bytes ----" . PHP_EOL;
    $lines = preg_split('/\r?\n/', $data);
    foreach (array_slice($lines, 0, 80) as $idx => $line) {
        printf("%4d | %s\n", $idx + 1, $line);
    }
    echo "---- end preview ----" . PHP_EOL;
}

function write_quarantine_manifest(array $action, array $finding): void {
    global $quarantineDir;
    $manifest = rtrim($quarantineDir, '/') . '/manifest.jsonl';
    file_put_contents($manifest, json_encode([
        'action' => $action,
        'finding' => $finding,
    ], JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function relative_path(string $root, string $path): string {
    $rootReal = realpath($root) ?: $root;
    $pathReal = realpath($path) ?: $path;
    $rootNorm = normalize_path($rootReal);
    $pathNorm = normalize_path($pathReal);
    if (strpos($pathNorm, $rootNorm) === 0) {
        return normalize_relative(substr($pathNorm, strlen($rootNorm)));
    }
    return normalize_relative($pathNorm);
}

function fast_relative_path(string $rootNorm, string $path): string {
    $pathNorm = normalize_path($path);
    $rootNorm = rtrim(normalize_path($rootNorm), '/');
    if (strpos($pathNorm, $rootNorm . '/') === 0) {
        return normalize_relative(substr($pathNorm, strlen($rootNorm) + 1));
    }
    if ($pathNorm === $rootNorm) {
        return '';
    }
    return normalize_relative($pathNorm);
}

function normalize_relative(string $path): string {
    return ltrim(normalize_path($path), '/');
}

function looks_like_core_path(string $rel): bool {
    if (warden_preg_match('#^(wp-admin/|wp-includes/)#', $rel)) {
        return true;
    }
    return in_array($rel, [
        'index.php',
        'wp-login.php',
        'wp-settings.php',
        'wp-config-sample.php',
        'wp-comments-post.php',
        'xmlrpc.php',
        'wp-cron.php',
        'wp-links-opml.php',
        'wp-mail.php',
        'wp-signup.php',
        'wp-trackback.php',
        'license.txt',
        'readme.html',
    ], true);
}

function scan_vulnerabilities(string $wpRoot, ?string $wpVersion, string $intelDir, string $wordfenceApiKeyFile): array {
    $out = [
        'enabled'=>true,
        'status'=>'CLEAR',
        'sources'=>[],
        'wordpress'=>[],
        'composer'=>[],
        'errors'=>[],
        'summary'=>['total'=>0,'wordpress'=>0,'composer'=>0,'unpatched'=>0],
    ];

    /*
     * Wordfence's scanner feed is intentionally never loaded wholesale into
     * PHP memory. The full response is streamed to a shared on-disk cache, then
     * jq filters it to the components installed on this site. PHP consumes the
     * small filtered result one JSON record at a time.
     */
    try {
        $wfKey = trim((string)getenv('WORDFENCE_INTEL_API_KEY'));
        if ($wfKey === '' && is_file($wordfenceApiKeyFile)) {
            $wfKey = trim((string)@file_get_contents($wordfenceApiKeyFile));
        }

        if ($wfKey !== '') {
            $feedPath = ensure_wordfence_scanner_feed_file($intelDir, $wfKey);
            if ($feedPath !== null) {
                $matchResult = match_wordfence_vulnerabilities_from_file(
                    $wpRoot,
                    $wpVersion,
                    $feedPath,
                    $intelDir
                );

                if (!empty($matchResult['available'])) {
                    $out['sources']['wordfence'] = [
                        'available'=>true,
                        'feed'=>'Wordfence Intelligence V3 scanner',
                        'cache_file'=>$feedPath,
                        'mode'=>'streamed-feed + jq component filter',
                    ];
                    $out['wordpress'] = $matchResult['vulnerabilities'];
                } else {
                    $out['sources']['wordfence'] = [
                        'available'=>false,
                        'reason'=>$matchResult['reason'] ?? 'component filtering failed',
                    ];
                    $out['errors'][] = 'Wordfence component filtering failed: ' .
                        ($matchResult['reason'] ?? 'unknown error');
                }
            } else {
                $out['sources']['wordfence'] = [
                    'available'=>false,
                    'reason'=>'feed download/cache unavailable',
                ];
                $out['errors'][] = 'Wordfence Intelligence feed download/cache unavailable.';
            }
        } else {
            $out['sources']['wordfence'] = [
                'available'=>false,
                'reason'=>'API key not configured',
                'key_file'=>$wordfenceApiKeyFile,
            ];
        }
    } catch (Throwable $e) {
        $out['sources']['wordfence'] = [
            'available'=>false,
            'reason'=>'scanner exception',
        ];
        $out['errors'][] = 'Wordfence scanner exception: ' . $e->getMessage();
    }

    try {
        $composer = scan_composer_vulnerabilities_osv($wpRoot);
        $out['composer'] = $composer['vulnerabilities'];
        $out['sources']['osv'] = $composer['source'];
        foreach ($composer['errors'] as $err) {
            $out['errors'][] = $err;
        }
    } catch (Throwable $e) {
        $out['sources']['osv'] = [
            'available'=>false,
            'name'=>'OSV.dev',
            'reason'=>'scanner exception',
        ];
        $out['errors'][] = 'OSV scanner exception: ' . $e->getMessage();
    }

    $out['summary']['wordpress'] = count($out['wordpress']);
    $out['summary']['composer'] = count($out['composer']);
    $out['summary']['total'] = $out['summary']['wordpress'] + $out['summary']['composer'];

    foreach ($out['wordpress'] as $v) {
        if (array_key_exists('patched', $v) && $v['patched'] === false) {
            $out['summary']['unpatched']++;
        }
    }

    $out['status'] = $out['summary']['total'] > 0 ? 'ATTENTION' : 'CLEAR';

    $wfAvailable = !empty($out['sources']['wordfence']['available']);
    $osvAvailable = !empty($out['sources']['osv']['available']);
    if (!$wfAvailable && !$osvAvailable) {
        $out['status'] = 'UNKNOWN';
    } elseif (!$wfAvailable) {
        // Composer may be clear while WordPress vulnerability coverage is absent.
        // Do not misrepresent that partial result as a complete CLEAR.
        $out['status'] = $out['summary']['total'] > 0 ? 'ATTENTION' : 'PARTIAL';
    }

    $out['sources']['wordfence_cache'] = wordfence_cache_status($intelDir);

    return $out;
}

function wordfence_cache_dir(string $intelDir): string {
    $dir = rtrim(dirname($intelDir), '/') . '/cache/vulnerabilities';
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    return $dir;
}

function ensure_wordfence_scanner_feed_file(string $intelDir, string $apiKey): ?string {
    $cacheDir = wordfence_cache_dir($intelDir);
    $cache = $cacheDir . '/wordfence-intelligence-v3-scanner.json';
    $stateFile = $cacheDir . '/wordfence-rate-limit.json';
    $lockFile = $cacheDir . '/wordfence-refresh.lock';

    // Vulnerability intelligence does not need per-site freshness. A single
    // feed younger than 24 hours is considered fresh for the entire server.
    $freshTtl = 86400;          // 24 hours
    $staleUsable = 604800;      // 7 days
    $now = time();

    if (is_file($cache) && filesize($cache) > 0) {
        $age = $now - (int)@filemtime($cache);
        if ($age < $freshTtl) {
            return $cache;
        }
    }

    // Honour previous Wordfence rate limiting without making another request.
    $rateState = json_file($stateFile);
    if (is_array($rateState)) {
        $nextAllowed = (int)($rateState['next_allowed_at'] ?? 0);
        if ($nextAllowed > $now) {
            if (is_file($cache) && filesize($cache) > 0) {
                $age = $now - (int)@filemtime($cache);
                say(
                    "Wordfence refresh suppressed until " .
                    gmdate('Y-m-d H:i:s', $nextAllowed) .
                    " UTC due to rate limiting; using cached feed (" .
                    round($age / 3600, 1) . "h old)",
                    true
                );
                return $cache;
            }

            say(
                "WARN: Wordfence refresh suppressed until " .
                gmdate('Y-m-d H:i:s', $nextAllowed) .
                " UTC due to rate limiting; no cached feed is available",
                true
            );
            return null;
        }
    }

    // Prevent concurrent site scans/processes from refreshing the same global
    // feed. Only one process is allowed to contact Wordfence at a time.
    $lockHandle = @fopen($lockFile, 'c+');
    if (!$lockHandle) {
        if (is_file($cache) && filesize($cache) > 0) {
            return $cache;
        }
        return null;
    }

    // Wait briefly for an existing refresh rather than launching another one.
    $gotLock = @flock($lockHandle, LOCK_EX | LOCK_NB);
    if (!$gotLock) {
        $waitUntil = microtime(true) + 15.0;
        do {
            usleep(250000);

            // Another process may have completed the refresh while we waited.
            clearstatcache(true, $cache);
            if (is_file($cache) && filesize($cache) > 0) {
                $age = time() - (int)@filemtime($cache);
                if ($age < $freshTtl) {
                    fclose($lockHandle);
                    return $cache;
                }
            }

            $gotLock = @flock($lockHandle, LOCK_EX | LOCK_NB);
        } while (!$gotLock && microtime(true) < $waitUntil);

        if (!$gotLock) {
            fclose($lockHandle);
            if (is_file($cache) && filesize($cache) > 0) {
                say("Wordfence refresh already in progress; using existing cached feed", true);
                return $cache;
            }
            say("WARN: Wordfence refresh lock busy and no cached feed is available", true);
            return null;
        }
    }

    try {
        // Re-check after acquiring the lock: another process may have refreshed
        // the cache before we obtained the lock.
        clearstatcache(true, $cache);
        if (is_file($cache) && filesize($cache) > 0) {
            $age = time() - (int)@filemtime($cache);
            if ($age < $freshTtl) {
                return $cache;
            }
        }

        // Re-check rate state while holding the lock.
        $rateState = json_file($stateFile);
        if (is_array($rateState)) {
            $nextAllowed = (int)($rateState['next_allowed_at'] ?? 0);
            if ($nextAllowed > time()) {
                if (is_file($cache) && filesize($cache) > 0) {
                    return $cache;
                }
                return null;
            }
        }

        $tmp = $cache . '.tmp-' . getmypid() . '-' . bin2hex(random_bytes(4));
        $headersFile = $cacheDir . '/wordfence-last-headers.txt';
        $errorFile = $cacheDir . '/wordfence-last-error.txt';
        $url = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner';

        say("Refreshing Wordfence Intelligence scanner feed (single shared request)...", true);

        $download = stream_http_to_file_with_status(
            $url,
            $tmp,
            [
                'Authorization: Bearer ' . $apiKey,
                'Accept: application/json',
            ],
            60,
            $headersFile
        );

        $httpCode = (int)($download['http_code'] ?? 0);
        $retryAfter = (int)($download['retry_after'] ?? 0);

        if ($httpCode === 429) {
            @unlink($tmp);

            // If Retry-After is missing, back off for six hours. If present,
            // add a small safety margin to avoid immediately hitting the edge.
            $backoff = $retryAfter > 0 ? $retryAfter + 60 : 21600;
            $nextAllowed = time() + $backoff;

            @file_put_contents(
                $stateFile,
                json_encode([
                    'status'=>'rate_limited',
                    'http_code'=>429,
                    'detected_at'=>gmdate('c'),
                    'retry_after_seconds'=>$retryAfter,
                    'next_allowed_at'=>$nextAllowed,
                    'next_allowed_utc'=>gmdate('c', $nextAllowed),
                ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
                LOCK_EX
            );
            @chmod($stateFile, 0600);

            @file_put_contents(
                $errorFile,
                "HTTP 429 Too Many Requests\n" .
                "Detected: " . gmdate('c') . "\n" .
                "Next allowed: " . gmdate('c', $nextAllowed) . "\n",
                LOCK_EX
            );
            @chmod($errorFile, 0600);

            if (is_file($cache) && filesize($cache) > 0) {
                say(
                    "WARN: Wordfence rate limit reached; using cached feed and suppressing refreshes until " .
                    gmdate('Y-m-d H:i:s', $nextAllowed) . " UTC",
                    true
                );
                return $cache;
            }

            say(
                "WARN: Wordfence rate limit reached; no cached feed available. " .
                "Further Wordfence requests suppressed until " .
                gmdate('Y-m-d H:i:s', $nextAllowed) . " UTC",
                true
            );
            return null;
        }

        if (empty($download['ok'])) {
            @unlink($tmp);

            @file_put_contents(
                $errorFile,
                "Wordfence feed refresh failed\n" .
                "HTTP: {$httpCode}\n" .
                "Detected: " . gmdate('c') . "\n",
                LOCK_EX
            );
            @chmod($errorFile, 0600);

            // Use any cached feed up to seven days old. Older feeds are still
            // safer than claiming CLEAR, but explicitly flag them as stale.
            if (is_file($cache) && filesize($cache) > 0) {
                $age = time() - (int)@filemtime($cache);
                if ($age <= $staleUsable) {
                    say(
                        "WARN: Wordfence refresh failed (HTTP {$httpCode}); using stale cached feed (" .
                        round($age / 3600, 1) . "h old)",
                        true
                    );
                    return $cache;
                }

                say(
                    "WARN: Wordfence refresh failed and cached feed is more than 7 days old",
                    true
                );
                return $cache;
            }

            return null;
        }

        if (!command_exists('jq')) {
            say("WARN: jq is required for memory-safe Wordfence feed processing", true);
            @unlink($tmp);
            if (is_file($cache) && filesize($cache) > 0) {
                return $cache;
            }
            return null;
        }

        // Validate JSON outside PHP memory.
        $cmd = 'jq -e "type == \\"object\\"" ' . escapeshellarg($tmp) . ' >/dev/null 2>&1';
        @exec($cmd, $dummy, $jqCode);
        if ($jqCode !== 0) {
            say("WARN: downloaded Wordfence feed failed JSON validation", true);
            @unlink($tmp);
            if (is_file($cache) && filesize($cache) > 0) {
                return $cache;
            }
            return null;
        }

        @chmod($tmp, 0600);
        if (!@rename($tmp, $cache)) {
            @unlink($tmp);
            if (is_file($cache) && filesize($cache) > 0) {
                return $cache;
            }
            return null;
        }

        // Successful refresh clears any previous backoff/error state.
        @unlink($stateFile);
        @unlink($errorFile);

        say(
            "Wordfence scanner feed cached: " .
            number_format((int)filesize($cache)) . " bytes",
            true
        );

        return $cache;
    } finally {
        @flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }
}

function stream_http_to_file_with_status(
    string $url,
    string $dest,
    array $headers = [],
    int $timeout = 60,
    ?string $headersFile = null
): array {
    global $state;

    $started = microtime(true);
    if (isset($state['timing'])) {
        $state['timing']['http_requests'] =
            (int)($state['timing']['http_requests'] ?? 0) + 1;
    }

    $result = [
        'ok'=>false,
        'http_code'=>0,
        'retry_after'=>0,
        'bytes'=>0,
    ];

    $fh = @fopen($dest, 'wb');
    if (!$fh) {
        return $result;
    }

    $headerHandle = null;
    if ($headersFile !== null) {
        $headerHandle = @fopen($headersFile, 'wb');
        if ($headerHandle) {
            @chmod($headersFile, 0600);
        }
    }

    if (function_exists('curl_init')) {
        $responseHeaders = [];

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_FILE => $fh,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_CONNECTTIMEOUT => min(8, $timeout),
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'WP-Warden/' . WP_WARDEN_VERSION,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_FAILONERROR => false,
            CURLOPT_HEADERFUNCTION => function($ch, $line) use (&$responseHeaders, $headerHandle) {
                if (is_resource($headerHandle)) {
                    @fwrite($headerHandle, $line);
                }
                $trim = trim($line);
                if ($trim !== '' && strpos($trim, ':') !== false) {
                    [$name, $value] = array_map('trim', explode(':', $trim, 2));
                    $responseHeaders[strtolower($name)] = $value;
                }
                return strlen($line);
            },
        ]);

        $curlOk = curl_exec($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        $result['http_code'] = $httpCode;
        $result['ok'] = $curlOk === true && $httpCode >= 200 && $httpCode < 400;

        if (isset($responseHeaders['retry-after'])) {
            $retry = trim((string)$responseHeaders['retry-after']);
            if (ctype_digit($retry)) {
                $result['retry_after'] = (int)$retry;
            } else {
                $ts = strtotime($retry);
                if ($ts !== false && $ts > time()) {
                    $result['retry_after'] = $ts - time();
                }
            }
        }
    } else {
        $headerText = "User-Agent: WP-Warden/" . WP_WARDEN_VERSION . "\r\n";
        foreach ($headers as $h) {
            $headerText .= $h . "\r\n";
        }

        $context = stream_context_create([
            'http'=>[
                'ignore_errors'=>true,
                'timeout'=>$timeout,
                'header'=>$headerText,
            ]
        ]);

        $src = @fopen($url, 'rb', false, $context);
        if ($src) {
            $copied = @stream_copy_to_stream($src, $fh);
            fclose($src);
            $result['bytes'] = is_int($copied) ? $copied : 0;
            $result['ok'] = $result['bytes'] > 0;
        }
    }

    fclose($fh);
    if (is_resource($headerHandle)) {
        fclose($headerHandle);
    }

    clearstatcache(true, $dest);
    if (is_file($dest)) {
        $result['bytes'] = (int)filesize($dest);
    }

    if (!$result['ok'] || !is_file($dest) || $result['bytes'] <= 0) {
        if ($result['http_code'] !== 429) {
            @unlink($dest);
        }
        $result['ok'] = false;
    }

    $elapsed = microtime(true) - $started;
    if (isset($state['timing'])) {
        $state['timing']['http_seconds'] =
            round((float)($state['timing']['http_seconds'] ?? 0) + $elapsed, 3);
        if (!$result['ok']) {
            $state['timing']['http_failures'] =
                (int)($state['timing']['http_failures'] ?? 0) + 1;
        }
    }

    return $result;
}

function command_exists(string $command): bool {
    static $cache = [];
    if (array_key_exists($command, $cache)) {
        return $cache[$command];
    }
    $path = @shell_exec('command -v ' . escapeshellarg($command) . ' 2>/dev/null');
    $cache[$command] = is_string($path) && trim($path) !== '';
    return $cache[$command];
}

function installed_wordpress_components(string $wpRoot, ?string $wpVersion): array {
    $installed = [];

    if ($wpVersion) {
        $installed['core:wordpress'] = [
            'type'=>'core',
            'slug'=>'wordpress',
            'version'=>$wpVersion,
        ];
    }

    foreach (glob("$wpRoot/wp-content/plugins/*", GLOB_ONLYDIR) ?: [] as $path) {
        $slug = strtolower(basename($path));
        if (is_backup_component_directory($slug)) {
            continue;
        }
        $version = detect_plugin_version($path, $slug);
        if ($version) {
            $installed['plugin:' . $slug] = [
                'type'=>'plugin',
                'slug'=>$slug,
                'version'=>$version,
            ];
        }
    }

    foreach (glob("$wpRoot/wp-content/themes/*", GLOB_ONLYDIR) ?: [] as $path) {
        $slug = strtolower(basename($path));
        if (is_backup_component_directory($slug)) {
            continue;
        }
        $version = detect_theme_version($path);
        if ($version) {
            $installed['theme:' . $slug] = [
                'type'=>'theme',
                'slug'=>$slug,
                'version'=>$version,
            ];
        }
    }

    ksort($installed);
    return $installed;
}

function wordfence_filtered_feed_path(
    string $feedPath,
    string $intelDir,
    array $installed
): ?string {
    if (!command_exists('jq')) {
        return null;
    }

    $componentMap = [];
    foreach ($installed as $key => $component) {
        $componentMap[$key] = true;
    }

    $componentJson = json_encode($componentMap, JSON_UNESCAPED_SLASHES);
    if (!is_string($componentJson)) {
        return null;
    }

    $cacheDir = wordfence_cache_dir($intelDir);
    $cacheKey = sha1(
        (string)@filemtime($feedPath) . '|' .
        (string)@filesize($feedPath) . '|' .
        implode('|', array_keys($installed))
    );
    $filtered = $cacheDir . '/wordfence-filter-' . $cacheKey . '.ndjson';

    if (
        is_file($filtered)
        && @filemtime($filtered) >= @filemtime($feedPath)
    ) {
        return $filtered;
    }

    $tmp = $filtered . '.tmp-' . getmypid();

    /*
     * Root feed is an object keyed by vulnerability UUID. Emit only records
     * whose software list contains an installed component. Output NDJSON so
     * PHP can decode one vulnerability at a time.
     */
    $program =
        'to_entries[].value ' .
        '| select((.informational // false) != true) ' .
        '| select(any(.software[]?; ' .
        '    ($components[((.type // "") + ":" + (.slug // ""))] // false) == true' .
        '  ))';

    $cmd =
        'jq -c --argjson components ' . escapeshellarg($componentJson) . ' ' .
        escapeshellarg($program) . ' ' .
        escapeshellarg($feedPath) .
        ' > ' . escapeshellarg($tmp) . ' 2>/dev/null';

    @exec($cmd, $output, $code);

    if ($code !== 0 || !is_file($tmp)) {
        @unlink($tmp);
        return null;
    }

    @chmod($tmp, 0600);
    if (!@rename($tmp, $filtered)) {
        @unlink($tmp);
        return null;
    }

    return $filtered;
}

function match_wordfence_vulnerabilities_from_file(
    string $wpRoot,
    ?string $wpVersion,
    string $feedPath,
    string $intelDir
): array {
    $installed = installed_wordpress_components($wpRoot, $wpVersion);
    if (!$installed) {
        return ['available'=>true, 'vulnerabilities'=>[]];
    }

    $filtered = wordfence_filtered_feed_path(
        $feedPath,
        $intelDir,
        $installed
    );

    if ($filtered === null) {
        return [
            'available'=>false,
            'vulnerabilities'=>[],
            'reason'=>'jq unavailable or feed filtering failed',
        ];
    }

    $fh = @fopen($filtered, 'rb');
    if (!$fh) {
        return [
            'available'=>false,
            'vulnerabilities'=>[],
            'reason'=>'filtered feed could not be opened',
        ];
    }

    $matches = [];

    while (($line = fgets($fh)) !== false) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }

        $record = json_decode($line, true);
        if (!is_array($record) || !empty($record['informational'])) {
            continue;
        }

        foreach (($record['software'] ?? []) as $software) {
            if (!is_array($software)) {
                continue;
            }

            $type = strtolower((string)($software['type'] ?? ''));
            $slug = strtolower((string)($software['slug'] ?? ''));
            $key = $type . ':' . ($type === 'core' ? 'wordpress' : $slug);

            if (!isset($installed[$key])) {
                continue;
            }

            $installedVersion = (string)$installed[$key]['version'];

            if (!wordfence_version_is_affected(
                $installedVersion,
                (array)($software['affected_versions'] ?? [])
            )) {
                continue;
            }

            $notices = [];
            foreach (($record['copyrights'] ?? []) as $copyright) {
                if (is_array($copyright) && !empty($copyright['notice'])) {
                    $notices[] = (string)$copyright['notice'];
                }
            }

            $matches[] = [
                'source'=>'wordfence',
                'id'=>(string)($record['id'] ?? ''),
                'title'=>(string)($record['title'] ?? 'Known WordPress vulnerability'),
                'type'=>$type,
                'slug'=>$type === 'core' ? 'wordpress' : $slug,
                'installed'=>$installedVersion,
                'patched'=>(bool)($software['patched'] ?? false),
                'patched_versions'=>array_values(
                    array_filter(
                        (array)($software['patched_versions'] ?? []),
                        'is_string'
                    )
                ),
                'published'=>$record['published'] ?? null,
                'references'=>array_slice(
                    array_values(
                        array_filter(
                            (array)($record['references'] ?? []),
                            'is_string'
                        )
                    ),
                    0,
                    3
                ),
                'copyright_notices'=>$notices,
            ];
        }
    }

    fclose($fh);

    // Deduplicate a vulnerability/software pair in case a feed record repeats it.
    $dedupe = [];
    foreach ($matches as $match) {
        $key =
            ($match['id'] ?? '') . '|' .
            ($match['type'] ?? '') . '|' .
            ($match['slug'] ?? '') . '|' .
            ($match['installed'] ?? '');
        $dedupe[$key] = $match;
    }

    $matches = array_values($dedupe);

    usort($matches, function($a, $b) {
        return [
            (string)($a['type'] ?? ''),
            (string)($a['slug'] ?? ''),
            (string)($a['title'] ?? ''),
        ] <=> [
            (string)($b['type'] ?? ''),
            (string)($b['slug'] ?? ''),
            (string)($b['title'] ?? ''),
        ];
    });

    return [
        'available'=>true,
        'vulnerabilities'=>$matches,
        'filtered_file'=>$filtered,
    ];
}

function http_get_body_with_headers(string $url, array $headers = [], int $timeout = 15) {
    global $state;
    $started = microtime(true);
    if (isset($state['timing'])) {
        $state['timing']['http_requests'] = (int)($state['timing']['http_requests'] ?? 0) + 1;
    }

    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL=>$url,
            CURLOPT_RETURNTRANSFER=>true,
            CURLOPT_FOLLOWLOCATION=>true,
            CURLOPT_CONNECTTIMEOUT=>min(5,$timeout),
            CURLOPT_TIMEOUT=>$timeout,
            CURLOPT_SSL_VERIFYPEER=>true,
            CURLOPT_SSL_VERIFYHOST=>2,
            CURLOPT_USERAGENT=>'WP-Warden/' . WP_WARDEN_VERSION,
            CURLOPT_HTTPHEADER=>$headers,
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if (!(is_string($body) && $body !== '' && $code >= 200 && $code < 400)) {
            $body = false;
        }
    } else {
        $headerText =
            "User-Agent: WP-Warden/" . WP_WARDEN_VERSION . "\r\n" .
            implode("\r\n", $headers) . "\r\n";
        $ctx = stream_context_create([
            'http'=>[
                'ignore_errors'=>true,
                'timeout'=>$timeout,
                'header'=>$headerText,
            ]
        ]);
        $body = @file_get_contents($url, false, $ctx);
    }

    $elapsed = microtime(true) - $started;
    if (isset($state['timing'])) {
        $state['timing']['http_seconds'] =
            round((float)($state['timing']['http_seconds'] ?? 0) + $elapsed, 3);
        if ($body === false) {
            $state['timing']['http_failures'] =
                (int)($state['timing']['http_failures'] ?? 0) + 1;
        }
    }

    return $body;
}

function wordfence_version_is_affected(string $version, array $ranges): bool {
    foreach ($ranges as $range) {
        if (!is_array($range)) continue;
        $from = (string)($range['from_version'] ?? '*');
        $to = (string)($range['to_version'] ?? '*');
        $fromInc = !array_key_exists('from_inclusive',$range) || (bool)$range['from_inclusive'];
        $toInc = !array_key_exists('to_inclusive',$range) || (bool)$range['to_inclusive'];
        $fromOk = $from==='*' || version_compare($version,$from,$fromInc?'>=':'>');
        $toOk = $to==='*' || version_compare($version,$to,$toInc?'<=':'<');
        if ($fromOk && $toOk) return true;
    }
    return false;
}

function scan_composer_vulnerabilities_osv(string $wpRoot): array {
    $result = ['source'=>['available'=>true,'name'=>'OSV.dev'],'vulnerabilities'=>[],'errors'=>[]];
    $locks = [];
    if (is_file("$wpRoot/composer.lock")) $locks[] = "$wpRoot/composer.lock";
    foreach (["$wpRoot/wp-content/plugins/*/composer.lock","$wpRoot/wp-content/themes/*/composer.lock","$wpRoot/wp-content/mu-plugins/*/composer.lock"] as $pattern) {
        foreach (glob($pattern) ?: [] as $path) $locks[] = $path;
    }
    $locks = array_values(array_unique($locks));
    $packages = [];
    foreach ($locks as $lock) {
        $json = json_file($lock);
        if (!is_array($json)) continue;
        foreach (($json['packages'] ?? []) as $pkg) {
            if (!is_array($pkg)) continue;
            $name=(string)($pkg['name'] ?? ''); $version=ltrim((string)($pkg['version'] ?? ''),'v');
            if ($name==='' || $version==='' || strpos($name,'/')===false) continue;
            $packages[strtolower($name).'@'.$version] = ['name'=>$name,'version'=>$version,'lock'=>str_replace($wpRoot.'/','',$lock)];
        }
    }
    if (!$packages) return $result;

    foreach (array_chunk(array_values($packages),100) as $chunk) {
        $queries=[];
        foreach ($chunk as $pkg) $queries[]=['package'=>['ecosystem'=>'Packagist','name'=>$pkg['name']],'version'=>$pkg['version']];
        $body=http_post_json('https://api.osv.dev/v1/querybatch',['queries'=>$queries],20);
        if (!is_array($body) || !isset($body['results']) || !is_array($body['results'])) {
            $result['errors'][]='OSV querybatch request failed.'; $result['source']['available']=false; continue;
        }
        foreach ($body['results'] as $idx=>$row) {
            $pkg=$chunk[$idx] ?? null; if (!$pkg || !is_array($row)) continue;
            foreach (($row['vulns'] ?? []) as $vuln) {
                $id=is_array($vuln)?(string)($vuln['id'] ?? ''):''; if ($id==='') continue;
                $details=osv_vulnerability_detail($id);
                $result['vulnerabilities'][]=[
                    'source'=>'osv','id'=>$id,'package'=>$pkg['name'],'installed'=>$pkg['version'],'lock'=>$pkg['lock'],
                    'summary'=>(string)($details['summary'] ?? ''),'aliases'=>array_values(array_filter((array)($details['aliases'] ?? []),'is_string')),
                    'fixed_versions'=>osv_fixed_versions_for_package($details,$pkg['name']),
                    'references'=>osv_reference_urls($details),
                ];
            }
        }
    }
    $dedupe=[];
    foreach ($result['vulnerabilities'] as $v) $dedupe[$v['id'].'|'.$v['package'].'|'.$v['installed']]=$v;
    $result['vulnerabilities']=array_values($dedupe);
    return $result;
}

function http_post_json(string $url, array $payload, int $timeout=20): ?array {
    global $state;
    $started=microtime(true);
    if (isset($state['timing'])) $state['timing']['http_requests']=(int)($state['timing']['http_requests'] ?? 0)+1;
    $json=json_encode($payload,JSON_UNESCAPED_SLASHES); if (!is_string($json)) return null;

    if (function_exists('curl_init')) {
        $ch=curl_init();
        curl_setopt_array($ch,[CURLOPT_URL=>$url,CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$json,CURLOPT_RETURNTRANSFER=>true,CURLOPT_CONNECTTIMEOUT=>5,CURLOPT_TIMEOUT=>$timeout,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_HTTPHEADER=>['Content-Type: application/json','Accept: application/json','User-Agent: WP-Warden/'.WP_WARDEN_VERSION]]);
        $body=curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_RESPONSE_CODE); curl_close($ch);
        if ($code<200 || $code>=400) $body=false;
    } else {
        $ctx=stream_context_create(['http'=>['method'=>'POST','timeout'=>$timeout,'ignore_errors'=>true,'header'=>"Content-Type: application/json\r\nUser-Agent: WP-Warden/".WP_WARDEN_VERSION."\r\n",'content'=>$json]]);
        $body=@file_get_contents($url,false,$ctx);
    }
    $elapsed=microtime(true)-$started;
    if (isset($state['timing'])) {
        $state['timing']['http_seconds']=round((float)($state['timing']['http_seconds'] ?? 0)+$elapsed,3);
        if ($body===false) $state['timing']['http_failures']=(int)($state['timing']['http_failures'] ?? 0)+1;
    }
    if (!is_string($body) || $body==='') return null;
    $decoded=json_decode($body,true); return is_array($decoded)?$decoded:null;
}

function osv_vulnerability_detail(string $id): array {
    static $memory=[];
    if (isset($memory[$id])) return $memory[$id];
    $body=http_get_body_with_headers('https://api.osv.dev/v1/vulns/'.rawurlencode($id),['Accept: application/json'],10);
    $decoded=is_string($body)?json_decode($body,true):null;
    $memory[$id]=is_array($decoded)?$decoded:[];
    return $memory[$id];
}

function osv_fixed_versions_for_package(array $details,string $packageName): array {
    $fixed=[];
    foreach (($details['affected'] ?? []) as $affected) {
        if (!is_array($affected)) continue;
        $pkg=$affected['package'] ?? [];
        if (!is_array($pkg) || strcasecmp((string)($pkg['name'] ?? ''),$packageName)!==0) continue;
        foreach (($affected['ranges'] ?? []) as $range) if (is_array($range)) foreach (($range['events'] ?? []) as $event) if (is_array($event) && isset($event['fixed']) && is_string($event['fixed'])) $fixed[$event['fixed']]=true;
    }
    return array_keys($fixed);
}

function osv_reference_urls(array $details): array {
    $urls=[];
    foreach (($details['references'] ?? []) as $ref) {
        if (is_array($ref) && !empty($ref['url']) && is_string($ref['url'])) $urls[]=$ref['url'];
        if (count($urls)>=3) break;
    }
    return $urls;
}

function wordfence_cache_status(string $intelDir): array {
    $dir = wordfence_cache_dir($intelDir);
    $cache = $dir . '/wordfence-intelligence-v3-scanner.json';
    $stateFile = $dir . '/wordfence-rate-limit.json';

    $out = [
        'cache_exists'=>is_file($cache) && @filesize($cache) > 0,
        'cache_age_seconds'=>null,
        'cache_age_hours'=>null,
        'rate_limited'=>false,
        'next_allowed_at'=>null,
        'next_allowed_utc'=>null,
    ];

    if ($out['cache_exists']) {
        $age = time() - (int)@filemtime($cache);
        $out['cache_age_seconds'] = $age;
        $out['cache_age_hours'] = round($age / 3600, 1);
    }

    $state = json_file($stateFile);
    if (is_array($state)) {
        $next = (int)($state['next_allowed_at'] ?? 0);
        if ($next > time()) {
            $out['rate_limited'] = true;
            $out['next_allowed_at'] = $next;
            $out['next_allowed_utc'] = gmdate('c', $next);
        }
    }

    return $out;
}

function check_update_health(string $wpRoot, ?string $wpVersion, string $intelDir): array {
    $result=[
        'core'=>null,'plugins'=>[],'themes'=>[],'unknown'=>[],
        'private_or_custom'=>[],'auto_update'=>detect_auto_update_config($wpRoot)
    ];

    if ($wpVersion) {
        $data = cached_remote_json($intelDir,'core-latest','https://api.wordpress.org/core/version-check/1.7/?version='.rawurlencode($wpVersion),21600);
        $latest = $data['offers'][0]['current'] ?? null;
        if (is_string($latest) && $latest !== '') {
            $result['core']=['installed'=>$wpVersion,'latest'=>$latest,'outdated'=>version_compare($wpVersion,$latest,'<'),'source'=>'wordpress.org'];
        } else {
            $result['unknown'][]=['type'=>'core','installed'=>$wpVersion,'reason'=>'latest version lookup failed'];
        }
    }

    foreach (glob("$wpRoot/wp-content/plugins/*",GLOB_ONLYDIR) ?: [] as $p) {
        $slug=basename($p);
        if (malicious_plugin_slug_ioc($slug) !== null) {
            // Reported as a CRITICAL malware IOC by the plugin-directory audit.
            continue;
        }
        if (is_backup_component_directory($slug)) {
            continue;
        }
        $installed=detect_plugin_version($p,$slug);
        if (!$installed) {
            $result['unknown'][]=['type'=>'plugin','slug'=>$slug,'reason'=>'installed version not detected'];
            continue;
        }

        $localNewer = local_component_versions('plugins', $slug, $installed);
        $url='https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]='.rawurlencode($slug);
        $d=cached_remote_json($intelDir,'plugin-'.$slug,$url,21600);
        $latest=$d['version'] ?? null;

        if (is_string($latest)&&$latest!=='') {
            if ($localNewer && version_compare($localNewer[0], $latest, '>')) {
                $latest = $localNewer[0];
                $source = 'local-clean-zip';
            } else {
                $source = 'wordpress.org';
            }
            $result['plugins'][]=['slug'=>$slug,'installed'=>$installed,'latest'=>$latest,'outdated'=>version_compare($installed,$latest,'<'),'source'=>$source];
        } elseif ($localNewer) {
            $result['plugins'][]=[
                'slug'=>$slug,'installed'=>$installed,'latest'=>$localNewer[0],
                'outdated'=>true,'source'=>'local-clean-zip'
            ];
        } else {
            $result['private_or_custom'][]=['type'=>'plugin','slug'=>$slug,'installed'=>$installed,'reason'=>'not found on wordpress.org and no newer trusted local package found'];
        }
    }

    foreach (glob("$wpRoot/wp-content/themes/*",GLOB_ONLYDIR) ?: [] as $p) {
        $slug=basename($p);
        if (is_backup_component_directory($slug)) {
            continue;
        }
        $installed=detect_theme_version($p);
        if (!$installed) {
            $result['unknown'][]=['type'=>'theme','slug'=>$slug,'reason'=>'installed version not detected'];
            continue;
        }

        $localNewer = local_component_versions('themes', $slug, $installed);
        $url='https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]='.rawurlencode($slug);
        $d=cached_remote_json($intelDir,'theme-'.$slug,$url,21600);
        $latest=$d['version'] ?? null;

        if (is_string($latest)&&$latest!=='') {
            if ($localNewer && version_compare($localNewer[0], $latest, '>')) {
                $latest=$localNewer[0];
                $source='local-clean-zip';
            } else {
                $source='wordpress.org';
            }
            $result['themes'][]=['slug'=>$slug,'installed'=>$installed,'latest'=>$latest,'outdated'=>version_compare($installed,$latest,'<'),'source'=>$source];
        } elseif ($localNewer) {
            $result['themes'][]=[
                'slug'=>$slug,'installed'=>$installed,'latest'=>$localNewer[0],
                'outdated'=>true,'source'=>'local-clean-zip'
            ];
        } else {
            $result['private_or_custom'][]=['type'=>'theme','slug'=>$slug,'installed'=>$installed,'reason'=>'not found on wordpress.org and no newer trusted local package found'];
        }
    }

    return $result;
}
function cached_remote_json(string $intelDir,string $key,string $url,int $ttl): array {
    $dir=rtrim($intelDir,'/').'/cache/update-health'; @mkdir($dir,0755,true); $p=$dir.'/'.sha1($key).'.json';
    if (is_file($p) && time()-(int)@filemtime($p)<$ttl) { $d=json_file($p); if (is_array($d)) return $d; }
    $body=http_get_body($url); $d=is_string($body)?json_decode($body,true):null;
    if (is_array($d)) { @file_put_contents($p,json_encode($d,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)); return $d; }
    if (is_file($p)) { $d=json_file($p); if (is_array($d)) return $d; }
    return [];
}
function detect_auto_update_config(string $wpRoot): array {
    $cfg=['DISALLOW_FILE_MODS'=>null,'AUTOMATIC_UPDATER_DISABLED'=>null,'WP_AUTO_UPDATE_CORE'=>null];
    $path=$wpRoot.'/wp-config.php'; $s=is_file($path)?@file_get_contents($path):false;
    if (!is_string($s)) return $cfg;
    foreach (array_keys($cfg) as $name) {
        if (warden_preg_match('/define\s*\(\s*[\'\"]'.preg_quote($name,'/').'[\'\"]\s*,\s*([^\)]+)\)/i',$s,$m)) $cfg[$name]=trim($m[1]);
    }
    return $cfg;
}

function stats_inc(string $key): void {
    global $state;
    $state['summary'][$key]++;
}

function print_human_report(array $report, ?string $jsonPath): void {
    $summary = $report['summary'];
    $findings = $report['findings'];

    echo PHP_EOL;
    echo "================ WP Warden Summary ================" . PHP_EOL;
    echo "Target:       {$report['target']}" . PHP_EOL;
    echo "Site ID:      {$report['site_id']}" . PHP_EOL;
    echo "Policy:       {$report['policy']}" . PHP_EOL;
    echo "Started:      {$report['started_at']}" . PHP_EOL;
    echo "Finished:     {$report['finished_at']}" . PHP_EOL;
    echo "Mode:         " . (!empty($report['apply']) ? 'apply enabled' : 'report only') . PHP_EOL;
    echo PHP_EOL;

    echo "Files seen:   {$summary['files_seen']}" . PHP_EOL;
    echo "Scanned:      {$summary['files_scanned']}" . PHP_EOL;
    echo "Skipped:      {$summary['files_skipped']}" . PHP_EOL;
    echo "Benign index: " . ($summary['benign_index_skipped'] ?? 0) . " placeholder(s) skipped" . PHP_EOL;
    echo "Large files:  " . (int)($summary['large_files_deep_scan_skipped'] ?? 0) . " deep scan(s) skipped" . PHP_EOL;
    echo "Symlinks:     " . (int)($summary['symlinks_detected'] ?? 0) . " reported, targets not followed" . PHP_EOL;
    $cacheHits = (int)($summary['cache_hits'] ?? 0);
    $cacheMisses = (int)($summary['cache_misses'] ?? 0);
    $cacheTotal = $cacheHits + $cacheMisses;
    $cacheRate = $cacheTotal > 0 ? round(($cacheHits / $cacheTotal) * 100, 1) : 0;
    echo "Cache hits:   $cacheHits" . PHP_EOL;
    echo "Cache misses: $cacheMisses" . PHP_EOL;
    echo "Cache rate:   {$cacheRate}%" . PHP_EOL;
    echo "Cache entries:" . str_pad((string)($summary['cache_entries'] ?? 0), 4, ' ', STR_PAD_LEFT) . PHP_EOL;
    echo "Actions:      {$summary['actions_taken']}" . PHP_EOL;
    echo PHP_EOL;

    echo "Findings:     {$summary['findings_total']}" . PHP_EOL;
    echo "  Critical:   {$summary['critical']}" . PHP_EOL;
    echo "  High:       {$summary['high']}" . PHP_EOL;
    echo "  Medium:     {$summary['medium']}" . PHP_EOL;
    echo "  Low:        {$summary['low']}" . PHP_EOL;
    echo "  Info:       {$summary['info']}" . PHP_EOL;
    echo PHP_EOL;

    print_db_audit_summary($report['db_audit'] ?? []);

    $ci=$report['checksum_intel'] ?? [];
    $mp=$ci['missing_plugins'] ?? []; $mt=$ci['missing_themes'] ?? [];
    $up=$ci['unknown_plugin_versions'] ?? []; $ut=$ci['unknown_theme_versions'] ?? [];
    if ($mp || $mt || $up || $ut) {
        echo "Missing Checksum Intel:" . PHP_EOL;
        foreach ($mp as $x) echo "  [PLUGIN] {$x['slug']} {$x['version']} -> {$x['expected_intel']}" . PHP_EOL;
        foreach ($mt as $x) echo "  [THEME]  {$x['slug']} {$x['version']} -> {$x['expected_intel']}" . PHP_EOL;
        foreach ($up as $x) echo "  [PLUGIN VERSION?] {$x['slug']}" . PHP_EOL;
        foreach ($ut as $x) echo "  [THEME VERSION?]  {$x['slug']}" . PHP_EOL;
        foreach (($ci['backup_plugin_dirs'] ?? []) as $x) echo "  [PLUGIN BACKUP DIR] {$x['slug']} - review/remove inactive backup copy" . PHP_EOL;
        foreach (($ci['backup_theme_dirs'] ?? []) as $x) echo "  [THEME BACKUP DIR]  {$x['slug']} - review/remove inactive backup copy" . PHP_EOL;
        foreach ($mp as $x) {
            if (!empty($x['newer_local_versions'])) {
                echo "    Newer trusted local package(s) available for {$x['slug']}: " . implode(', ', $x['newer_local_versions']) . PHP_EOL;
            }
        }
        foreach ($mt as $x) {
            if (!empty($x['newer_local_versions'])) {
                echo "    Newer trusted local package(s) available for {$x['slug']}: " . implode(', ', $x['newer_local_versions']) . PHP_EOL;
            }
        }
        echo PHP_EOL;
    }
    $vulns=$report['vulnerabilities'] ?? [];
    if (!empty($vulns['enabled'])) {
        $vs=$vulns['summary'] ?? [];
        echo "Vulnerability Health:" . PHP_EOL;
        echo "  Status:    " . ($vulns['status'] ?? 'UNKNOWN') . PHP_EOL;
        echo "  Total:     " . (int)($vs['total'] ?? 0) . PHP_EOL;
        echo "  WordPress: " . (int)($vs['wordpress'] ?? 0) . PHP_EOL;
        echo "  Composer:  " . (int)($vs['composer'] ?? 0) . PHP_EOL;
        if (empty($vulns['sources']['wordfence']['available'])) {
            echo "  [SOURCE UNAVAILABLE] Wordfence: " . ($vulns['sources']['wordfence']['reason'] ?? 'not configured') . PHP_EOL;
        }
        $wfCache = $vulns['sources']['wordfence_cache'] ?? [];
        if (!empty($wfCache['cache_exists'])) {
            echo "  Wordfence cache age: " . ($wfCache['cache_age_hours'] ?? '?') . "h" . PHP_EOL;
        }
        if (!empty($wfCache['rate_limited'])) {
            echo "  [RATE LIMITED] Wordfence refresh suppressed until " .
                ($wfCache['next_allowed_utc'] ?? 'unknown') . PHP_EOL;
        }
        foreach (($vulns['wordpress'] ?? []) as $v) {
            $patch=!empty($v['patched'])?'patched':'NO KNOWN PATCH';
            $fixed=!empty($v['patched_versions'])?' fixed='.implode(',',$v['patched_versions']):'';
            echo "  [WORDPRESS VULNERABLE] {$v['type']} {$v['slug']} {$v['installed']} - {$v['title']} ({$patch}{$fixed})" . PHP_EOL;
            foreach (($v['copyright_notices'] ?? []) as $notice) echo "       {$notice}" . PHP_EOL;
        }
        foreach (($vulns['composer'] ?? []) as $v) {
            $fixed=!empty($v['fixed_versions'])?' fixed='.implode(',',$v['fixed_versions']):'';
            echo "  [COMPOSER VULNERABLE] {$v['package']} {$v['installed']} - {$v['id']} {$v['summary']}{$fixed}" . PHP_EOL;
        }
        foreach (($vulns['errors'] ?? []) as $err) echo "  [VULN SCAN WARNING] {$err}" . PHP_EOL;
        echo PHP_EOL;
    }

    $updates=$report['updates'] ?? [];
    $outCore=!empty($updates['core']['outdated']);
    $outPlugins=array_values(array_filter($updates['plugins'] ?? [],fn($x)=>!empty($x['outdated'])));
    $outThemes=array_values(array_filter($updates['themes'] ?? [],fn($x)=>!empty($x['outdated'])));
    if ($outCore || $outPlugins || $outThemes || !empty($updates['unknown'])) {
        echo "Update Health / Manual Review:" . PHP_EOL;
        if ($outCore) echo "  [CORE OUTDATED] {$updates['core']['installed']} -> {$updates['core']['latest']}" . PHP_EOL;
        foreach ($outPlugins as $x) echo "  [PLUGIN OUTDATED] {$x['slug']} {$x['installed']} -> {$x['latest']}" . PHP_EOL;
        foreach ($outThemes as $x) echo "  [THEME OUTDATED]  {$x['slug']} {$x['installed']} -> {$x['latest']}" . PHP_EOL;
        foreach (($updates['unknown'] ?? []) as $x) echo "  [UPDATE UNKNOWN] " . ($x['type']??'component') . " " . ($x['slug']??'') . " " . ($x['installed']??'') . " - " . ($x['reason']??'unknown') . PHP_EOL;
        foreach (($updates['private_or_custom'] ?? []) as $x) echo "  [PRIVATE/CUSTOM UPDATE SOURCE] " . ($x['type']??'component') . " " . ($x['slug']??'') . " " . ($x['installed']??'') . " - " . ($x['reason']??'') . PHP_EOL;
        $a=$updates['auto_update'] ?? [];
        echo "  Auto-update config: DISALLOW_FILE_MODS=".($a['DISALLOW_FILE_MODS']??'not set').", AUTOMATIC_UPDATER_DISABLED=".($a['AUTOMATIC_UPDATER_DISABLED']??'not set').", WP_AUTO_UPDATE_CORE=".($a['WP_AUTO_UPDATE_CORE']??'not set').PHP_EOL;
        echo PHP_EOL;
    }
    if (!empty($report['timing'])) {
        $timing = $report['timing'];
        $slowestRule = $timing['slowest_rule'] ?? null;
        $slowestFile = $timing['slowest_file'] ?? null;
        echo "Performance:" . PHP_EOL;
        echo "  File scan seconds: " . ($timing['file_scan_seconds'] ?? 0) . PHP_EOL;
        echo "  Cache hits: " . (int)($summary['cache_hits'] ?? 0) . PHP_EOL;
        echo "  Cache misses: " . (int)($summary['cache_misses'] ?? 0) . PHP_EOL;
        echo "  PCRE errors: " . (int)($timing['pcre_errors'] ?? 0) . PHP_EOL;
        echo "  Slow rules: " . (int)($timing['slow_rules'] ?? 0) . PHP_EOL;
        echo "  Slow files: " . (int)($timing['slow_files'] ?? 0) . PHP_EOL;
        echo "  Slowest rule: " . (is_array($slowestRule)
            ? sprintf('%.2fms %s %s', (float)$slowestRule['milliseconds'], $slowestRule['rule_id'], $slowestRule['path'])
            : 'n/a') . PHP_EOL;
        echo "  Slowest file: " . (is_array($slowestFile)
            ? sprintf('%.2fms %s', (float)$slowestFile['milliseconds'], $slowestFile['path'])
            : 'n/a') . PHP_EOL;
        echo PHP_EOL;

        echo "Timing:" . PHP_EOL;
        foreach ($report['timing'] as $k=>$v) {
            if (is_array($v) || $v === null) {
                echo "  $k: " . ($v === null ? 'n/a' : json_encode($v, JSON_UNESCAPED_SLASHES)) . PHP_EOL;
                continue;
            }
            $isCount = warden_preg_match('/(?:_requests|_failures|_attempts|pcre_errors|slow_rules|slow_files)$/', (string)$k) === 1;
            echo "  $k: {$v}" . ($isCount ? '' : 's') . PHP_EOL;
        }
        echo PHP_EOL;
    }

    if (empty($findings)) {
        echo "Result:       No findings." . PHP_EOL;
        echo "===================================================" . PHP_EOL;
        return;
    }

    echo "Finding Types:" . PHP_EOL;
    foreach (finding_type_counts($findings) as $type => $count) {
        echo "  " . str_pad((string)$count, 4, ' ', STR_PAD_LEFT) . "  $type" . PHP_EOL;
    }
    echo PHP_EOL;

    echo "Highest Risk Findings:" . PHP_EOL;
    $shown = 0;
    foreach (['critical', 'high', 'medium', 'low', 'info'] as $sev) {
        foreach ($findings as $finding) {
            if (strtolower($finding['severity'] ?? 'medium') !== $sev) {
                continue;
            }
            $shown++;
            $line = sprintf(
                "  [%s] %s: %s",
                strtoupper($sev),
                $finding['type'] ?? 'finding',
                $finding['relative_path'] ?? $finding['path'] ?? '(unknown path)'
            );
            echo $line . PHP_EOL;
            if (!empty($finding['rule_id'])) {
                echo "       rule: {$finding['rule_id']}" . PHP_EOL;
            }
            if (!empty($finding['line'])) {
                echo "       line: {$finding['line']}" . PHP_EOL;
            }
            if (!empty($finding['rule_pattern'])) {
                echo "       pattern: " . shorten_text((string)$finding['rule_pattern'], 140) . PHP_EOL;
            }
            if (!empty($finding['matched_text'])) {
                echo "       matched: " . $finding['matched_text'] . PHP_EOL;
            }
            if (!empty($finding['reason'])) {
                echo "       why:  {$finding['reason']}" . PHP_EOL;
            }
            if ($shown >= 50) {
                echo "  ... showing first 50 findings. Use --report-json for full details." . PHP_EOL;
                break 2;
            }
        }
    }
    echo PHP_EOL;

    if (!empty($report['actions'])) {
        echo "Actions Taken:" . PHP_EOL;
        foreach ($report['actions'] as $action) {
            $type = $action['type'] ?? 'action';
            $target = $action['relative_path'] ?? $action['path'] ?? $action['from'] ?? '';
            echo "  - $type: $target" . PHP_EOL;
            if (!empty($action['backup'])) {
                echo "    backup: {$action['backup']}" . PHP_EOL;
            }
            if (!empty($action['to'])) {
                echo "    to: {$action['to']}" . PHP_EOL;
            }
        }
        echo PHP_EOL;
    }

    echo "Recommended Next Steps:" . PHP_EOL;
    if (($summary['critical'] ?? 0) > 0) {
        echo "  - Treat critical findings as active compromise until reviewed." . PHP_EOL;
        echo "  - Quarantine or delete malicious extra files, then re-run the scan." . PHP_EOL;
    }
    if (($summary['high'] ?? 0) > 0) {
        echo "  - Repair modified official files from clean packages where possible." . PHP_EOL;
        echo "  - Review extra plugin/theme files and allowlist only known-good custom files." . PHP_EOL;
    }
    if (($summary['actions_taken'] ?? 0) > 0) {
        echo "  - Confirm site behavior and run another scan to verify nothing respawned." . PHP_EOL;
    }
    if (!$jsonPath) {
        echo "  - Add --report-json=/path/report.json for machine-readable details." . PHP_EOL;
    } else {
        echo "  - JSON report: $jsonPath" . PHP_EOL;
    }

    echo "===================================================" . PHP_EOL;
}

function print_db_audit_summary(array $audit): void {
    if (!$audit) {
        return;
    }

    echo "WordPress Admin Users:" . PHP_EOL;
    if (!empty($audit['error'])) {
        echo "  Audit skipped: {$audit['error']}" . PHP_EOL;
        echo PHP_EOL;
        return;
    }

    $knownAdmins = $audit['known_admins'] ?? [];
    if ($knownAdmins === []) {
        echo "  Known admin list: not configured; reporting admins without flagging." . PHP_EOL;
    } else {
        echo "  Known admin list: " . implode(', ', $knownAdmins) . PHP_EOL;
    }

    $admins = $audit['admin_users'] ?? [];
    if ($admins === []) {
        echo "  No administrator users found by DB audit." . PHP_EOL;
        echo PHP_EOL;
        return;
    }

    foreach ($admins as $admin) {
        $status = array_key_exists('known', $admin) && $admin['known'] === null
            ? 'reported'
            : (!empty($admin['known']) ? 'known' : 'unknown');
        $login = $admin['login'] ?? '(unknown)';
        $email = $admin['email'] ?? '';
        $registered = $admin['registered'] ?? '';
        $id = $admin['id'] ?? '?';
        echo "  - {$login} [{$status}] id={$id}";
        if ($email !== '') {
            echo " email={$email}";
        }
        if ($registered !== '') {
            echo " created={$registered}";
        }
        echo PHP_EOL;
    }

    $persist = $audit['persistence_findings'] ?? [];
    $optionIocs = $audit['option_iocs'] ?? [];
    $cronIocs = $audit['cron_iocs'] ?? [];
    $metaIocs = $audit['usermeta_iocs'] ?? [];

    if ($persist || $optionIocs || $cronIocs || $metaIocs) {
        echo PHP_EOL;
        echo "Database Persistence Review:" . PHP_EOL;
        foreach ($persist as $finding) {
            $sev = strtoupper((string)($finding['severity'] ?? 'medium'));
            $rule = (string)($finding['rule_id'] ?? '');
            $where = (string)($finding['relative_path'] ?? 'database');
            $reason = (string)($finding['reason'] ?? '');
            echo "  [{$sev}] {$rule}: {$where}" . PHP_EOL;
            echo "       {$reason}" . PHP_EOL;
        }
    }

    echo PHP_EOL;
}

function finding_type_counts(array $findings): array {
    $counts = [];
    foreach ($findings as $finding) {
        $type = $finding['type'] ?? 'unknown';
        $counts[$type] = ($counts[$type] ?? 0) + 1;
    }
    arsort($counts);
    return $counts;
}

function write_json_report(string $path, array $report): void {
    $dir = dirname($path);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    file_put_contents($path, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}
