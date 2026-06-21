#!/usr/bin/env php
<?php
/**
 * WP Warden - WordPress malware and integrity scanner.
 *
 * First standalone version wired to the wp-warden-intel bundle layout.
 * Noninteractive runs are report-only unless --apply is supplied.
 */

const WP_WARDEN_VERSION = '0.1.27';

$opts = parse_args($argv);
@ini_set('pcre.backtrack_limit', '500000');
@ini_set('pcre.recursion_limit', '500000');

if (isset($opts['help']) || empty($opts['target'])) {
    print_help();
    exit(isset($opts['help']) ? 0 : 1);
}

$target = normalize_path($opts['target']);
if (!is_dir($target)) {
    fwrite(STDERR, "ERROR: target is not a directory: {$opts['target']}\n");
    exit(1);
}

$intelDir = normalize_path($opts['intel-dir'] ?? __DIR__ . '/../wp-warden-intel');
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
$fetchOfficialChecksums = isset($opts['fetch-official-checksums']) || isset($opts['fetch-official']);
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

$state = [
    'started_at' => gmdate('c'),
    'target' => $target,
    'site_id' => $siteId,
    'intel_dir' => $intelDir,
    'policy' => $policyId,
    'apply' => $apply,
    'findings' => [],
    'actions' => [],
    'db_audit' => [
        'admin_users' => [],
        'known_admins' => [],
        'error' => null,
    ],
    'summary' => [
        'files_seen' => 0,
        'files_scanned' => 0,
        'files_skipped' => 0,
        'findings_total' => 0,
        'critical' => 0,
        'high' => 0,
        'medium' => 0,
        'low' => 0,
        'info' => 0,
        'actions_taken' => 0,
    ],
];
$handledInteractivePaths = [];

$intel = load_intel($intelDir, $policyId, $siteId);
$wpRoot = realpath($target) ?: $target;
$wpVersion = detect_wp_version($wpRoot);
$locale = detect_wp_locale($wpRoot);
$coreChecksums = load_core_checksums($intelDir, $wpVersion, $locale, $fetchOfficialChecksums);
$componentChecksums = load_component_checksums($wpRoot, $intelDir, $fetchOfficialChecksums);

say("WP Warden " . WP_WARDEN_VERSION, true);
say("Target: $wpRoot", true);
say("Intel:  $intelDir", true);
say("Policy: $policyId", true);
if (!$apply) {
    say("Mode:   report-only; no file changes will be made without --apply", true);
} elseif (!$quarantineDir) {
    say("Mode:   apply enabled, but no --quarantine directory was supplied; no files will be moved", true);
}
if ($repairOriginal && !$apply) {
    say("Mode:   repair requested, but --apply is missing; repairs will be offered as report-only", true);
}
if ($wpVersion) {
    say("WordPress: $wpVersion ($locale)", true);
}

say("Scanning files...", true);
scan_tree($wpRoot, $intel, $coreChecksums, $componentChecksums);
say("File scan complete. Auditing WordPress admin users...", true);
audit_wordpress_admins($wpRoot, $intel);
say("Building report...", true);

$state['finished_at'] = gmdate('c');
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
    echo "                          Interactive actions: V preview, R repair, Q quarantine, D delete, A allowlist, S skip\n";
    echo "  --repair-original       Offer to replace mismatched core/plugin/theme files from clean ZIPs\n";
    echo "  --repair-original-auto  Auto-replace mismatched files from clean ZIPs; requires --apply\n";
    echo "  --repair-backup=DIR     Backup originals before repair overwrite\n";
    echo "  --package-cache=DIR     Cache downloaded clean ZIP packages\n";
    echo "  --known-admins=a,b      Comma-separated expected admin logins for DB audit\n";
    echo "  --no-db-audit           Skip WordPress administrator DB audit\n";
    echo "  --verify-all            Report files not matched by core checksum/baseline\n";
    echo "  --fetch-official-checksums\n";
    echo "                          Fetch/cache official WordPress core and wordpress.org plugin checksums\n";
    echo "  --max-size=MB           Skip files larger than MB (default 10)\n";
    echo "  --max-text-size=MB      Skip regex text scan for files larger than MB (default 5)\n";
    echo "  --debug-progress        Print each file path before scanning it\n";
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
    foreach ([
        "$intelDir/patterns/php-malware-rules.json",
        "$intelDir/patterns/community-malware-rules.json",
    ] as $path) {
        $data = json_file($path);
        foreach (($data['rules'] ?? []) as $rule) {
            if (is_array($rule)) {
                $rules[] = $rule;
            }
        }
    }
    return $rules;
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
    if (preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $data, $m)) {
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
    if (preg_match('/define\s*\(\s*[\'"]WPLANG[\'"]\s*,\s*[\'"]([^\'"]*)[\'"]\s*\)/', $data, $m) && $m[1] !== '') {
        return $m[1];
    }
    return 'en_US';
}

function audit_wordpress_admins(string $root, array $intel): void {
    global $state, $opts;

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
    if (!preg_match('/^[A-Za-z0-9_]+$/', $prefix)) {
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
        $isKnown = $knownAdmins === [] ? null : ($login !== '' && isset($knownIndex[strtolower($login)]));
        $entry = [
            'id' => (int)($row['ID'] ?? 0),
            'login' => $login,
            'email' => (string)($row['user_email'] ?? ''),
            'registered' => (string)($row['user_registered'] ?? ''),
            'known' => $isKnown,
        ];
        $state['db_audit']['admin_users'][] = $entry;

        if ($isKnown === false) {
            add_finding([
                'severity' => $intel['policy']['severity']['rogue_admin'] ?? 'critical',
                'type' => 'unknown_admin_user',
                'rule_id' => 'DB_UNKNOWN_ADMIN_001',
                'path' => 'database',
                'relative_path' => 'database:admin-user/' . $login,
                'reason' => 'Administrator account is not in the known admin list.',
                'db_user' => $entry,
                'file_action' => false,
                'recommended_action' => 'Confirm this WordPress administrator is legitimate; remove it or add it to known_admins if approved.',
            ], false);
        }
    }

    $result->free();
    $db->close();
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
        if (preg_match('/define\s*\(\s*[\'"]' . preg_quote($key, '/') . '[\'"]\s*,\s*([\'"])(.*?)\1\s*\)/s', $data, $m)) {
            $config[$key] = stripcslashes($m[2]);
        }
    }
    if (preg_match('/\$table_prefix\s*=\s*([\'"])(.*?)\1\s*;/', $data, $m)) {
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

    if (preg_match('/^(.+):(\d+)$/', $host, $m)) {
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
    $sets = [];
    $pluginsDir = "$wpRoot/wp-content/plugins";
    if (!is_dir($pluginsDir)) {
        return $sets;
    }

    foreach (glob("$pluginsDir/*", GLOB_ONLYDIR) ?: [] as $pluginPath) {
        $slug = basename($pluginPath);
        $version = detect_plugin_version($pluginPath, $slug);
        if (!$version) {
            say("WARN: plugin version not detected for $slug");
            continue;
        }

        $local = "$intelDir/checksums/plugins/$slug/$version.json";
        $payload = load_component_checksum_payload($local);
        $map = $payload['files'];
        if (!$map && $fetchOfficial) {
            $map = fetch_plugin_checksums($slug, $version);
            if ($map) {
                cache_checksum_file($local, [
                    'schema' => 'wp-warden.checksums.component.v1',
                    'type' => 'plugin',
                    'slug' => $slug,
                    'version' => $version,
                    'source' => "https://downloads.wordpress.org/plugin-checksums/$slug/$version.json with http://wpmd5.mattjung.net/plugin/$slug/$version/ fallback",
                    'created_at' => gmdate('c'),
                    'files' => $map,
                ]);
            }
        }
        if ($map) {
            $sets[$slug] = [
                'version' => $version,
                'files' => normalize_checksum_map($map),
                'clean_zip' => $payload['clean_zip'],
            ];
        }
    }
    return $sets;
}

function load_theme_checksum_sets(string $wpRoot, string $intelDir, bool $fetchOfficial): array {
    $sets = [];
    $themesDir = "$wpRoot/wp-content/themes";
    if (!is_dir($themesDir)) {
        return $sets;
    }

    foreach (glob("$themesDir/*", GLOB_ONLYDIR) ?: [] as $themePath) {
        $slug = basename($themePath);
        $version = detect_theme_version($themePath);
        if (!$version) {
            continue;
        }

        $local = "$intelDir/checksums/themes/$slug/$version.json";
        $payload = load_component_checksum_payload($local);
        $map = $payload['files'];
        if (!$map && $fetchOfficial) {
            $map = fetch_theme_checksums($slug, $version);
            if ($map) {
                cache_checksum_file($local, [
                    'schema' => 'wp-warden.checksums.component.v1',
                    'type' => 'theme',
                    'slug' => $slug,
                    'version' => $version,
                    'source' => "http://wpmd5.mattjung.net/theme/$slug/$version/",
                    'created_at' => gmdate('c'),
                    'files' => $map,
                ]);
            }
        }
        if ($map) {
            $sets[$slug] = [
                'version' => $version,
                'files' => normalize_checksum_map($map),
                'clean_zip' => $payload['clean_zip'],
            ];
        }
    }
    return $sets;
}

function load_component_checksum_payload(string $path): array {
    if (!is_file($path)) {
        return ['files' => [], 'clean_zip' => null];
    }
    $data = json_file($path);
    $cleanZip = normalize_clean_zip_intel($data['clean_zip'] ?? $data['package_zip'] ?? null);
    if (isset($data['files']) && is_array($data['files'])) {
        return ['files' => $data['files'], 'clean_zip' => $cleanZip];
    }
    return ['files' => $data, 'clean_zip' => $cleanZip];
}

function normalize_clean_zip_intel($value): ?array {
    if (is_string($value) && trim($value) !== '') {
        return ['path' => trim($value)];
    }
    if (is_array($value) && !empty($value['path'])) {
        return [
            'path' => (string)$value['path'],
            'sha256' => isset($value['sha256']) ? strtolower((string)$value['sha256']) : null,
        ];
    }
    return null;
}

function fetch_plugin_checksums(string $slug, string $version): array {
    $url = "https://downloads.wordpress.org/plugin-checksums/" . rawurlencode($slug) . "/" . rawurlencode($version) . ".json";
    $data = http_get_json($url);
    if (!isset($data['files']) || !is_array($data['files'])) {
        say("WARN: official plugin checksum fetch failed for $slug $version");
        $fallback = fetch_wpmd5_checksums("plugin/$slug/$version");
        if ($fallback) {
            say("Fetched wpmd5 fallback plugin checksums: $slug $version (" . count($fallback) . " files)");
        }
        return $fallback;
    }

    $map = [];
    foreach ($data['files'] as $relPath => $info) {
        if (is_array($info)) {
            $md5 = checksum_string($info['md5'] ?? null);
            $sha256 = checksum_string($info['sha256'] ?? null);
            if ($md5 || $sha256) {
                $entry = [];
                if ($md5) {
                    $entry['md5'] = $md5;
                }
                if ($sha256) {
                    $entry['sha256'] = $sha256;
                }
                $map[$relPath] = $entry;
            }
        }
    }
    say("Fetched official plugin checksums: $slug $version (" . count($map) . " files)");
    return $map;
}

function fetch_theme_checksums(string $slug, string $version): array {
    $fallback = fetch_wpmd5_checksums("theme/$slug/$version");
    if ($fallback) {
        say("Fetched wpmd5 theme checksums: $slug $version (" . count($fallback) . " files)");
    } else {
        say("WARN: wpmd5 theme checksum fetch failed for $slug $version");
    }
    return $fallback;
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
        if (preg_match('/^[ \t\/*#@]*Version:\s*(.+)$/mi', $head, $m)) {
            return trim($m[1]);
        }
    }

    $readme = "$pluginPath/readme.txt";
    if (is_file($readme)) {
        $head = @file_get_contents($readme, false, null, 0, 8192);
        if (is_string($head) && preg_match('/^[ \t]*Stable tag:\s*(.+)$/mi', $head, $m)) {
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
    if (is_string($head) && preg_match('/^[ \t\/*#@]*Version:\s*(.+)$/mi', $head, $m)) {
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
        if (!preg_match('#^([A-Za-z]:)?/#', $zipPath)) {
            $zipPath = rtrim($intelDir, '/') . '/' . ltrim($zipPath, '/');
        }

        return [
            'label' => "$type $slug $version local clean ZIP",
            'url' => $zipPath,
            'local_path' => $zipPath,
            'clean_zip_sha256' => $cleanZip['sha256'] ?? null,
            'cache_name' => basename($zipPath),
            'zip_prefix' => $type === 'core' ? 'wordpress/' : (($slug ?: '') . '/'),
        ];
    }

    if ($type === 'core') {
        if (!$wpVersion) {
            return null;
        }
        return [
            'label' => 'WordPress core',
            'url' => "https://wordpress.org/wordpress-$wpVersion.zip",
            'cache_name' => "wordpress-$wpVersion.zip",
            'zip_prefix' => 'wordpress/',
        ];
    }

    if ($type === 'plugin' && $slug && $version) {
        return [
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

    if (!class_exists('ZipArchive')) {
        say("[REPAIR-FAIL] PHP ZipArchive extension is not available; cannot repair $relativePath", true);
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
        return repair_from_svn_file($package, $relativePath, $absPath, $expected);
    }

    $zipInnerPath = package_inner_path($package, $relativePath);
    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        say("[REPAIR-FAIL] Could not open package ZIP: $zipPath", true);
        return false;
    }

    $data = $zip->getFromName($zipInnerPath);
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
        say("[REPAIR-FAIL] Package file checksum did not match intel for $relativePath", true);
        return false;
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

function repair_from_svn_file(array $package, string $relativePath, string $absPath, array $expected): bool {
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
    $context = stream_context_create([
        'http' => [
            'ignore_errors' => true,
            'timeout' => 20,
            'header' => "User-Agent: WP-Warden/" . WP_WARDEN_VERSION . "\r\n",
        ],
    ]);
    $body = @file_get_contents($url, false, $context);
    if ($body === false && function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'WP-Warden/' . WP_WARDEN_VERSION,
        ]);
        $body = curl_exec($ch);
        curl_close($ch);
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
        if (preg_match('/^([0-9a-f]{32})\s+\.(\/.+)$/i', $line, $m)) {
            $map[ltrim($m[2], './')] = ['md5' => strtolower($m[1])];
            continue;
        }
        if (preg_match('/^([0-9a-f]{32})\s+(.+)$/i', $line, $m)) {
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
    if (is_string($value) && preg_match('/^[a-f0-9]{32,64}$/i', $value)) {
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

function scan_tree(string $root, array $intel, array $coreChecksums, array $componentChecksums): void {
    global $maxSizeMb, $verifyAll, $state, $debugProgress;

    $rootNorm = normalize_path(realpath($root) ?: $root);
    $directory = new RecursiveDirectoryIterator($rootNorm, FilesystemIterator::SKIP_DOTS);
    $filter = new RecursiveCallbackFilterIterator($directory, function ($current) use ($rootNorm, $intel) {
        $rel = fast_relative_path($rootNorm, $current->getPathname());
        if ($current->isDir() && should_skip_path($rel . '/', $intel)) {
            return false;
        }
        return true;
    });
    $iterator = new RecursiveIteratorIterator(
        $filter
    );

    foreach ($iterator as $file) {
        if (!$file->isFile()) {
            continue;
        }

        $path = $file->getPathname();
        $rel = fast_relative_path($rootNorm, $path);
        stats_inc('files_seen');
        if (($state['summary']['files_seen'] % 1000) === 0) {
            $findingCount = count($state['findings']);
            say("Scan progress: {$state['summary']['files_seen']} files seen, {$state['summary']['files_scanned']} scanned, $findingCount findings");
        }

        if (should_skip_path($rel, $intel)) {
            stats_inc('files_skipped');
            continue;
        }

        if ($maxSizeMb > 0 && $file->getSize() > ($maxSizeMb * 1024 * 1024)) {
            stats_inc('files_skipped');
            continue;
        }

        stats_inc('files_scanned');
        if ($debugProgress) {
            say("Scanning file: $rel", true);
        }
        scan_one_file($root, $path, $rel, $intel, $coreChecksums, $componentChecksums, $verifyAll);
    }
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

function scan_one_file(string $root, string $path, string $rel, array $intel, array $coreChecksums, array $componentChecksums, bool $verifyAll): void {
    global $maxTextSizeMb;

    $hashes = file_hashes($path);
    if (!$hashes) {
        return;
    }

    if (is_whitelisted($hashes, $intel['file_whitelist'])) {
        return;
    }

    $rel = normalize_relative($rel);
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
            maybe_offer_original_repair('core', null, null, $rel, $path, $expected);
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
            'severity' => $component['type'] === 'plugin' ? 'high' : 'high',
            'type' => "modified_official_{$component['type']}",
            'component' => $component['slug'],
            'component_version' => $component['version'],
            'path' => $path,
            'relative_path' => $rel,
            'reason' => ucfirst($component['type']) . ' file hash does not match checksum intel.',
            'hashes' => $hashes,
            'expected' => $component['expected'],
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
            maybe_offer_original_repair($component['type'], $component['slug'], $component['version'], $rel, $path, $component['expected'], $component['clean_zip'] ?? null);
        }
    }

    if ($verifyAll && !$component) {
        $componentContext = component_context_for_path($rel, $componentChecksums);
        if ($componentContext) {
            add_finding([
                'severity' => 'high',
                'type' => "extra_{$componentContext['type']}_file",
                'component' => $componentContext['slug'],
                'component_version' => $componentContext['version'],
                'path' => $path,
                'relative_path' => $rel,
                'reason' => ucfirst($componentContext['type']) . ' has checksum intel, but this file is not listed in that expected file map.',
                'hashes' => $hashes,
                'recommended_action' => 'Inspect the file. If legitimate, regenerate or approve checksum intel from a clean package.',
            ], true);
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

    $size = @filesize($path);
    if (is_int($size) && $size > ($maxTextSizeMb * 1024 * 1024)) {
        stats_inc('files_skipped');
        say("[TEXT-SKIP] Regex scan skipped for large text candidate: $rel (" . round($size / 1048576, 2) . " MB)");
    } elseif (is_probably_text($path)) {
        scan_text_rules($path, $rel, $hashes, $intel['php_rules']);
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

function scan_trusted_known_good_file(string $path, string $rel, array $hashes, array $intel): void {
    return;
}

function component_expected_checksum(string $rel, array $componentChecksums): ?array {
    foreach (($componentChecksums['plugins'] ?? []) as $slug => $set) {
        $prefix = "wp-content/plugins/$slug/";
        if (strpos($rel, $prefix) !== 0) {
            continue;
        }
        $inner = substr($rel, strlen($prefix));
        if (isset($set['files'][$inner])) {
            return [
                'type' => 'plugin',
                'slug' => $slug,
                'version' => $set['version'] ?? null,
                'expected' => $set['files'][$inner],
                'clean_zip' => $set['clean_zip'] ?? null,
            ];
        }
    }

    foreach (($componentChecksums['themes'] ?? []) as $slug => $set) {
        $prefix = "wp-content/themes/$slug/";
        if (strpos($rel, $prefix) !== 0) {
            continue;
        }
        $inner = substr($rel, strlen($prefix));
        if (isset($set['files'][$inner])) {
            return [
                'type' => 'theme',
                'slug' => $slug,
                'version' => $set['version'] ?? null,
                'expected' => $set['files'][$inner],
                'clean_zip' => $set['clean_zip'] ?? null,
            ];
        }
    }

    return null;
}

function component_context_for_path(string $rel, array $componentChecksums): ?array {
    foreach (($componentChecksums['plugins'] ?? []) as $slug => $set) {
        $prefix = "wp-content/plugins/$slug/";
        if (strpos($rel, $prefix) === 0) {
            return [
                'type' => 'plugin',
                'slug' => $slug,
                'version' => $set['version'] ?? null,
            ];
        }
    }

    foreach (($componentChecksums['themes'] ?? []) as $slug => $set) {
        $prefix = "wp-content/themes/$slug/";
        if (strpos($rel, $prefix) === 0) {
            return [
                'type' => 'theme',
                'slug' => $slug,
                'version' => $set['version'] ?? null,
            ];
        }
    }

    return null;
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

function is_probably_text(string $path): bool {
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    $textExt = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'js', 'htaccess', 'txt', 'html', 'css', 'inc'];
    if (in_array($ext, $textExt, true)) {
        return true;
    }
    $sample = @file_get_contents($path, false, null, 0, 512);
    return is_string($sample) && strpos($sample, "\0") === false;
}

function scan_text_rules(string $path, string $rel, array $hashes, array $rules): void {
    $data = @file_get_contents($path);
    if ($data === false) {
        return;
    }

    scan_builtin_text_heuristics($path, $rel, $hashes, $data);

    if (!should_run_external_php_rules($rel, $data)) {
        return;
    }

    foreach ($rules as $rule) {
        $pattern = $rule['pattern'] ?? null;
        if (!$pattern) {
            continue;
        }
        $regex = '/' . str_replace('/', '\\/', $pattern) . '/i';
        $matched = false;
        $matchedText = null;

        if (($rule['type'] ?? '') === 'regex_line') {
            $lines = preg_split('/\r?\n/', $data);
            foreach ($lines as $idx => $line) {
                if (strlen($line) > 20000) {
                    continue;
                }
                if (@preg_match($regex, $line)) {
                    $matched = $idx + 1;
                    $matchedText = trim($line);
                    break;
                }
            }
        } else {
            $matched = @preg_match($regex, $data) ? true : false;
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
        }
    }
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
            'pattern' => '/\$_COOKIE[\s\S]{0,1200}base64_decode\s*\(\s*str_rot13\s*\([\s\S]{0,1200}(tempnam|fopen|fputs|require_once)/i',
            'reason' => 'Cookie-supplied payload is str_rot13/base64 decoded, written to a temp file, and loaded.',
        ],
        [
            'id' => 'BUILTIN_AUTOLOAD_TEMP_REQUIRE_001',
            'severity' => 'critical',
            'pattern' => '/spl_autoload_register\s*\([\s\S]{0,1500}tempnam\s*\([\s\S]{0,1500}require_once\s*\(/i',
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
            'pattern' => '/(?=[\s\S]*filemtime\s*\([\s\S]{0,200}index\.php)(?=[\s\S]*\btouch\s*\()(?=[\s\S]*updateFileDates\s*\()(?=[\s\S]*(wp-content\/themes|wp-content\/plugins))(?=[\s\S]*STATUS\|OK)(?=[\s\S]*unlink\s*\(\s*__FILE__\s*\))/i',
            'reason' => 'Self-deleting WordPress timestomper resets plugin/theme file dates to hide recently changed files.',
        ],
    ];

    foreach ($heuristics as $rule) {
        if (!empty($rule['requires_php_or_execution_context']) && !$hasPhpOpenTag && !$hasExecutionContext && !$isPhpLike) {
            continue;
        }
        if (@preg_match($rule['pattern'], $data)) {
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
        }
    }
}

function has_php_open_tag(string $data): bool {
    return strpos($data, '<?') !== false && preg_match('/<\?(php|=|\s)/i', $data) === 1;
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

    say("[{$severity}] {$finding['type']}: {$finding['relative_path']}");

    $fileAction = $finding['file_action'] ?? true;
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
    global $apply, $interactive, $nonInteractive, $quarantineDir, $handledInteractivePaths;

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
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
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
    if (preg_match('#^(wp-admin/|wp-includes/)#', $rel)) {
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
