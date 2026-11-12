#!/usr/bin/env php
<?php
/**
 * WP Warden report remediation helper.
 *
 * Quarantines only explicitly allow-listed, high-confidence finding types from
 * an existing WP Warden JSON report. This is intended for cron/noninteractive
 * workflows where the scanner itself remains report-first.
 */

const WP_WARDEN_AUTO_QUARANTINE_VERSION = '0.1.0';

$opts = parse_args($argv);
if (isset($opts['help']) || empty($opts['report']) || empty($opts['quarantine'])) {
    print_help();
    exit(isset($opts['help']) ? 0 : 1);
}

$reportPath = normalize_path((string)$opts['report']);
$quarantineDir = normalize_path((string)$opts['quarantine']);
$apply = isset($opts['apply']);

$allowedTypes = [
    'extra_core_file',
    'executable_in_uploads',
    'php_code_in_non_php_file',
];

if (!is_file($reportPath)) {
    fwrite(STDERR, "ERROR: report does not exist: $reportPath\n");
    exit(1);
}

$raw = file_get_contents($reportPath);
$report = is_string($raw) ? json_decode($raw, true) : null;
if (!is_array($report)) {
    fwrite(STDERR, "ERROR: invalid WP Warden JSON report: $reportPath\n");
    exit(1);
}

$target = normalize_path((string)($report['target'] ?? ''));
if ($target === '' || !is_dir($target)) {
    fwrite(STDERR, "ERROR: report target is missing or no longer exists.\n");
    exit(1);
}

$actions = [];
foreach (($report['findings'] ?? []) as $finding) {
    if (!is_array($finding)) {
        continue;
    }

    $type = (string)($finding['type'] ?? '');
    $severity = strtolower((string)($finding['severity'] ?? ''));
    if (!in_array($type, $allowedTypes, true) || $severity !== 'critical') {
        continue;
    }

    $src = normalize_path((string)($finding['path'] ?? ''));
    $rel = normalize_relative((string)($finding['relative_path'] ?? ''));
    if ($src === '' || $rel === '' || !is_file($src)) {
        continue;
    }

    // Never trust a report path blindly. The file must still resolve inside the
    // WordPress target and its current hash must match the finding we reviewed.
    $srcReal = realpath($src);
    $targetReal = realpath($target);
    if (!$srcReal || !$targetReal || strpos(normalize_path($srcReal), rtrim(normalize_path($targetReal), '/') . '/') !== 0) {
        fwrite(STDERR, "[SKIP] path escaped report target: $rel\n");
        continue;
    }

    $expectedSha256 = strtolower((string)($finding['hashes']['sha256'] ?? ''));
    if ($expectedSha256 !== '') {
        $currentSha256 = strtolower((string)hash_file('sha256', $srcReal));
        if (!hash_equals($expectedSha256, $currentSha256)) {
            fwrite(STDERR, "[SKIP] file changed since scan: $rel\n");
            continue;
        }
    }

    $dest = rtrim($quarantineDir, '/') . '/' . $rel;
    if (!$apply) {
        echo "[DRY-RUN] Would quarantine [$type] $rel -> $dest\n";
        continue;
    }

    $dir = dirname($dest);
    if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
        fwrite(STDERR, "[FAIL] could not create quarantine directory for $rel\n");
        continue;
    }

    if (file_exists($dest)) {
        $dest .= '.quarantine-' . gmdate('Ymd-His');
    }

    if (!@rename($srcReal, $dest)) {
        fwrite(STDERR, "[FAIL] could not quarantine $rel\n");
        continue;
    }

    $action = [
        'type' => 'auto_quarantine',
        'finding_id' => $finding['id'] ?? null,
        'finding_type' => $type,
        'from' => $srcReal,
        'to' => $dest,
        'sha256' => $expectedSha256 ?: null,
        'at' => gmdate('c'),
    ];
    $actions[] = $action;
    append_manifest($quarantineDir, $action, $finding);
    echo "[QUARANTINED] [$type] $rel -> $dest\n";
}

echo $apply
    ? 'Automatic quarantine complete. Actions: ' . count($actions) . PHP_EOL
    : "Dry run complete. Re-run with --apply to move eligible files.\n";
exit(0);

function parse_args(array $argv): array {
    $opts = [];
    foreach (array_slice($argv, 1) as $arg) {
        if (substr($arg, 0, 2) !== '--') {
            continue;
        }
        $eq = strpos($arg, '=');
        if ($eq === false) {
            $opts[substr($arg, 2)] = true;
        } else {
            $opts[substr($arg, 2, $eq - 2)] = substr($arg, $eq + 1);
        }
    }
    return $opts;
}

function normalize_path(string $path): string {
    return rtrim(str_replace('\\', '/', $path), '/');
}

function normalize_relative(string $path): string {
    return ltrim(normalize_path($path), '/');
}

function append_manifest(string $quarantineDir, array $action, array $finding): void {
    $manifest = rtrim($quarantineDir, '/') . '/manifest.jsonl';
    file_put_contents($manifest, json_encode([
        'action' => $action,
        'finding' => $finding,
    ], JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function print_help(): void {
    echo "WP Warden automatic quarantine helper " . WP_WARDEN_AUTO_QUARANTINE_VERSION . "\n\n";
    echo "USAGE:\n";
    echo "  php auto-quarantine-report.php --report=/path/site.json --quarantine=/path/quarantine [--apply]\n\n";
    echo "High-confidence critical types eligible for automatic quarantine:\n";
    echo "  - extra_core_file\n";
    echo "  - executable_in_uploads\n";
    echo "  - php_code_in_non_php_file\n\n";
    echo "Without --apply this helper performs a dry run only.\n";
}
