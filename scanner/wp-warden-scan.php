#!/usr/bin/env php
<?php
/**
 * WP Warden combined scan wrapper.
 *
 * Runs the normal WP Warden malware/integrity scan and, when available,
 * 10up/wpcli-vulnerability-scanner through WP-CLI. The resulting vulnerability
 * data is normalised and merged into the WP Warden JSON report.
 *
 * This file does not copy or embed the 10up scanner. It invokes the separately
 * installed MIT-licensed WP-CLI package.
 */

declare(strict_types=1);

const WP_WARDEN_COMBINED_VERSION = '0.1.0';

$options = parse_combined_args($argv);
if (isset($options['help']) || empty($options['target'])) {
    print_combined_help();
    exit(isset($options['help']) ? 0 : 2);
}

$target = realpath((string)$options['target']);
if ($target === false || !is_dir($target)) {
    fwrite(STDERR, "ERROR: WordPress target is not a directory.\n");
    exit(2);
}

$wpWarden = realpath(__DIR__ . '/wp-warden.php');
if ($wpWarden === false || !is_file($wpWarden)) {
    fwrite(STDERR, "ERROR: wp-warden.php was not found beside this wrapper.\n");
    exit(2);
}

$phpBin = isset($options['php-bin']) ? (string)$options['php-bin'] : PHP_BINARY;
$wpBin = isset($options['wp-bin']) ? (string)$options['wp-bin'] : 'wp';
$skipVulnerabilities = isset($options['skip-vulnerabilities']);
$requireVulnerabilities = isset($options['require-vulnerabilities']);
$keepIntermediate = isset($options['keep-intermediate']);
$finalReport = isset($options['report-json']) && is_string($options['report-json'])
    ? $options['report-json']
    : null;

$temporaryReport = tempnam(sys_get_temp_dir(), 'wp-warden-report-');
if ($temporaryReport === false) {
    fwrite(STDERR, "ERROR: Unable to create a temporary report file.\n");
    exit(2);
}

$scannerArgs = build_scanner_args($argv, $target, $temporaryReport);
$scannerCommand = array_merge([$phpBin, $wpWarden], $scannerArgs);

fwrite(STDERR, "WP Warden combined scan " . WP_WARDEN_COMBINED_VERSION . "\n");
fwrite(STDERR, "Running malware and integrity scan...\n");
$scannerResult = run_process($scannerCommand, $target);

$report = read_json_object($temporaryReport);
if ($report === null) {
    @unlink($temporaryReport);
    fwrite(STDERR, "ERROR: WP Warden did not produce a valid JSON report.\n");
    if ($scannerResult['stderr'] !== '') {
        fwrite(STDERR, $scannerResult['stderr']);
    }
    exit($scannerResult['exit_code'] !== 0 ? $scannerResult['exit_code'] : 2);
}

$report['combined_scan'] = [
    'version' => WP_WARDEN_COMBINED_VERSION,
    'scanner_exit_code' => $scannerResult['exit_code'],
];

if ($skipVulnerabilities) {
    $report['vulnerability_exposure'] = vulnerability_unavailable(
        'skipped',
        'Vulnerability exposure checking was disabled by --skip-vulnerabilities.'
    );
} else {
    fwrite(STDERR, "Checking vulnerability exposure...\n");
    $vulnerabilityResult = run_vulnerability_scan($wpBin, $target);
    $report['vulnerability_exposure'] = $vulnerabilityResult['report'];
    $report['combined_scan']['vulnerability_exit_code'] = $vulnerabilityResult['exit_code'];
}

recalculate_combined_summary($report);

if ($finalReport !== null) {
    write_json_file($finalReport, $report);
    fwrite(STDERR, "Combined report written: {$finalReport}\n");
} else {
    fwrite(STDOUT, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
}

if ($keepIntermediate) {
    fwrite(STDERR, "Intermediate WP Warden report: {$temporaryReport}\n");
} else {
    @unlink($temporaryReport);
}

$vulnerabilityStatus = $report['vulnerability_exposure']['status'] ?? 'unavailable';
if ($requireVulnerabilities && $vulnerabilityStatus !== 'ok') {
    exit(3);
}

$critical = (int)($report['summary']['critical'] ?? 0);
$high = (int)($report['summary']['high'] ?? 0);
exit(($critical > 0 || $high > 0) ? 1 : 0);

function parse_combined_args(array $argv): array
{
    $result = [];
    foreach (array_slice($argv, 1) as $arg) {
        if (strncmp($arg, '--', 2) === 0) {
            $equal = strpos($arg, '=');
            if ($equal === false) {
                $result[substr($arg, 2)] = true;
            } else {
                $result[substr($arg, 2, $equal - 2)] = substr($arg, $equal + 1);
            }
            continue;
        }
        if (!isset($result['target'])) {
            $result['target'] = $arg;
        }
    }
    return $result;
}

function print_combined_help(): void
{
    echo <<<'HELP'
WP Warden combined malware, integrity and vulnerability scan

USAGE:
  php wp-warden-scan.php /path/to/wordpress [WP Warden options] [wrapper options]

WRAPPER OPTIONS:
  --report-json=FILE          Write the combined JSON report to FILE
  --wp-bin=PATH               WP-CLI executable (default: wp)
  --php-bin=PATH              PHP executable used for wp-warden.php
  --skip-vulnerabilities      Run only malware and integrity checks
  --require-vulnerabilities   Fail with exit code 3 when vulnerability data is unavailable
  --keep-intermediate         Retain the temporary scanner report
  --help                      Show this help

All other options are forwarded to wp-warden.php. The wrapper replaces any
forwarded --report-json value with its own temporary report, then writes the
combined report to the requested destination.

PREREQUISITE:
  wp package install 10up/wpcli-vulnerability-scanner:dev-stable

EXAMPLE:
  php wp-warden-scan.php /home/virtual/example.com/var/www/html \
    --intel-dir=/var/lib/wp-warden/intel \
    --policy=apiscp \
    --site-id=example.com \
    --verify-all \
    --fetch-official-checksums \
    --noninteractive \
    --report-json=/var/log/wp-warden/example.com.json

HELP;
}

function build_scanner_args(array $argv, string $target, string $temporaryReport): array
{
    $args = [$target];
    $wrapperOnly = [
        'help',
        'wp-bin',
        'php-bin',
        'skip-vulnerabilities',
        'require-vulnerabilities',
        'keep-intermediate',
    ];

    foreach (array_slice($argv, 1) as $arg) {
        if (strncmp($arg, '--', 2) !== 0) {
            continue;
        }
        $name = substr($arg, 2);
        $equal = strpos($name, '=');
        if ($equal !== false) {
            $name = substr($name, 0, $equal);
        }
        if ($name === 'report-json' || in_array($name, $wrapperOnly, true)) {
            continue;
        }
        $args[] = $arg;
    }

    $args[] = '--report-json=' . $temporaryReport;
    return $args;
}

function run_vulnerability_scan(string $wpBin, string $target): array
{
    $command = [$wpBin, '--path=' . $target, 'vuln', 'status', '--format=json', '--reference'];
    $result = run_process($command, $target);

    if ($result['exit_code'] !== 0 && trim($result['stdout']) === '') {
        return [
            'exit_code' => $result['exit_code'],
            'report' => vulnerability_unavailable(
                'unavailable',
                trim($result['stderr']) !== ''
                    ? trim($result['stderr'])
                    : 'WP-CLI vulnerability command failed.'
            ),
        ];
    }

    $raw = extract_json_object($result['stdout']);
    if ($raw === null) {
        return [
            'exit_code' => $result['exit_code'],
            'report' => vulnerability_unavailable(
                'invalid-response',
                'The WP-CLI vulnerability command did not return valid JSON.'
            ),
        ];
    }

    $normalised = normalise_vulnerability_report($raw);
    return [
        'exit_code' => $result['exit_code'],
        'report' => $normalised,
    ];
}

function normalise_vulnerability_report(array $raw): array
{
    $items = [];
    foreach (['core' => 'core', 'plugins' => 'plugin', 'themes' => 'theme'] as $section => $type) {
        $rows = $raw[$section] ?? [];
        if (!is_array($rows)) {
            continue;
        }
        foreach ($rows as $row) {
            if (!is_array($row) || !row_is_vulnerable($row)) {
                continue;
            }
            $severityText = first_string($row, ['severity', 'cvss', 'risk']);
            $severity = normalise_severity($severityText);
            $items[] = [
                'type' => $type,
                'name' => first_string($row, ['name', 'slug']),
                'installed_version' => first_string($row, ['installed version', 'installed_version', 'version']),
                'status' => first_string($row, ['status', 'title', 'vulnerability']),
                'introduced_in' => first_string($row, ['introduced in', 'introduced_in']),
                'fixed_in' => first_string($row, ['fixed in', 'fixed_in', 'fixed_version']),
                'severity' => $severity,
                'severity_raw' => $severityText,
                'reference' => first_string($row, ['reference', 'references', 'url']),
                'source' => '10up/wpcli-vulnerability-scanner',
            ];
        }
    }

    $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'unknown' => 0];
    foreach ($items as $item) {
        $severity = $item['severity'];
        $counts[$severity] = ($counts[$severity] ?? 0) + 1;
    }

    return [
        'status' => 'ok',
        'checked_at' => gmdate('c'),
        'source' => '10up/wpcli-vulnerability-scanner',
        'counts' => $counts,
        'total' => count($items),
        'items' => $items,
        'raw' => $raw,
    ];
}

function row_is_vulnerable(array $row): bool
{
    $status = strtolower(first_string($row, ['status', 'title', 'vulnerability']));
    if ($status === '') {
        return false;
    }
    foreach ([
        'no vulnerabilities reported',
        'no vulnerability reported',
        'not vulnerable',
        'n/a',
    ] as $safePhrase) {
        if (strpos($status, $safePhrase) !== false) {
            return false;
        }
    }
    return true;
}

function normalise_severity(string $value): string
{
    $lower = strtolower($value);
    foreach (['critical', 'high', 'medium', 'low'] as $severity) {
        if (strpos($lower, $severity) !== false) {
            return $severity;
        }
    }

    if (preg_match('/(?:^|\s)(10(?:\.0)?|9(?:\.\d+)?)(?:\s|\/|$)/', $lower)) {
        return 'critical';
    }
    if (preg_match('/(?:^|\s)(8(?:\.\d+)?|7(?:\.\d+)?)(?:\s|\/|$)/', $lower)) {
        return 'high';
    }
    if (preg_match('/(?:^|\s)(6(?:\.\d+)?|5(?:\.\d+)?|4(?:\.\d+)?)(?:\s|\/|$)/', $lower)) {
        return 'medium';
    }
    if (preg_match('/(?:^|\s)(3(?:\.\d+)?|2(?:\.\d+)?|1(?:\.\d+)?|0(?:\.\d+)?)(?:\s|\/|$)/', $lower)) {
        return 'low';
    }
    return 'unknown';
}

function recalculate_combined_summary(array &$report): void
{
    if (!isset($report['summary']) || !is_array($report['summary'])) {
        $report['summary'] = [];
    }

    $vulnerability = $report['vulnerability_exposure'] ?? [];
    $counts = is_array($vulnerability) && isset($vulnerability['counts']) && is_array($vulnerability['counts'])
        ? $vulnerability['counts']
        : [];

    $report['summary']['vulnerabilities_total'] = (int)($vulnerability['total'] ?? 0);
    foreach (['critical', 'high', 'medium', 'low'] as $severity) {
        $count = (int)($counts[$severity] ?? 0);
        $report['summary']['vulnerability_' . $severity] = $count;
        $report['summary'][$severity] = (int)($report['summary'][$severity] ?? 0) + $count;
    }
}

function vulnerability_unavailable(string $status, string $message): array
{
    return [
        'status' => $status,
        'checked_at' => gmdate('c'),
        'source' => '10up/wpcli-vulnerability-scanner',
        'message' => $message,
        'counts' => ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'unknown' => 0],
        'total' => 0,
        'items' => [],
    ];
}

function first_string(array $row, array $keys): string
{
    foreach ($keys as $key) {
        if (!array_key_exists($key, $row)) {
            continue;
        }
        $value = $row[$key];
        if (is_scalar($value)) {
            return trim((string)$value);
        }
        if (is_array($value)) {
            return trim(implode(', ', array_map('strval', $value)));
        }
    }
    return '';
}

function run_process(array $command, string $workingDirectory): array
{
    $spec = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    $process = proc_open($command, $spec, $pipes, $workingDirectory);
    if (!is_resource($process)) {
        return ['exit_code' => 127, 'stdout' => '', 'stderr' => 'Unable to start command.'];
    }

    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);

    if ($stderr !== '') {
        fwrite(STDERR, $stderr);
    }

    return [
        'exit_code' => is_int($exitCode) ? $exitCode : 1,
        'stdout' => is_string($stdout) ? $stdout : '',
        'stderr' => is_string($stderr) ? $stderr : '',
    ];
}

function read_json_object(string $path): ?array
{
    if (!is_file($path)) {
        return null;
    }
    $contents = file_get_contents($path);
    if (!is_string($contents)) {
        return null;
    }
    $decoded = json_decode($contents, true);
    return is_array($decoded) ? $decoded : null;
}

function extract_json_object(string $output): ?array
{
    $start = strpos($output, '{');
    $end = strrpos($output, '}');
    if ($start === false || $end === false || $end < $start) {
        return null;
    }
    $json = substr($output, $start, $end - $start + 1);
    $decoded = json_decode($json, true);
    return is_array($decoded) ? $decoded : null;
}

function write_json_file(string $path, array $data): void
{
    $directory = dirname($path);
    if (!is_dir($directory) && !mkdir($directory, 0755, true) && !is_dir($directory)) {
        throw new RuntimeException("Unable to create report directory: {$directory}");
    }
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (!is_string($json) || file_put_contents($path, $json . PHP_EOL) === false) {
        throw new RuntimeException("Unable to write report: {$path}");
    }
}
