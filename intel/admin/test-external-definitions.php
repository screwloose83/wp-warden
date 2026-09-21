<?php
// Synthetic signature fixtures are inert data, never evaluated.
$repo = dirname(__DIR__, 2);
$bundle = json_decode(file_get_contents($repo . '/intel/patterns/external-malware-rules.json'), true, 512, JSON_THROW_ON_ERROR);
$base = sys_get_temp_dir() . '/warden-external-test-' . bin2hex(random_bytes(6));
$root = $base . '/site';
mkdir($root . '/wp-content/mu-plugins', 0700, true);
function check($condition, $message) { if (!$condition) { throw new RuntimeException($message); } }
$expected = [];
foreach ($bundle['rules'] as $rule) {
    $name = $rule['source_rule'];
    $path = 'wp-content/mu-plugins/' . $name . '.php';
    file_put_contents($root . '/' . $path, "<?php\n/*\n" . implode("\n", $rule['anchors']) . "\n*/");
    $expected[$path] = $rule['id'];
    foreach ($rule['anchors'] as $i => $anchor) {
        file_put_contents($root . '/wp-content/mu-plugins/partial-' . $name . '-' . $i . '.php', "<?php\n/* " . $anchor . ' */');
    }
}
file_put_contents($root . '/wp-content/mu-plugins/benign.php', <<<'PHP'
<?php
class PHPMailer {}
class phpmailerException extends Exception {}
// Documentation: https://shodan.io https://www.rapid7.com
function run_health_check() { return 'ipconfig /all'; }
PHP
);
$report = $base . '/report.json';
$args = [PHP_BINARY, $repo . '/scanner/wp-warden-pef.php', $root,
    '--intel-dir=' . $repo . '/intel', '--noninteractive', '--no-file-cache', '--quiet',
    '--apply', '--quarantine-malware-auto', '--quarantine=' . $base . '/quarantine', '--report-json=' . $report];
exec(implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1', $output, $exit);
check(is_file($report), 'Missing scan report: ' . implode("\n", $output));
$result = json_decode(file_get_contents($report), true, 512, JSON_THROW_ON_ERROR);
$hits = array_values(array_filter($result['findings'], fn($f) => strpos($f['rule_id'] ?? '', 'EXTERNAL_') === 0));
check(count($hits) === count($expected), 'Exactly one external finding per positive, no partial/benign matches');
foreach ($hits as $hit) {
    check(($expected[$hit['relative_path']] ?? null) === $hit['rule_id'], 'Correct family and path');
    check($hit['file_action'] === false, 'External finding must be report-only');
    check($hit['source_revision'] === $bundle['source_revision'], 'Revision retained');
    check($hit['rule_source'] === $bundle['source'], 'Source retained');
    check(is_file($root . '/' . $hit['relative_path']), 'Automatic cleanup must preserve external-only matches');
}
check(count($result['actions']) === 0, 'No remediation actions for external-only matches');

// Verify feed-supplied IDs and report_only=false cannot claim trusted cleanup.
$source = file_get_contents($repo . '/scanner/wp-warden-pef.php');
foreach (['load_php_pattern_rules', 'prepare_php_pattern_rule', 'build_file_cache_context', 'rule_enabled'] as $name) {
    check(preg_match('/^function ' . $name . '\b[\s\S]*?(?=^function |\z)/m', $source, $m) === 1, 'Helper exists');
    eval($m[0]); // Trusted local definitions only, never fixture code.
}
function say($message, $unused = false) {}
function json_file($path) { return json_decode(file_get_contents($path), true); }
function warden_preg_match($regex, $data, &$matches = null, $flags = 0, $offset = 0, $context = []) { return preg_match($regex, $data, $matches, $flags, $offset); }
define('WP_WARDEN_CACHE_VERSION', 'test');
define('WP_WARDEN_VERSION', 'test');
mkdir($base . '/intel/patterns', 0700, true);
$fake = $bundle['rules'][0];
$fake['id'] = 'PHP_WP_MAINTENANCE_CREDENTIAL_STEALER_001';
$fake['report_only'] = false;
file_put_contents($base . '/intel/patterns/external-malware-rules.json', json_encode(['rules' => [$fake]]));
$loaded = load_php_pattern_rules($base . '/intel');
check($loaded[0]['_external_report_only'] === true && strpos($loaded[0]['id'], 'EXTERNAL_') === 0, 'Feed cannot impersonate a trusted rule');
$before = build_file_cache_context(['php_rules' => $loaded], [], [], false, 1, 1, false);
$loaded[0]['pattern'] .= 'updated';
$after = build_file_cache_context(['php_rules' => $loaded], [], [], false, 1, 1, false);
check($before !== $after, 'Definition changes invalidate cached scan context');
echo 'PASS ' . count($expected) . " external families, single-indicator negatives, benign controls, provenance, report-only cleanup, ID isolation and cache invalidation\n";
