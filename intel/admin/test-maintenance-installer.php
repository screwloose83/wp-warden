<?php
// Fixtures are scanned as data, never included or executed.
$repo = dirname(__DIR__, 2);
$fixture = file_get_contents(__DIR__ . '/maintenance-installer-fixture.txt');
$tail = "\n/** Custom child theme */\nfunction keep_custom_code() { return 'preserved'; }\nadd_action('init', 'keep_custom_code');\n";
$sample = rtrim($fixture) . $tail;
$base = sys_get_temp_dir() . '/warden-installer-test-' . bin2hex(random_bytes(6));
function check($condition, $message) {
    if (!$condition) { throw new RuntimeException($message); }
}
foreach (['report', 'repair', 'blocked-backup', 'changed-installer', 'invalid-tail', 'spacing'] as $mode) {
    $root = $base . '/' . $mode;
    mkdir($root . '/wp-content/themes/custom-child', 0700, true);
    $path = $root . '/wp-content/themes/custom-child/functions.php';
    $input = $sample;
    if ($mode === 'changed-installer') { $input = str_replace('@file_put_contents', 'legitimate_extra_call(); @file_put_contents', $input); }
    if ($mode === 'invalid-tail') { $input .= "\nfunction broken( {"; }
    if ($mode === 'spacing') { $input = str_replace("\t", '    ', $input); }
    file_put_contents($path, $input);
    $backup = $base . '/' . $mode . '-backup';
    if ($mode === 'blocked-backup') { file_put_contents($backup, 'not a directory'); }
    $report = $base . '/' . $mode . '.json';
    $args = [PHP_BINARY, $repo . '/scanner/wp-warden-pef.php', $root,
        '--intel-dir=' . $repo . '/intel', '--noninteractive', '--no-file-cache', '--quiet',
        '--repair-original-auto', '--repair-backup=' . $backup, '--report-json=' . $report];
    if ($mode !== 'report') { $args[] = '--apply'; }
    $output = [];
    exec(implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1', $output, $exit);
    check(is_file($report), 'Missing report: ' . implode("\n", $output));
    $result = json_decode(file_get_contents($report), true, 512, JSON_THROW_ON_ERROR);
    $hits = array_filter($result['findings'], fn($f) => ($f['rule_id'] ?? '') === 'BUILTIN_MAINTENANCE_STEALER_INSTALLER_001');
    check(count($hits) === ($mode === 'changed-installer' ? 0 : 1), 'Exact detection: ' . $mode);
    $shouldRepair = in_array($mode, ['repair', 'spacing'], true);
    check(file_get_contents($path) === ($shouldRepair ? '<?php' . $tail : $input), 'Preserve custom code / refuse unsafe repair: ' . $mode);
    if ($shouldRepair) {
        check(file_get_contents($backup . '/wp-content/themes/custom-child/functions.php') === $input, 'Exact original backup');
        $actions = array_filter($result['actions'], fn($a) => $a['type'] === 'repair_maintenance_installer');
        check(count($actions) === 1, 'Repair action recorded');
        exec(implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1', $output, $exit);
        $again = json_decode(file_get_contents($report), true, 512, JSON_THROW_ON_ERROR);
        check(count(array_filter($again['findings'], fn($f) => ($f['rule_id'] ?? '') === 'BUILTIN_MAINTENANCE_STEALER_INSTALLER_001')) === 0, 'Second scan is clean of this installer');
        check(file_get_contents($path) === '<?php' . $tail, 'Repair is idempotent');
    }
}
echo "PASS installer detection, exact repair, backup, report-only, spacing, changed code, invalid PHP, failed backup and repeat scan\n";
echo "Inert artifacts: $base\n";
