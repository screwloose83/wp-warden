<?php
require dirname(__DIR__, 2) . '/scanner/core-directory-review.php';
function normalize_path($p) { return str_replace('\\', '/', $p); }
function should_skip_path($p, $intel) { return in_array(rtrim($p, '/'), $intel['skip'] ?? [], true); }
function say($text, $unused = false) {}
function add_finding($f) { $GLOBALS['state']['findings'][] = $f; }
function check($ok, $message) { if (!$ok) { throw new RuntimeException($message); } }
$base = sys_get_temp_dir() . '/warden-core-dirs-' . bin2hex(random_bytes(6));
$root = $base . '/site';
$rel = 'wp-includes/rest-api/abzkhvx';
mkdir($root . '/' . $rel . '/ujnlrmw/qpnygxw', 0700, true);
mkdir($root . '/wp-admin/css', 0700, true);
mkdir($root . '/wp-includes/rest-api/endpoints', 0700, true);
file_put_contents($root . '/' . $rel . '/ujnlrmw/qpnygxw/anonymousfox.php', '<?php /* inert */');
file_put_contents($root . '/' . $rel . '/.htaccess', 'hidden evidence');
$checksums = ['wp-admin/index.php' => 'x', 'wp-admin/css/common.css' => 'x',
    'wp-includes/version.php' => 'x', 'wp-includes/rest-api/endpoints/class-wp-rest-posts-controller.php' => 'x'];
$expected = expected_core_directories($checksums);
$state = ['findings' => [], 'actions' => [], 'summary' => ['actions_taken' => 0]];
$interactive = isset($argv[1]) && $argv[1] === '--prompt';
$nonInteractive = !$interactive;
$apply = true;
$quarantineDir = $base . '/quarantine';
audit_extra_core_directories($root, $checksums, []);
check(count($state['findings']) === 1 && $state['findings'][0]['relative_path'] === $rel . '/', 'Only outermost unexpected directory reported');
if ($interactive) {
    check(!is_dir($root . '/' . $rel), 'Prompt must quarantine tree');
    check($state['summary']['actions_taken'] === 1 && $state['findings'][0]['action_taken'] === 'quarantine_extra_core_directory', 'Action recorded');
    echo "PASS interactive view and quarantine\n";
    exit;
}
check(is_file($root . '/' . $rel . '/.htaccess'), 'Noninteractive audit preserves files');
foreach (['wp-includes', 'wp-includes/rest-api', 'wp-admin/css', 'wp-includes/../wp-content', '../outside', 'wp-includes//extra'] as $bad) {
    check(extra_core_directory_path($root, $bad, $expected) === null, 'Refuse protected/unsafe path: ' . $bad);
}
$state['findings'] = [];
audit_extra_core_directories($root, [], []);
check(!$state['findings'], 'No manifest means no directory finding');
audit_extra_core_directories($root, ['wp-includes/version.php' => 'x'], []);
check(!$state['findings'], 'Obvious partial manifest skipped');
audit_extra_core_directories($root, $checksums, ['skip' => [$rel]]);
check(!$state['findings'], 'Directory exclusion respected');
$apply = false;
check(!extra_core_directory_action($root, $rel, $expected, 'D')['success'], 'Apply required');
$apply = true;
$quarantineDir = $root . '/quarantine';
check(!extra_core_directory_action($root, $rel, $expected, 'Q')['success'], 'In-site quarantine rejected');
$quarantineDir = $base . '/quarantine';
$q = extra_core_directory_action($root, $rel, $expected, 'Q');
check($q['success'], 'Quarantine tree: ' . ($q['error'] ?? ''));
check(file_get_contents($q['destination'] . '/.htaccess') === 'hidden evidence', 'Hidden file preserved');
check(is_file($q['destination'] . '/ujnlrmw/qpnygxw/anonymousfox.php'), 'Nested payload preserved');
check(is_dir($root . '/wp-includes/rest-api/endpoints'), 'Legitimate directory untouched');
mkdir($root . '/' . $rel . '/empty/nested', 0700, true);
$state['findings'] = [];
audit_extra_core_directories($root, $checksums, []);
check(count($state['findings']) === 1, 'Empty trees reported');
file_put_contents($root . '/' . $rel . '/.hidden', 'inert');
$deleted = extra_core_directory_action($root, $rel, $expected, 'D');
check($deleted['success'] && !is_dir($root . '/' . $rel), 'Delete complete tree: ' . ($deleted['error'] ?? ''));
check(is_dir($root . '/wp-includes/rest-api'), 'Delete stops at official parent');
mkdir($root . '/' . $rel, 0700, true);
mkdir($base . '/outside', 0700, true);
file_put_contents($base . '/outside/keep.txt', 'keep');
if (@symlink($base . '/outside', $root . '/' . $rel . '/link')) {
    check(!extra_core_directory_action($root, $rel, $expected, 'D')['success'], 'Symlink tree refused');
    check(is_file($base . '/outside/keep.txt'), 'External link target untouched');
    echo "PASS symlink boundary\n";
} else { echo "SKIP symlink creation unavailable on this host\n"; }
$proc = proc_open([PHP_BINARY, __FILE__, '--prompt'], [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
fwrite($pipes[0], "V\nQ\n"); fclose($pipes[0]);
$out = stream_get_contents($pipes[1]); fclose($pipes[1]);
$err = stream_get_contents($pipes[2]); fclose($pipes[2]);
check(proc_close($proc) === 0 && strpos($out, '.htaccess') !== false && strpos($out, 'PASS interactive') !== false, 'Interactive contents and Q: ' . $out . $err);

// Exercise the real --verify-all entry point with a local version-specific map.
$site = $base . '/integration';
mkdir($site . '/wp-admin', 0700, true);
mkdir($site . '/wp-includes/rest-api/extra/empty', 0700, true);
file_put_contents($site . '/wp-admin/index.php', '<?php // fixture');
file_put_contents($site . '/wp-includes/version.php', "<?php\n\$wp_version = '6.8.2';\n");
mkdir($base . '/intel/checksums/wordpress-core', 0700, true);
$map = ['wp-admin/index.php' => md5_file($site . '/wp-admin/index.php'),
    'wp-includes/version.php' => md5_file($site . '/wp-includes/version.php'),
    'wp-includes/rest-api/official.php' => md5('fixture')];
file_put_contents($base . '/intel/checksums/wordpress-core/6.8.2.json', json_encode(['checksums' => $map]));
$report = $base . '/integration.json';
$args = [PHP_BINARY, dirname(__DIR__, 2) . '/scanner/wp-warden-pef.php', $site,
    '--verify-all', '--noninteractive', '--no-file-cache', '--quiet',
    '--intel-dir=' . $base . '/intel', '--report-json=' . $report];
exec(implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1', $lines, $exit);
check(is_file($report), 'Full scanner report: ' . implode("\n", $lines));
$result = json_decode(file_get_contents($report), true, 512, JSON_THROW_ON_ERROR);
$hits = array_values(array_filter($result['findings'], fn($f) => ($f['type'] ?? '') === 'extra_core_directory'));
check(count($hits) === 1 && $hits[0]['relative_path'] === 'wp-includes/rest-api/extra/', 'Full scanner detects extra directory');
check(is_dir($site . '/wp-includes/rest-api/extra/empty'), 'Full report-only scan preserves empty tree');
echo "PASS extra core directory detection, empty trees, view/quarantine prompt, deletion, manifest guards, exclusions and path protection\n";
