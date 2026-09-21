<?php
$source = file_get_contents(dirname(__DIR__, 2) . '/scanner/wp-warden-pef.php');
foreach (['write_file_cache_stream', 'save_file_cache', 'load_file_cache'] as $name) {
    if (!preg_match('/^function ' . $name . '\b[\s\S]*?(?=^function |\z)/m', $source, $m)) { throw new RuntimeException('Missing helper'); }
    eval($m[0]); // Trusted local scanner definitions only.
}
unset($source, $m);
define('WP_WARDEN_VERSION', 'test');
define('WP_WARDEN_CACHE_VERSION', '3');
function normalize_path($path) { return str_replace('\\', '/', $path); }
function say($text, $unused = false) {}
function json_file($path) { return json_decode(file_get_contents($path), true); }
function check($ok, $message) { if (!$ok) { throw new RuntimeException($message); } }
$dir = sys_get_temp_dir() . '/warden-cache-test-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
$fileCacheEnabled = true;
$fileCacheDir = $dir;
$fileCachePath = $dir . '/cache.json';
$fileCacheSignature = 'test-signature';
$fileCacheDirty = true;
$wpRoot = $dir;
$state = ['summary' => []];
$fileCacheEntries = [];
$fileCacheSeen = [];
if (($argv[1] ?? '') === '--low-memory') {
    // The encoded cache alone exceeds this child's entire 32 MB limit. Shared
    // stat values keep fixture creation cheap, isolating serialization overhead.
    $value = ['mtime' => '123', 'size' => '4096', 'scan_signature' => str_repeat('a', 640)];
    for ($i = 0; $i < 45000; $i++) {
        $path = 'wp-content/plugins/example/' . str_repeat('x', 100) . '/' . $i . '.php';
        $fileCacheEntries[$path] = $value;
        $fileCacheSeen[$path] = true;
    }
    $before = memory_get_usage(true);
    save_file_cache();
    check(!$fileCacheDirty && is_file($fileCachePath), 'Low-memory save succeeds');
    check(filesize($fileCachePath) > 32 * 1024 * 1024, 'Cache JSON exceeds PHP memory budget');
    check(memory_get_peak_usage(true) - $before < 8 * 1024 * 1024, 'Bounded serialization overhead');
    echo 'PASS low-memory save: ' . filesize($fileCachePath) . ' bytes, peak ' . memory_get_peak_usage(true) . " bytes\n";
    unlink($fileCachePath); rmdir($dir);
    exit;
}
$fileCacheEntries = ['a/"quoted".php' => ['size' => '3'], 'unicode-é.php' => ['size' => '4'], 'gone.php' => ['size' => '8']];
$fileCacheSeen = ['a/"quoted".php' => true, 'unicode-é.php' => true];
save_file_cache();
check(!$fileCacheDirty && $state['summary']['cache_entries'] === 2, 'Pruned entries saved');
check(load_file_cache($fileCachePath, $fileCacheSignature, $wpRoot) === $fileCacheEntries, 'Round-trip existing reader and path escaping');
$old = file_get_contents($fileCachePath);
$metadata = ['schema' => 'test'];
$bad = ['bad.php' => ['invalid' => "\xff"]];
check(!write_file_cache_stream($fileCachePath, $metadata, $bad), 'Invalid UTF-8 fails safely');
check(file_get_contents($fileCachePath) === $old && !glob($fileCachePath . '.tmp.*'), 'Failed write preserves original and removes temp');
$empty = [];
check(write_file_cache_stream($fileCachePath, $metadata, $empty), 'Empty cache saved');
check(json_decode(file_get_contents($fileCachePath), true)['entries'] === [], 'Empty entries parse');
mkdir($dir . '/blocked');
check(!write_file_cache_stream($dir . '/blocked', $metadata, $empty), 'Rename failure reported');
check(is_dir($dir . '/blocked') && !glob($dir . '/blocked.tmp.*'), 'Rename failure leaves destination intact and removes temp');
$args = [PHP_BINARY, '-d', 'memory_limit=32M', __FILE__, '--low-memory'];
exec(implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1', $output, $exit);
check($exit === 0, 'Low-memory child: ' . implode("\n", $output));
echo implode("\n", $output) . "\nPASS cache schema, pruning, escaping, invalid input, atomic replacement and failure cleanup\n";
