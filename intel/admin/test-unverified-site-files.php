<?php
// Exercise the real scanner, including repeat scans through its clean-file cache.
function check($ok, $message) { if (!$ok) { throw new RuntimeException($message); } }
$base = sys_get_temp_dir() . '/warden-extra-files-' . bin2hex(random_bytes(6));
$site = $base . '/site';
$files = [
    'wp-includes/version.php' => "<?php\n\$wp_version = '6.8.2';\n",
    'wp-admin/index.php' => '<?php // official fixture',
    'wp-comments-post-loader.php' => '<?php // inert loader fixture',
    'custom/deep/loader.php' => '<?php // custom fixture',
    '.render-cache/render.lock' => 'inert',
    'custom/index.php' => '<?php // Silence is golden.',
    'wp-content/mu-plugins/custom.php' => '<?php // custom mu-plugin',
    'wp-content/plugins/custom/plugin.php' => '<?php // no trusted manifest',
    'wp-content/uploads/photo.jpg' => 'media fixture',
    'wp-content/uploads/loader.php' => '<?php // inert',
    'wp-config.php' => '<?php // local configuration',
    '.htaccess' => '# local configuration',
    '.user.ini' => "memory_limit=512M\nauto_prepend_file = \"/home/existco/public_html/wp-comments-post-loader.php\"\n;auto_append_file=ignored.php\nauto_append_file = none\n",
    'custom/.user.ini' => "auto_prepend_file = ''\nauto_append_file=\"/outside/append.php\"\n",
    'wp-content/plugins/listed/plugin.php' => "<?php\n/*\nPlugin Name: Listed Fixture\nVersion: 1.0\n*/\n",
    'wp-content/plugins/listed/extra.txt' => 'unexpected package file',
];
foreach ($files as $rel => $body) {
    @mkdir(dirname($site . '/' . $rel), 0700, true);
    file_put_contents($site . '/' . $rel, $body);
}
@mkdir($base . '/intel/checksums/wordpress-core', 0700, true);
$map = [];
foreach (['wp-includes/version.php', 'wp-admin/index.php'] as $rel) { $map[$rel] = md5($files[$rel]); }
file_put_contents($base . '/intel/checksums/wordpress-core/6.8.2.json', json_encode(['checksums' => $map]));
@mkdir($base . '/intel/checksums/plugins/listed', 0700, true);
file_put_contents($base . '/intel/checksums/plugins/listed/1.0.json', json_encode(['files' => [
    'plugin.php' => ['md5' => md5($files['wp-content/plugins/listed/plugin.php'])],
]]));
// Use no network and no automatic actions.
foreach ([1, 2] as $pass) {
    $report = $base . '/report-' . $pass . '.json';
    $args = [PHP_BINARY, dirname(__DIR__, 2) . '/scanner/wp-warden-pef.php', $site,
        '--verify-all', '--noninteractive', '--quiet', '--intel-dir=' . $base . '/intel',
        '--file-cache-dir=' . $base . '/cache', '--report-json=' . $report];
    exec(implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1', $output, $exit);
    check(is_file($report), 'Scanner report produced: ' . implode("\n", $output));
    $result = json_decode(file_get_contents($report), true, 512, JSON_THROW_ON_ERROR);
    $hits = [];
    foreach ($result['findings'] as $f) {
        if (($f['type'] ?? '') === 'unverified_site_file') { $hits[$f['relative_path']] = $f; }
    }
    foreach (['wp-comments-post-loader.php', 'custom/deep/loader.php', '.render-cache/render.lock',
        'custom/index.php', 'wp-content/mu-plugins/custom.php', 'wp-content/plugins/custom/plugin.php',
        'wp-content/uploads/loader.php'] as $rel) {
        check(isset($hits[$rel]), 'Review unexpected file on pass ' . $pass . ': ' . $rel);
    }
    foreach (['wp-config.php', '.htaccess', 'wp-content/uploads/photo.jpg', 'wp-includes/version.php',
        'wp-content/plugins/listed/plugin.php', 'wp-content/plugins/listed/extra.txt'] as $rel) {
        check(!isset($hits[$rel]), 'Expected file not marked unverified: ' . $rel);
    }
    check($hits['wp-comments-post-loader.php']['severity'] === 'high', 'Executable review is high severity');
    $extras = array_filter($result['findings'], fn($f) => ($f['type'] ?? '') === 'extra_plugin_file'
        && $f['relative_path'] === 'wp-content/plugins/listed/extra.txt');
    check(count($extras) === 1, 'Known package extras retain their existing finding');
    $hooks = array_values(array_filter($result['findings'], fn($f) => ($f['type'] ?? '') === 'php_configuration_hook'));
    check(count($hooks) === 2, 'Active root and nested hooks reported; commented and disabled hooks ignored');
    foreach ($hooks as $hook) {
        check($hook['file_action'] === false, 'Configuration must not be removed wholesale');
        if ($hook['relative_path'] === '.user.ini') {
            check($hook['target'] === '/home/existco/public_html/wp-comments-post-loader.php', 'Exact prepend target reported');
        }
    }
    foreach ($files as $rel => $body) { check(file_get_contents($site . '/' . $rel) === $body, 'Report-only preserves ' . $rel); }
}
$actionSite = $base . '/actions';
mkdir($actionSite, 0700, true);
file_put_contents($actionSite . '/wp-comments-post-loader.php', '<?php // inert fixture');
$args = [PHP_BINARY, dirname(__DIR__, 2) . '/scanner/wp-warden-pef.php', $actionSite,
    '--verify-all', '--no-file-cache', '--quiet', '--intel-dir=' . $base . '/intel',
    '--apply', '--quarantine=' . $base . '/quarantine'];
$automatic = array_merge($args, ['--noninteractive', '--quarantine-extra-core-auto', '--quarantine-extra-auto', '--quarantine-malware-auto']);
exec(implode(' ', array_map('escapeshellarg', $automatic)) . ' 2>&1', $automaticOutput, $exit);
check(is_file($actionSite . '/wp-comments-post-loader.php'), 'Unverified file is not automatically quarantined');
$proc = proc_open(array_merge($args, ['--interactive']), [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
fwrite($pipes[0], "Q\n"); fclose($pipes[0]);
$out = stream_get_contents($pipes[1]); fclose($pipes[1]);
$err = stream_get_contents($pipes[2]); fclose($pipes[2]);
proc_close($proc);
check(strpos($out, 'unverified_site_file') !== false && strpos($out, 'D = delete permanently') !== false,
    'Interactive review offers removal: ' . $out . $err);
check(!is_file($actionSite . '/wp-comments-post-loader.php'), 'Interactive quarantine moves the reviewed loader');
echo "PASS recursive file review, config hooks, package coverage, cached repeats, automatic cleanup isolation and interactive quarantine\n";
