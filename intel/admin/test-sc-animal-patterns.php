<?php
// Static regression test. Sample bytes are read as data and never included/evaluated.
// Usage: php test-sc-animal-patterns.php /path/to/batch3/2
$root = dirname(__DIR__, 2);
$scanner = file_get_contents($root . '/scanner/wp-warden-pef.php');
foreach (['prepare_php_pattern_rule', 'read_text_candidate', 'scan_fast_trusted_family_rules', 'should_run_external_php_rules', 'is_php_like_extension', 'has_php_open_tag', 'has_php_only_execution_marker'] as $name) {
    if (!preg_match('/^function ' . $name . '\b[\s\S]*?(?=^function |\z)/m', $scanner, $m)) {
        throw new RuntimeException('Missing scanner function: ' . $name);
    }
    eval($m[0]); // Only trusted repository function definitions, never sample code.
}
function warden_preg_match($pattern, $subject, &$matches = null, $flags = 0, $offset = 0, $context = []) {
    $result = preg_match($pattern, $subject, $matches, $flags, $offset);
    if ($result === false) throw new RuntimeException(json_encode($context) . ': ' . preg_last_error_msg());
    return $result;
}
function add_finding($finding, $unused = false) { $GLOBALS['hits'][] = $finding['rule_id']; }
function say($message, $unused = false) { throw new RuntimeException($message); }
ini_set('pcre.backtrack_limit', '500000');
$rules = [];
foreach (json_decode(file_get_contents($root . '/intel/patterns/php-malware-rules.json'), true, 512, JSON_THROW_ON_ERROR)['rules'] as $rule) {
    if (preg_match('/^PHP_(?:SC_|ANIMAL_|ONYX_)/', $rule['id'])) $rules[] = prepare_php_pattern_rule($rule);
}
if (count($rules) !== 10) throw new RuntimeException('Expected ten family rules');
function check_data($label, $data, $expected = null, $path = __FILE__) {
    global $rules;
    $GLOBALS['hits'] = [];
    scan_fast_trusted_family_rules($path, $label, [], $rules, $data);
    if ($expected === null ? count($GLOBALS['hits']) !== 0 : !in_array($expected, $GLOBALS['hits'], true)) {
        throw new RuntimeException($label . ': unexpected matches ' . json_encode($GLOBALS['hits']));
    }
    echo 'PASS ' . $label . ': ' . implode(',', $GLOBALS['hits']) . PHP_EOL;
}
$fixture = '<?php $encrypted="x"; $alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
decbin(0); bindec("0"); $res .= $bytes[$i] ^ $key[$i % $klen];
file_put_contents($tmp = tempnam(sys_get_temp_dir(), "shf_"), decode($encrypted, "key"));
include $tmp; unlink($tmp);';
check_data('synthetic family wrapper', $fixture, 'PHP_ANIMAL_XOR_TEMP_INCLUDE_001');
check_data('decoder without execution', str_replace('include $tmp;', '', $fixture));
check_data('writer includes different file', str_replace('include $tmp;', 'include $other;', $fixture));
check_data('legitimate prepend', 'auto_prepend_file = "/home/site/wordfence-waf.php"');
check_data('unrelated hashed prepend', 'auto_prepend_file = "/home/site/wp-content/deadbeef.php"');
check_data('commented known prepend', '; auto_prepend_file = "/home/site/wp-content/735e7808.php"');
check_data('unrelated versioned data', 'SCD1:1.2.3:invalid:H4sI' . str_repeat('A', 200));
check_data('ordinary cache dropin', '<?php /* Database cache */ function cache_get($key) { return false; }');
check_data('ordinary index', '<?php // Silence is golden.');
check_data('synthetic onyx restorer', '<?php $a="/onyx-wrapper-tap.php"; $b="/.sd_onyx-wrapper-tap"; $c="/.rd_onyx-wrapper-tap";', 'PHP_ONYX_WRAPPER_RESTORER_001');
check_data('partial onyx marker set', '<?php $a="/onyx-wrapper-tap.php"; $b="/.sd_onyx-wrapper-tap";');
check_data('synthetic disguised core', '<?php /** Plugin Name: Aero Bridge Pad */ /* SCV:4.3.24 */ if (defined("SC_CORE_BOOT_VER") || isset($GLOBALS["sc_boot_ver"])) {}', 'PHP_ONYX_AERO_BRIDGE_IMPLANT_001');
check_data('ordinary similarly named plugin', '<?php /** Plugin Name: Aero Bridge Pad */ function aero_bridge_pad() {}');
check_data('synthetic onyx status', '<?php{"v":"4.3.24","gen":"5a84eeb3c39c","path":"/home/site/wp-content/mu-plugins/onyx-wrapper-tap.php","slug":"onyx-wrapper-tap","state":"ok","start_ts":1,"boot_ts":2}', 'PHP_ONYX_STATUS_BEACON_001');
if (isset($argv[1])) {
    $base = realpath($argv[1]);
    if (!$base || !is_dir($base)) throw new RuntimeException('Invalid sample directory');
    $count = 0;
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS)) as $file) {
        if (!$file->isFile() || $file->getSize() === 0) continue;
        $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($base) + 1));
        $expected = 'PHP_ANIMAL_XOR_TEMP_INCLUDE_001';
        if (in_array($rel, ['.htaccess', '.user.ini'], true)) $expected = 'PHP_SC_KNOWN_PREPEND_CONFIG_001';
        elseif (in_array($rel, ['.wp-object-cache-0f344484.dat', '.wp-object-cache-0f344484.dat.lkg'], true)) $expected = 'PHP_SC_SCD1_PACKED_CORE_001';
        elseif ($rel === '735e7808.php') $expected = 'PHP_SC_HASHED_HIDDEN_INCLUDE_001';
        elseif (in_array($rel, ['.735e7808.php', 'bac4a7ce.php', 'db.php'], true)) $expected = 'PHP_SC_RESTORER_FAMILY_001';
        $data = read_text_candidate($file->getPathname());
        if ($data === null) throw new RuntimeException('Not a text candidate: ' . $rel);
        check_data($rel, $data, $expected, $file->getPathname());
        if (in_array($expected, ['PHP_SC_KNOWN_PREPEND_CONFIG_001', 'PHP_SC_SCD1_PACKED_CORE_001'], true)
            && should_run_external_php_rules($rel, $data)) throw new RuntimeException('Expected non-PHP context');
        $count++;
    }
    if ($count !== 22) throw new RuntimeException('Expected 22 nonempty samples, got ' . $count);
    $previous = dirname($base);
    check_data('previous core', file_get_contents($previous . '/core_4a0e2d4d.php'), 'PHP_SC_OBFUSCATED_CORE_001');
    check_data('previous onyx core', file_get_contents($previous . '/onyx-wrapper-tap.php'), 'PHP_ONYX_AERO_BRIDGE_IMPLANT_001');
    check_data('previous onyx status', file_get_contents($previous . '/own_8355ad57.php'), 'PHP_ONYX_STATUS_BEACON_001');
    check_data('previous installer', file_get_contents($previous . '/f3eb15a7.php'), 'PHP_SC_RESTORER_FAMILY_001');
    check_data('theme backup', file_get_contents($previous . '/thv_753dcc814a9f.bak'));
}
echo "All static family regression checks passed.\n";
