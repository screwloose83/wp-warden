<?php
// Run normally and with -d disable_functions=shell_exec / exec / exec,shell_exec.
// Load only the repository helper, without bootstrapping the full scanner.
$source = file_get_contents(dirname(__DIR__, 2) . '/scanner/wp-warden-pef.php');
if (!preg_match('/^function command_exists\b[\s\S]*?(?=^function |\z)/m', $source, $match)) {
    throw new RuntimeException('command_exists helper not found');
}
eval($match[0]);
$warnings = [];
function say($message, $verbose = false) { $GLOBALS['warnings'][] = $message; }
function check($condition, $message) {
    if (!$condition) throw new RuntimeException($message);
}
check(command_exists('wp_warden_nonexistent_93baf681') === false, 'Missing command must be false');
check(command_exists('wp_warden_nonexistent_93baf681') === false, 'Cached result must be false');
if (!function_exists('exec')) {
    check(command_exists('crontab') === false, 'Disabled exec must prevent cron command use');
    check(command_exists('jq') === false, 'Disabled exec must prevent jq command use');
    check(command_exists('wp') === false, 'Disabled exec must prevent WP-CLI command use');
    check(count($warnings) === 1, 'Unavailable exec must warn exactly once');
    check(strpos($warnings[0], 'system cron auditing') !== false, 'Warning must disclose skipped cron audit');
} else {
    check($warnings === [], 'Available exec must not produce an unavailable warning');
    if (PHP_OS_FAMILY !== 'Windows') {
        check(command_exists('sh') === true, 'POSIX sh should be found, even without shell_exec');
        check(command_exists('sh; exit 0') === false, 'Command argument must be shell escaped');
    }
}
echo "PASS command lookup with exec=" . (function_exists('exec') ? 'on' : 'off')
    . ' shell_exec=' . (function_exists('shell_exec') ? 'on' : 'off') . "\n";
