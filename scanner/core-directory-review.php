<?php
// Directory review uses the same version-specific core manifest as file checks.
function expected_core_directories(array $checksums): array {
    $expected = ['wp-admin' => true, 'wp-includes' => true];
    foreach (array_keys($checksums) as $file) {
        if (!preg_match('#^wp-(?:admin|includes)/#', $file) || strpos('/' . $file . '/', '/../') !== false) { continue; }
        for ($dir = dirname($file); $dir !== '.'; $dir = dirname($dir)) { $expected[$dir] = true; }
    }
    return $expected;
}

// Revalidate ancestry before every action; never operate on an official tree.
function extra_core_directory_path(string $root, string $rel, array $expected): ?string {
    $rel = rtrim($rel, '/');
    if (!preg_match('#^wp-(?:admin|includes)/[^\\\\]+$#', $rel) || isset($expected[$rel])) { return null; }
    $base = realpath($root);
    if ($base === false) { return null; }
    $path = $base;
    $device = @stat($base)['dev'];
    foreach (explode('/', $rel) as $part) {
        if ($part === '' || $part === '.' || $part === '..') { return null; }
        $path .= '/' . $part;
        clearstatcache(true, $path);
        if (is_link($path) || !is_dir($path) || @stat($path)['dev'] !== $device) { return null; }
    }
    $real = realpath($path);
    if ($real === false || normalize_path($real) !== normalize_path($path)) { return null; }
    foreach ($expected as $known => $_) { if (strpos($known, $rel . '/') === 0) { return null; } }
    return $path;
}

function extra_core_directory_action(string $root, string $rel, array $expected, string $choice): array {
    global $apply, $quarantineDir;
    if (!$apply || !in_array($choice, ['Q', 'D'], true)) { return ['success' => false, 'error' => 'Apply mode and an explicit Q/D choice are required']; }
    $path = extra_core_directory_path($root, $rel, $expected);
    if ($path === null) { return ['success' => false, 'error' => 'Directory is no longer safe to act on']; }
    $rootStat = @lstat($path);
    $entries = [];
    try {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $entry) {
            $name = $entry->getPathname();
            $stat = @lstat($name);
            if (!$stat || $entry->isLink() || $stat['dev'] !== $rootStat['dev'] || (!$entry->isDir() && !$entry->isFile())) {
                throw new RuntimeException('Tree contains a link, mount or special file; review manually');
            }
            $entries[] = [$name, $stat, $entry->isDir()];
        }
        $nowRoot = @lstat($path);
        if (extra_core_directory_path($root, $rel, $expected) !== $path || !$nowRoot
            || $nowRoot['ino'] !== $rootStat['ino'] || $nowRoot['dev'] !== $rootStat['dev']) {
            throw new RuntimeException('Directory changed during review');
        }
        if ($choice === 'Q') {
            if (!$quarantineDir) { throw new RuntimeException('Set --quarantine=DIR'); }
            if (!is_dir($quarantineDir) && !@mkdir($quarantineDir, 0700, true)) { throw new RuntimeException('Cannot create quarantine directory'); }
            $q = realpath($quarantineDir);
            $site = rtrim(normalize_path((string)realpath($root)), '/') . '/';
            if ($q === false || strpos(rtrim(normalize_path($q), '/') . '/', $site) === 0) {
                throw new RuntimeException('Whole-tree quarantine must be outside the WordPress root');
            }
            $destination = $q . '/extra-core-' . str_replace('/', '-', $rel) . '-' . bin2hex(random_bytes(6));
            if (!@rename($path, $destination)) { throw new RuntimeException('Directory move failed; source was not deleted'); }
            return ['success' => true, 'destination' => $destination];
        }
        // Preflight completes before deletion. No symlink traversal or shell rm.
        foreach ($entries as [$name, $stat, $isDir]) {
            $parentRel = substr(normalize_path(dirname($name)), strlen(rtrim(normalize_path((string)realpath($root)), '/')) + 1);
            clearstatcache(true, $name);
            $now = @lstat($name);
            if (extra_core_directory_path($root, $parentRel, $expected) === null || !$now || is_link($name)
                || $now['ino'] !== $stat['ino'] || $now['dev'] !== $stat['dev']) { throw new RuntimeException('Tree changed; stopped deletion'); }
            if (!($isDir ? @rmdir($name) : @unlink($name))) { throw new RuntimeException('Could not remove entry; stopped deletion'); }
        }
        if (extra_core_directory_path($root, $rel, $expected) !== $path || !@rmdir($path)) { throw new RuntimeException('Could not remove root directory'); }
        return ['success' => true];
    } catch (Throwable $e) { return ['success' => false, 'error' => $e->getMessage()]; }
}

function review_extra_core_directory(string $root, string $rel, array $expected, int $findingIndex): void {
    global $interactive, $nonInteractive, $apply, $state;
    if (!$interactive || $nonInteractive) { return; }
    while (true) {
        echo "\n[EXTRA CORE DIRECTORY] $rel/\n";
        echo 'V = view contents; ' . ($apply ? 'Q = quarantine entire tree; D = permanently delete tree; ' : '') . "S = skip\nChoice: ";
        $choice = strtoupper(trim((string)fgets(STDIN)));
        if ($choice === '' || $choice === 'S') { return; }
        if ($choice === 'V') {
            $path = extra_core_directory_path($root, $rel, $expected);
            if ($path === null) { echo "Directory unavailable.\n"; return; }
            $count = 0;
            try {
                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                foreach ($it as $entry) {
                    echo '  ' . substr($entry->getPathname(), strlen($path) + 1) . ($entry->isLink() ? ' [link; not followed]' : ($entry->isDir() ? '/' : '')) . "\n";
                    if (++$count >= 100) { echo "  [Preview limited to 100 entries]\n"; break; }
                }
                if ($count === 0) { echo "  [Empty directory]\n"; }
            } catch (UnexpectedValueException $e) { echo "Cannot read all contents.\n"; }
            continue;
        }
        if (!$apply || !in_array($choice, ['Q', 'D'], true)) { continue; }
        $result = extra_core_directory_action($root, $rel, $expected, $choice);
        $action = array_merge(['type' => $choice === 'Q' ? 'quarantine_extra_core_directory' : 'delete_extra_core_directory',
            'relative_path' => $rel . '/', 'at' => gmdate('c')], $result);
        $state['actions'][] = $action;
        $state['findings'][$findingIndex]['directory_action'] = $action;
        if ($result['success']) {
            $state['summary']['actions_taken']++;
            $state['findings'][$findingIndex]['action_taken'] = $action['type'];
            echo "[ACTION] $rel/: " . $action['type'] . "\n";
            return;
        }
        echo '[ACTION FAILED] ' . $result['error'] . "\n";
    }
}

function audit_extra_core_directories(string $root, array $checksums, array $intel): void {
    global $state;
    if (!isset($checksums['wp-admin/index.php'], $checksums['wp-includes/version.php'])) {
        say('WARN: extra core directory audit skipped: core checksum manifest unavailable/incomplete', true); return;
    }
    $expected = expected_core_directories($checksums);
    $pending = ['wp-admin', 'wp-includes'];
    while ($pending) {
        $rel = array_pop($pending);
        $path = rtrim($root, '/') . '/' . $rel;
        if (is_link($path) || should_skip_path($rel . '/', $intel)) { continue; }
        $names = @scandir($path);
        if ($names === false) { say("WARN: could not inspect core directory $rel", true); continue; }
        foreach ($names as $name) {
            if ($name === '.' || $name === '..') { continue; }
            $child = $rel . '/' . $name;
            $dir = $path . '/' . $name;
            if (is_link($dir) || !is_dir($dir) || should_skip_path($child . '/', $intel)) { continue; }
            if (isset($expected[$child])) { $pending[] = $child; continue; }
            $index = count($state['findings']);
            add_finding(['severity' => 'high', 'type' => 'extra_core_directory', 'rule_id' => 'BUILTIN_EXTRA_CORE_DIRECTORY_001',
                'path' => $dir, 'relative_path' => $child . '/', 'file_action' => false,
                'reason' => 'Directory tree is absent from the loaded core checksum manifest. Review before cleanup.',
                'recommended_action' => 'Use --interactive --apply for view, whole-tree quarantine, delete or skip.',
            ]);
            review_extra_core_directory($root, $child, $expected, $index);
        }
    }
}
