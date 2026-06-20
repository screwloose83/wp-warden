#!/usr/bin/env php
<?php
/**
 * Generate WP Warden plugin checksum intel from a clean plugin ZIP.
 */

if ($argc < 4 || in_array($argv[1] ?? '', ['-h', '--help'], true)) {
    fwrite(STDERR, "USAGE: php admin/add-plugin-zip-checksums.php PLUGIN_ZIP SLUG VERSION [INTEL_DIR]\n\n");
    fwrite(STDERR, "Example:\n");
    fwrite(STDERR, "  php admin/add-plugin-zip-checksums.php ~/clean/unlimited-elements-for-elementor-premium.2.0.10.zip unlimited-elements-for-elementor-premium 2.0.10\n");
    exit($argc < 4 ? 1 : 0);
}

if (!class_exists('ZipArchive')) {
    fwrite(STDERR, "ERROR: PHP ZipArchive extension is not available.\n");
    exit(1);
}

$zipPath = realpath($argv[1]);
$slug = trim($argv[2]);
$version = trim($argv[3]);
$intelDir = isset($argv[4]) ? rtrim(str_replace('\\', '/', $argv[4]), '/') : dirname(__DIR__);

if (!$zipPath || !is_file($zipPath)) {
    fwrite(STDERR, "ERROR: ZIP not found: {$argv[1]}\n");
    exit(1);
}
if ($slug === '' || !preg_match('/^[A-Za-z0-9._-]+$/', $slug)) {
    fwrite(STDERR, "ERROR: invalid plugin slug.\n");
    exit(1);
}
if ($version === '') {
    fwrite(STDERR, "ERROR: version is required.\n");
    exit(1);
}

$zip = new ZipArchive();
if ($zip->open($zipPath) !== true) {
    fwrite(STDERR, "ERROR: could not open ZIP: $zipPath\n");
    exit(1);
}

$names = [];
for ($i = 0; $i < $zip->numFiles; $i++) {
    $name = str_replace('\\', '/', $zip->getNameIndex($i));
    if ($name === '' || substr($name, -1) === '/' || preg_match('#(^|/)(__MACOSX|\.DS_Store)(/|$)#', $name)) {
        continue;
    }
    $names[] = $name;
}

$rootPrefix = detect_common_zip_root($names, $slug);
$files = [];
foreach ($names as $name) {
    $data = $zip->getFromName($name);
    if ($data === false) {
        fwrite(STDERR, "WARN: could not read ZIP entry: $name\n");
        continue;
    }

    $rel = $rootPrefix !== '' && strpos($name, $rootPrefix) === 0
        ? substr($name, strlen($rootPrefix))
        : $name;
    $rel = ltrim($rel, '/');
    if ($rel === '') {
        continue;
    }

    $files[$rel] = [
        'md5' => strtolower(hash('md5', $data)),
        'sha256' => strtolower(hash('sha256', $data)),
    ];
}
$zip->close();

ksort($files, SORT_STRING);

$outDir = "$intelDir/checksums/plugins/$slug";
if (!is_dir($outDir) && !mkdir($outDir, 0755, true)) {
    fwrite(STDERR, "ERROR: could not create output directory: $outDir\n");
    exit(1);
}

$cleanZipRel = "clean-zips/plugins/$slug.$version.zip";
$cleanZipPath = "$intelDir/$cleanZipRel";
$cleanZipDir = dirname($cleanZipPath);
if (!is_dir($cleanZipDir) && !mkdir($cleanZipDir, 0755, true)) {
    fwrite(STDERR, "ERROR: could not create clean ZIP directory: $cleanZipDir\n");
    exit(1);
}
if (!copy($zipPath, $cleanZipPath)) {
    fwrite(STDERR, "ERROR: could not copy clean ZIP to: $cleanZipPath\n");
    exit(1);
}

$outFile = "$outDir/$version.json";
$payload = [
    'schema' => 'wp-warden.checksums.component.v1',
    'type' => 'plugin',
    'slug' => $slug,
    'version' => $version,
    'source' => basename($zipPath),
    'clean_zip' => [
        'path' => $cleanZipRel,
        'sha256' => strtolower(hash_file('sha256', $cleanZipPath)),
    ],
    'created_at' => gmdate('c'),
    'files' => $files,
];

file_put_contents($outFile, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
fwrite(STDERR, "Wrote plugin checksums: $outFile (" . count($files) . " files)\n");
fwrite(STDERR, "Stored clean ZIP: $cleanZipPath\n");

function detect_common_zip_root(array $names, string $slug): string {
    $firstSegments = [];
    foreach ($names as $name) {
        $parts = explode('/', $name, 2);
        if (count($parts) < 2) {
            return '';
        }
        $firstSegments[$parts[0]] = true;
    }

    if (count($firstSegments) !== 1) {
        return '';
    }

    $root = array_key_first($firstSegments);
    if ($root === $slug || stripos($root, $slug) !== false) {
        return $root . '/';
    }

    return $root . '/';
}
