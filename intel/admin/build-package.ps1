param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = (Get-Date).ToUniversalTime().ToString("yyyy.MM.dd.HHmm")
}

$OutDir = Join-Path $RootDir "releases"
$PackageName = "wp-warden-intel-$Version.zip"
$OutFile = Join-Path $OutDir $PackageName
$ManifestPath = Join-Path $RootDir "releases\manifest.json"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $RootDir "clean-zips") | Out-Null

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$manifest.version = $Version
$manifest.created_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$manifest.bundle.format = "zip"
$manifest.bundle.sha256 = $null
$manifest.bundle.url = $PackageName
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ManifestPath, (($manifest | ConvertTo-Json -Depth 20) + "`n"), $utf8NoBom)

$items = @(
    "checksums",
    "clean-zips",
    "whitelists",
    "patterns",
    "policy",
    "releases\manifest.json",
    "README.md"
) | ForEach-Object { Join-Path $RootDir $_ }

if (Test-Path -LiteralPath $OutFile) {
    Remove-Item -LiteralPath $OutFile -Force
}

Compress-Archive -Path $items -DestinationPath $OutFile -Force

$sha = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$manifest.bundle.sha256 = $sha
[System.IO.File]::WriteAllText($ManifestPath, (($manifest | ConvertTo-Json -Depth 20) + "`n"), $utf8NoBom)

Compress-Archive -Path $ManifestPath -DestinationPath $OutFile -Update

Write-Output $OutFile
Write-Output $sha
