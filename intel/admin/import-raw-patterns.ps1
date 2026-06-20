param(
    [Parameter(Mandatory = $true)]
    [string]$InputFile,

    [string]$OutputFile = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutputFile)) {
    $root = Resolve-Path (Join-Path $PSScriptRoot "..")
    $OutputFile = Join-Path $root "patterns\community-malware-rules.json"
}

function Convert-DelimitedRegex {
    param([string]$Line)

    $line = $Line.Trim()
    if ($line -notmatch '^/(.*)/([a-zA-Z]*)\s*$') {
        return $line
    }

    $body = $matches[1]
    return $body
}

function Get-Severity {
    param([string]$Pattern)

    $criticalTerms = @(
        '@eval', 'eval\\s*\\(', 'eval\(', 'assert\\s*\\(', 'system\\s*\\(',
        'passthru\\s*\\(', 'bindshell', 'ConnectBackShell', 'ShellBOT',
        'wp-vcd', 'WordpressApieSystem', 'jquerysv', 'HTTP_[A-Z0-9_]+',
        '/etc/shadow', 'GIF89A;<\\?php'
    )

    foreach ($term in $criticalTerms) {
        if ($Pattern.ToLowerInvariant().Contains($term.ToLowerInvariant())) {
            return "critical"
        }
    }

    $highTerms = @(
        'base64_decode', 'gzinflate', 'str_rot13', 'create_fun', 'preg_replace',
        'HACKED BY', 'Backdoor', 'SHELL_PASSWORD', 'php_uname', '/etc/passwd',
        'wp_set_auth_cookie', 'wp_set_current_user'
    )

    foreach ($term in $highTerms) {
        if ($Pattern.ToLowerInvariant().Contains($term.ToLowerInvariant())) {
            return "high"
        }
    }

    return "medium"
}

$rules = @()
$counter = 1

Get-Content -LiteralPath $InputFile | ForEach-Object {
    $line = $_.Trim()
    if ([string]::IsNullOrWhiteSpace($line)) {
        return
    }
    if ($line.StartsWith("#")) {
        return
    }

    $pattern = Convert-DelimitedRegex -Line $line
    if ([string]::IsNullOrWhiteSpace($pattern)) {
        return
    }

    $severity = Get-Severity -Pattern $pattern
    $id = "COMMUNITY_MALWARE_{0:D4}" -f $counter
    $counter++

    $rules += [ordered]@{
        id = $id
        enabled = $true
        severity = $severity
        confidence = if ($severity -eq "critical") { "high" } else { "medium" }
        type = "regex_file"
        pattern = $pattern
        description = "Imported community malware signature."
    }
}

$payload = [ordered]@{
    schema = "wp-warden.patterns.php.v1"
    source = "imported raw regex list"
    created_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    rules = $rules
}

$dir = Split-Path -Parent $OutputFile
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$payload | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputFile -Encoding UTF8

Write-Output $OutputFile
Write-Output "Imported $($rules.Count) rules"
