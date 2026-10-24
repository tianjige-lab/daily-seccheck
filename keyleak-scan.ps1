# keyleak-scan.ps1 - key-leak module of daily-seccheck. Read-only and VALUE-BLIND.
# Finds key-shaped strings in files that are new or changed in the last -HoursBack hours. Reports only: path, pattern kind and an 8-hex SHA-256
# fingerprint of the matched value. The matched value is never printed, logged or written anywhere.
# A hit whose full SHA-256 equals the fingerprint of a currently active secret (read from -SecretsDir and -ActiveFiles, never printed) is severity P0.
# Also checks (read-only) that the ACL of -SecretsDir has not been widened to broad principals.
# Output: with -Json, one JSON object { findings:[{id,kind,path,fp,severity,active}], errors:[...], scanned:N, active_fps:N } on stdout.
# ASCII-only on purpose (Windows PowerShell 5.1 reads BOM-less files as ANSI).
param(
    [string[]]$Roots = @('.'),
    [string]$SecretsDir = (Join-Path $env:USERPROFILE '.secrets'),
    [string[]]$ActiveFiles = @(),
    [string[]]$ExcludeDirs = @(),
    [string[]]$DeniedSids = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11'),   # Everyone, BUILTIN\Users, Authenticated Users (well-known SIDs: independent of the Windows display language)
    [int]$HoursBack = 26,
    [int]$MaxFileKB = 1024,
    [switch]$Json
)
$ErrorActionPreference = 'Continue'
# a launcher may pass comma-joined lists as a single string
function Split-List([string[]]$Items) { return @($Items | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
$Roots = Split-List $Roots; $ActiveFiles = Split-List $ActiveFiles; $ExcludeDirs = Split-List $ExcludeDirs; $DeniedSids = Split-List $DeniedSids
$errors = New-Object System.Collections.ArrayList
$findings = New-Object System.Collections.ArrayList

# kind -> regex. Every pattern is applied to every scanned file.
$patterns = [ordered]@{
    'github-token'   = 'gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}'
    'openai-style'   = '\bsk-[A-Za-z0-9_\-]{32,}'
    'google-api-key' = '\bAIza[0-9A-Za-z_\-]{35}\b'
    'slack-token'    = '\bxox[abposr]-[A-Za-z0-9\-]{10,}'
    'aws-access-key' = '\b(AKIA|ASIA)[0-9A-Z]{16}\b'
    'private-key'    = '-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----[A-Za-z0-9+/=\s\\]{80,}'
    'jwt'            = '\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'
    'telegram-bot'   = '\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b|TELEGRAM_BOT_TOKEN\s*[=:]\s*[''"]?\d{8,10}:[A-Za-z0-9_\-]{30,}'
}
$compiled = @{}; foreach ($k in $patterns.Keys) { $compiled[$k] = New-Object System.Text.RegularExpressions.Regex($patterns[$k]) }

$textExt = @('.md', '.txt', '.json', '.jsonl', '.env', '.ps1', '.psm1', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.sh', '.bat', '.cmd', '.vbs', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf', '.pem', '.key', '.log', '.csv', '.xml', '.html', '.sql', '.properties', '.npmrc', '.gitconfig', '')
$pruneNames = @('node_modules', '.git', '.venv', 'venv', 'site-packages', '.next', 'dist', '__pycache__', '.cache', '.secrets', 'AppData', '.pnpm-store') + $ExcludeDirs

function Get-Sha256Hex([string]$Text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
}
function Get-Matches([string]$Content) {
    # returns @(@{kind; value}) - values stay in memory only
    $out = @()
    foreach ($k in $compiled.Keys) {
        foreach ($m in $compiled[$k].Matches($Content)) {
            $v = $m.Value
            if ($k -eq 'private-key') {
                # a bare header is not a leak (docs and tests mention it); fingerprint the key BODY, normalised so JSON-escaped and raw copies compare equal
                $body = $v -replace '^-----BEGIN[^-]*-----', ''
                $body = ($body -replace '\\r|\\n', '') -replace '\s', ''
                if ($body.Length -lt 60) { continue }
                $v = $body.Substring(0, [Math]::Min(120, $body.Length))
            }
            $out += @{ kind = $k; value = $v }
        }
    }
    return $out
}

# ---- active secret fingerprints (full hex, memory only) ----
$active = New-Object 'System.Collections.Generic.HashSet[string]'
if (Test-Path -LiteralPath $SecretsDir) {
    Get-ChildItem -LiteralPath $SecretsDir -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Length -le 65536 } | ForEach-Object {
        try {
            $c = [IO.File]::ReadAllText($_.FullName)
            foreach ($m in (Get-Matches $c)) { [void]$active.Add((Get-Sha256Hex $m.value)) }
            foreach ($line in ($c -split "`r?`n")) {
                if ($line -match '^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.+?)\s*$') { $v = $Matches[1].Trim('"', "'"); if ($v.Length -ge 16) { [void]$active.Add((Get-Sha256Hex $v)) } }
            }
            $t = $c.Trim(); if ($t.Length -ge 16 -and $t.Length -le 4096 -and $t -notmatch "[\r\n]") { [void]$active.Add((Get-Sha256Hex $t)) }
        } catch { [void]$errors.Add('secrets-read-failed') }
    }
} else { [void]$errors.Add('secrets-dir-missing') }
# other files that hold live credentials (for example a CLI login file): their token values count as active secrets too
foreach ($af in $ActiveFiles) {
    if (-not (Test-Path -LiteralPath $af)) { continue }
    try {
        $c = [IO.File]::ReadAllText($af)
        foreach ($m in (Get-Matches $c)) { [void]$active.Add((Get-Sha256Hex $m.value)) }
        foreach ($m in [regex]::Matches($c, '"[A-Za-z_]*(?:[Tt]oken|[Kk]ey)[A-Za-z_]*"\s*:\s*"([^"]{16,})"')) { [void]$active.Add((Get-Sha256Hex $m.Groups[1].Value)) }
    } catch { [void]$errors.Add('active-file-read-failed') }
}

# ---- scan changed files ----
$cutoff = (Get-Date).AddHours(-$HoursBack)
$scanned = 0
$seen = New-Object 'System.Collections.Generic.HashSet[string]'
function Scan-Dir([string]$Dir) {
    try { $files = [IO.Directory]::EnumerateFiles($Dir) } catch { return }
    foreach ($f in $files) {
        try {
            $fi = New-Object IO.FileInfo($f)
            if ($fi.LastWriteTime -lt $cutoff -or $fi.Length -eq 0 -or $fi.Length -gt ($MaxFileKB * 1KB)) { continue }
            $ext = $fi.Extension.ToLowerInvariant()
            if ($textExt -notcontains $ext -and $fi.Name -notmatch '^\.env') { continue }
            $script:scanned++
            $content = [IO.File]::ReadAllText($f)
            foreach ($m in (Get-Matches $content)) {
                $full = Get-Sha256Hex $m.value
                $fp = $full.Substring(0, 8)
                # daily backup copies live in date-stamped folders; strip the stamp so the same leak in tomorrow's copy keeps the same id (baseline de-duplication)
                $pth = (Get-Sha256Hex (($f.ToLowerInvariant()) -replace '\d{4}-\d{2}-\d{2}_\d{6}', '<ts>')).Substring(0, 8)
                $id = "keyleak:$($m.kind):${pth}:$fp"
                if (-not $seen.Add($id)) { continue }
                $isActive = $active.Contains($full)
                [void]$findings.Add([pscustomobject]@{ id = $id; kind = $m.kind; path = $f; fp = $fp; severity = $(if ($isActive) { 'P0' } else { 'HIGH' }); active = $isActive })
            }
        } catch { }
    }
    try { $dirs = [IO.Directory]::EnumerateDirectories($Dir) } catch { return }
    foreach ($d in $dirs) {
        $leaf = [IO.Path]::GetFileName($d)
        if ($pruneNames -contains $leaf) { continue }
        Scan-Dir $d
    }
}
foreach ($r in $Roots) { if (Test-Path -LiteralPath $r) { Scan-Dir ((Resolve-Path -LiteralPath $r).Path) } else { [void]$errors.Add("root-missing:$r") } }

# ---- secrets folder ACL widened? (read-only) ----
if (Test-Path -LiteralPath $SecretsDir) {
    try {
        $acl = Get-Acl -LiteralPath $SecretsDir
        foreach ($a in $acl.Access) {
            $who = [string]$a.IdentityReference
            $sid = ''; try { $sid = $a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = '' }
            if ($a.AccessControlType -eq 'Allow' -and $sid -and ($DeniedSids -contains $sid)) {
                [void]$findings.Add([pscustomobject]@{ id = "secrets-acl:$sid"; kind = 'secrets-acl-widened'; path = $SecretsDir; fp = ''; severity = 'HIGH'; active = $false; principal = $who })
            }
        }
    } catch { [void]$errors.Add('secrets-acl-read-failed') }
}

$result = [ordered]@{ findings = @($findings); errors = @($errors); scanned = $scanned; active_fps = $active.Count }
if ($Json) { $result | ConvertTo-Json -Depth 5 -Compress } else { "scanned=$scanned active_fps=$($active.Count) findings=$($findings.Count) errors=$($errors.Count)"; $findings | ForEach-Object { "[{0}] {1} {2} fp={3}" -f $_.severity, $_.kind, $_.path, $_.fp } }
