# test-keyleak-scan.ps1 - must-break tests for ../keyleak-scan.ps1 (fake keys are built at run time from fragments; nothing key-shaped is stored in this file).
# Run: powershell -NoProfile -ExecutionPolicy Bypass -File test-keyleak-scan.ps1   (exit 0 = all good)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scanner = Join-Path (Split-Path -Parent $here) 'keyleak-scan.ps1'
$tmp = Join-Path $env:TEMP ('keyleak-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force $tmp | Out-Null

function Rep([string]$c, [int]$n) { -join (1..$n | ForEach-Object { $c }) }
$fake = [ordered]@{
    'github-token'   = 'gh' + 'p_' + (Rep 'A' 36)
    'openai-style'   = 's' + 'k-' + (Rep 'b' 40)
    'google-api-key' = 'AI' + 'za' + (Rep 'C' 35)
    'slack-token'    = 'xo' + 'xb-' + (Rep '1' 12) + '-' + (Rep 'd' 12)
    'aws-access-key' = 'AK' + 'IA' + (Rep 'E' 16)
    'private-key'    = '-----BEGIN ' + 'RSA PRIVATE' + ' KEY-----' + "`n" + (Rep 'M' 100) + "`n" + '-----END ' + 'RSA PRIVATE' + ' KEY-----'
    'jwt'            = 'ey' + 'J' + (Rep 'f' 12) + '.' + 'ey' + 'J' + (Rep 'g' 12) + '.' + (Rep 'h' 12)
    'telegram-bot'   = '1234567890' + ':' + 'AA' + (Rep 'i' 33)
}
$activeFake = 'AI' + 'za' + (Rep 'Z' 35)    # google-style key that is "active" (lives in the fake .secrets)

function Build-Fixture {
    param([string]$Root)
    if (Test-Path $Root) { Remove-Item -Recurse -Force $Root }
    $scan = Join-Path $Root 'scan'; $sec = Join-Path $Root 'secrets'
    New-Item -ItemType Directory -Force $scan, $sec, (Join-Path $scan 'node_modules'), (Join-Path $scan 'sub') | Out-Null
    foreach ($k in $fake.Keys) { [IO.File]::WriteAllText((Join-Path $scan ("hit-$k.txt")), ("line one`nvalue = " + $fake[$k] + "`nline three`n")) }
    [IO.File]::WriteAllText((Join-Path $scan 'clean.md'), "nothing secret here, just words like sk and AIza and ghp but short`n")
    [IO.File]::WriteAllText((Join-Path $scan 'sub\active-copy.env'), ("GOOGLE=" + $activeFake + "`n"))
    $old = Join-Path $scan 'old-hit.txt'; [IO.File]::WriteAllText($old, ($fake['github-token'] + "`n")); (Get-Item $old).LastWriteTime = (Get-Date).AddDays(-3)
    [IO.File]::WriteAllText((Join-Path $scan 'node_modules\pruned.txt'), ($fake['github-token'] + "`n"))
    [IO.File]::WriteAllText((Join-Path $sec 'google.key'), ($activeFake + "`n"))
    $pemHdr = '-----BEGIN ' + 'RSA PRIVATE' + ' KEY-----'; $pemEnd = '-----END ' + 'RSA PRIVATE' + ' KEY-----'
    [IO.File]::WriteAllText((Join-Path $sec 'deploy.pem'), ($pemHdr + "`n" + (Rep 'N' 100) + "`n" + $pemEnd + "`n"))
    [IO.File]::WriteAllText((Join-Path $scan 'escaped-pem.json'), ('{"k":"' + $pemHdr + ([char]92) + 'n' + (Rep 'N' 100) + ([char]92) + 'n' + $pemEnd + '"}'))
    [IO.File]::WriteAllText((Join-Path $scan 'bare-header.md'), ("docs mention " + $pemHdr + " only as a title`n"))
    foreach ($d in '2026-10-24_030001', '2026-10-25_030001') { $bd = Join-Path (Join-Path $scan 'backup') $d; New-Item -ItemType Directory -Force $bd | Out-Null; [IO.File]::WriteAllText((Join-Path $bd 'copy.txt'), ($fake['github-token'] + "`n")) }
    icacls $sec /inheritance:r /grant ("$env:USERNAME" + ':(OI)(CI)F') | Out-Null
    return @{ scan = $scan; sec = $sec }
}
function Run-Scanner([string]$Path, $fx) {
    $o = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Path -Roots $fx.scan -SecretsDir $fx.sec -Json 2>&1 | Out-String
    return $o
}
function Assert-All([string]$Path, [string]$Label) {
    $fails = New-Object System.Collections.ArrayList
    $fx = Build-Fixture (Join-Path $tmp $Label)
    $out = Run-Scanner $Path $fx
    $j = $null; try { $j = $out | ConvertFrom-Json } catch { [void]$fails.Add('output-not-json') }
    if ($j) {
        $f = @($j.findings)
        foreach ($k in $fake.Keys) {
            $hit = @($f | Where-Object { $_.kind -eq $k -and $_.path -like "*hit-$k.txt" })
            if ($hit.Count -ne 1) { [void]$fails.Add("missing-$k") }
        }
        if (@($f | Where-Object { $_.path -like '*clean.md' }).Count -ne 0) { [void]$fails.Add('clean-file-flagged') }
        if (@($f | Where-Object { $_.path -like '*old-hit.txt' }).Count -ne 0) { [void]$fails.Add('old-file-scanned') }
        if (@($f | Where-Object { $_.path -like '*node_modules*' }).Count -ne 0) { [void]$fails.Add('pruned-dir-scanned') }
        $act = @($f | Where-Object { $_.path -like '*active-copy.env' })
        if ($act.Count -ne 1 -or $act[0].severity -ne 'P0') { [void]$fails.Add('active-key-not-P0') }
        $nonAct = @($f | Where-Object { $_.path -like '*hit-github-token.txt' })
        if ($nonAct.Count -eq 1 -and $nonAct[0].severity -eq 'P0') { [void]$fails.Add('inactive-key-marked-P0') }
        if (@($f | Where-Object { $_.kind -eq 'secrets-acl-widened' }).Count -ne 0) { [void]$fails.Add('acl-false-positive') }
        if (@($f | Where-Object { $_.path -like '*bare-header.md' }).Count -ne 0) { [void]$fails.Add('bare-pem-header-flagged') }
        $esc = @($f | Where-Object { $_.path -like '*escaped-pem.json' })
        if ($esc.Count -ne 1 -or $esc[0].severity -ne 'P0') { [void]$fails.Add('escaped-active-pem-not-P0') }
        $bk = @($f | Where-Object { $_.path -like '*backup*copy.txt' })
        if ($bk.Count -ne 1) { [void]$fails.Add('date-stamped-duplicates-not-deduped:' + $bk.Count) }
    }
    foreach ($v in (@($fake.Values | Where-Object { $_ -notmatch "`n" }) + $activeFake + (Rep 'M' 100) + (Rep 'N' 100))) { if ($out.Contains($v)) { [void]$fails.Add('VALUE-LEAKED-IN-OUTPUT'); break } }
    # ACL widening must be reported
    icacls $fx.sec /grant '*S-1-5-32-545:(OI)(CI)R' | Out-Null   # BUILTIN\Users by well-known SID: works on any Windows display language
    $out2 = Run-Scanner $Path $fx
    $j2 = $null; try { $j2 = $out2 | ConvertFrom-Json } catch { }
    if (-not $j2 -or @($j2.findings | Where-Object { $_.kind -eq 'secrets-acl-widened' }).Count -lt 1) { [void]$fails.Add('acl-widening-not-reported') }
    return ,$fails
}

$pass = 0; $fail = 0
$base = Assert-All $scanner 'real'
if ($base.Count -eq 0) { 'PASS scanner-real | 0 failed assertions'; $pass++ } else { 'FAIL scanner-real | ' + ($base -join ','); $fail++ }

# must-break: each mutant has to be caught by at least one assertion
$src = [IO.File]::ReadAllText($scanner)
$mutants = [ordered]@{
    'no-files-scanned'      = @('$cutoff = (Get-Date).AddHours(-$HoursBack)', '$cutoff = (Get-Date).AddYears(1)')
    'active-set-ignored'    = @('$isActive = $active.Contains($full)', '$isActive = $false')
    'value-leaked'          = @('fp = $fp; severity', 'fp = $fp; value = $m.value; severity')
    'old-files-scanned'     = @('$fi.LastWriteTime -lt $cutoff -or ', '')
    'pruning-disabled'      = @('if ($pruneNames -contains $leaf) { continue }', '')
    'acl-check-disabled'    = @("if (`$a.AccessControlType -eq 'Allow' -and", "if (`$false -and")
    'datestamp-not-stripped' = @("-replace '\d{4}-\d{2}-\d{2}_\d{6}', '<ts>'", "-replace 'NEVERMATCH', ''")
    'bare-header-guards-removed' = @('KEY-----[A-Za-z0-9+/=\s\\]{80,}', 'KEY-----[A-Za-z0-9+/=\s\\]{0,}', 'if ($body.Length -lt 60) { continue }', '')
}
foreach ($name in $mutants.Keys) {
    $pair = $mutants[$name]
    if (-not $src.Contains($pair[0])) { "FAIL mutant-$name | mutation anchor not found (scanner changed?)"; $fail++; continue }
    $mp = Join-Path $tmp "mutant-$name.ps1"
    $mut = $src.Replace($pair[0], $pair[1])
    if ($pair.Count -ge 4) { if (-not $mut.Contains($pair[2])) { "FAIL mutant-$name | second anchor not found"; $fail++; continue }; $mut = $mut.Replace($pair[2], $pair[3]) }
    [IO.File]::WriteAllText($mp, $mut)
    $r = Assert-All $mp $name
    if ($r.Count -gt 0) { "PASS mutant-$name | FAULT_CAUGHT by: " + (($r | Select-Object -First 3) -join ','); $pass++ } else { "FAIL mutant-$name | NOT caught (tests are blind to this fault)"; $fail++ }
}
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
"TOTAL keyleak PASS=$pass FAIL=$fail"
if ($fail -gt 0) { exit 1 } else { exit 0 }
