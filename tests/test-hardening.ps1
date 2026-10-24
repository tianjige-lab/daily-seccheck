# test-hardening.ps1 - must-break tests for the input validation and ssh handling of daily-seccheck.ps1 / lib-validate.ps1.
# A fake "ssh" (a .cmd file first on PATH) records every call, so nothing ever leaves this machine.
# Run: powershell -NoProfile -ExecutionPolicy Bypass -File tests\test-hardening.ps1   (exit 0 = all good)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Split-Path -Parent $here
$tmp = Join-Path $env:TEMP ('hardening-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force $tmp | Out-Null

# ---- fake ssh on PATH ----
$fakeBin = Join-Path $tmp 'bin'; New-Item -ItemType Directory -Force $fakeBin | Out-Null
$sshLog = Join-Path $tmp 'ssh-calls.log'
[IO.File]::WriteAllText((Join-Path $fakeBin 'ssh.cmd'), "@echo off`r`necho %* >> `"%SSH_LOG%`"`r`nexit /b 1`r`n", [Text.Encoding]::ASCII)
$env:SSH_LOG = $sshLog
$env:PATH = $fakeBin + ';' + $env:PATH

function New-ProjectCopy([string]$Name) {
    $d = Join-Path $tmp $Name; New-Item -ItemType Directory -Force $d | Out-Null
    foreach ($f in 'daily-seccheck.ps1', 'keyleak-scan.ps1', 'lib-validate.ps1', 'osv-scan.mjs') { Copy-Item (Join-Path $proj $f) (Join-Path $d $f) }
    return $d
}
function Run-Main([string]$Dir, $Config, [switch]$DryRun) {
    if (Test-Path $sshLog) { Remove-Item $sshLog -Force }
    $cfgPath = Join-Path $Dir 'config-test.json'
    [IO.File]::WriteAllText($cfgPath, ($Config | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Dir 'daily-seccheck.ps1'), '-ConfigPath', $cfgPath)
    if ($DryRun) { $a += '-DryRun' }
    $ErrorActionPreference = 'Continue'
    $out = (& powershell.exe @a 2>&1 | Out-String)
    $ErrorActionPreference = 'Stop'
    $calls = @(); if (Test-Path $sshLog) { $calls = @(Get-Content $sshLog) }
    $errLine = ($out -split "`r?`n" | Where-Object { $_ -like 'ERRORS:*' } | Select-Object -First 1)
    return @{ out = $out; calls = $calls; errors = $(if ($errLine) { $errLine.Substring(7).Trim() } else { '' }) }
}
function New-Cfg([string]$Dir, $Modules, $Extra) {
    $m = @{ osv = $false; hosts = $false; node = $false; router = $false; windowsUpdate = $false; kev = $false; keyleak = $false }
    foreach ($k in $Modules.Keys) { $m[$k] = $Modules[$k] }
    $c = @{ stateDir = (Join-Path $Dir 'state'); alertDirs = @((Join-Path $Dir 'alerts')); modules = $m }
    foreach ($k in $Extra.Keys) { $c[$k] = $Extra[$k] }
    return $c
}

# ---- validator unit assertions (dot-sourced lib; used for the real lib and for lib mutants) ----
function Assert-Validators([string]$LibPath) {
    $f = New-Object System.Collections.ArrayList
    . $LibPath
    foreach ($ok in 'nginx', 'web1', 'my-app@1.service', 'a.b_c:d') { if (-not (Test-SafeLabel $ok)) { [void]$f.Add("label-rejects-good:$ok") } }
    foreach ($bad in 'nginx; touch x', '$(id)', 'a b', '`id`', "a'b", '', 'a|b', 'a&b') { if (Test-SafeLabel $bad) { [void]$f.Add("label-accepts-bad:$bad") } }
    foreach ($ok in '/srv/app/package-lock.json', 'app/package-lock.json', '~/x/package-lock.json') { if (-not (Test-SafeRemotePath $ok)) { [void]$f.Add("rpath-rejects-good:$ok") } }
    foreach ($bad in '/srv/a;touch', '/srv/a$(id)', '/srv/a b', "/srv/a'b", '/srv/a`id`', '/srv/a|b', '/srv/a&b', "/srv/a`nb") { if (Test-SafeRemotePath $bad) { [void]$f.Add("rpath-accepts-bad:$bad") } }
    foreach ($ok in 'C:\Program Files\nodejs\node.exe', 'D:/tools/node.exe') { if (-not (Test-SafeWindowsPath $ok)) { [void]$f.Add("wpath-rejects-good:$ok") } }
    foreach ($bad in "C:\a'; calc; '", 'C:\a"b', 'C:\a;b', 'C:\a$b') { if (Test-SafeWindowsPath $bad) { [void]$f.Add("wpath-accepts-bad:$bad") } }
    foreach ($ok in 'deploy@192.0.2.10', 'host.example', 'u@host-1.example', 'u@[::1]') { if (-not (Test-SafeSshTarget $ok)) { [void]$f.Add("target-rejects-good:$ok") } }
    foreach ($bad in '-oProxyCommand=touch x', '-o', '--', 'u@-x', 'a b', "u@h;x", '') { if (Test-SafeSshTarget $bad) { [void]$f.Add("target-accepts-bad:$bad") } }
    $a = Get-SshArgs 'deploy@192.0.2.10' 'k'
    $i = [array]::IndexOf($a, '--')
    if ($i -lt 0 -or $a[$i + 1] -ne 'deploy@192.0.2.10' -or $a[-1] -ne 'deploy@192.0.2.10') { [void]$f.Add('ssh-args-no-double-dash-before-target') }
    if ((ConvertTo-SingleQuoted "a'b") -ne "'a'\''b'") { [void]$f.Add('single-quote-escaping') }
    return ,$f
}

# ---- end-to-end assertions with the fake ssh ----
function Assert-Main([string]$Dir) {
    $f = New-Object System.Collections.ArrayList
    # 1 missing hosts key: nothing may be run, no phantom host error
    $r = Run-Main $Dir (New-Cfg $Dir @{ hosts = $true } @{}) -DryRun
    if ($r.calls.Count -ne 0) { [void]$f.Add("missing-hosts-key-ran-ssh:$($r.calls.Count)") }
    if ($r.errors -match 'host--unreachable') { [void]$f.Add('missing-hosts-key-phantom-host-error') }
    if ($r.errors -match 'config-invalid') { [void]$f.Add('missing-hosts-key-phantom-config-error') }
    # 2 missing remoteWindows key with windowsUpdate/node on: no phantom item
    $r = Run-Main $Dir (New-Cfg $Dir @{ windowsUpdate = $true } @{}) -DryRun
    if ($r.errors -match '(^|,)hotfix-(,|$)') { [void]$f.Add('missing-remoteWindows-key-phantom-error') }
    if ($r.errors -match 'config-invalid') { [void]$f.Add('missing-remoteWindows-key-phantom-config-error') }
    if ($r.calls.Count -ne 0) { [void]$f.Add("missing-remoteWindows-key-ran-ssh:$($r.calls.Count)") }
    # 3 valid host: ssh is called with -- right before the target
    $r = Run-Main $Dir (New-Cfg $Dir @{ hosts = $true } @{ hosts = @(@{ name = 'web1'; target = 'deploy@192.0.2.10'; services = @('nginx'); userServices = @() }) }) -DryRun
    if ($r.calls.Count -lt 1) { [void]$f.Add('valid-host-not-called') } elseif ($r.calls[0] -notmatch '-- deploy@192\.0\.2\.10 ') { [void]$f.Add('valid-host-call-without-double-dash:' + ([string]$r.calls[0]).Substring(0, [Math]::Min(90, ([string]$r.calls[0]).Length))) }
    # 3b valid host with both service lists empty: still called, no config error
    $r = Run-Main $Dir (New-Cfg $Dir @{ hosts = $true } @{ hosts = @(@{ name = 'web1'; target = 'deploy@192.0.2.10'; services = @(); userServices = @() }) }) -DryRun
    if ($r.calls.Count -lt 1) { [void]$f.Add('valid-host-empty-service-lists-not-called') }
    if ($r.errors -match 'config-invalid') { [void]$f.Add('valid-host-empty-service-lists-flagged') }
    # 4 service name with shell metacharacters: never sent
    $r = Run-Main $Dir (New-Cfg $Dir @{ hosts = $true } @{ hosts = @(@{ name = 'web1'; target = 'deploy@192.0.2.10'; services = @('nginx; touch pwned'); userServices = @() }) }) -DryRun
    if ($r.calls.Count -ne 0) { [void]$f.Add('bad-service-name-was-sent') }
    if ($r.errors -notmatch 'config-invalid:hosts\.services:web1') { [void]$f.Add('bad-service-name-not-reported') }
    # 5 ssh target starting with a dash: never sent
    $r = Run-Main $Dir (New-Cfg $Dir @{ hosts = $true } @{ hosts = @(@{ name = 'web1'; target = '-oProxyCommand=touch pwned'; services = @(); userServices = @() }) }) -DryRun
    if ($r.calls.Count -ne 0) { [void]$f.Add('dash-target-was-sent') }
    if ($r.errors -notmatch 'config-invalid') { [void]$f.Add('dash-target-not-reported') }
    # 6 remote lock path with shell metacharacters: never sent
    $r = Run-Main $Dir (New-Cfg $Dir @{ osv = $true } @{ hosts = @(@{ name = 'web1'; target = 'deploy@192.0.2.10'; services = @(); userServices = @() }); osv = @{ remoteLocks = @(@{ label = 'prod'; host = 'web1'; path = '/srv/x;touch pwned' }) } }) -DryRun
    if ($r.calls.Count -ne 0) { [void]$f.Add('bad-remote-path-was-sent') }
    if ($r.errors -notmatch 'config-invalid:osv\.remoteLocks\.path') { [void]$f.Add('bad-remote-path-not-reported') }
    # 7 remote Windows node path with a quote: never sent
    $r = Run-Main $Dir (New-Cfg $Dir @{ node = $true } @{ remoteWindows = @(@{ name = 'winbox'; target = 'admin@192.0.2.20'; nodePath = "C:\x'; calc; '" }) }) -DryRun
    if ($r.calls.Count -ne 0) { [void]$f.Add('bad-node-path-was-sent') }
    # 8 DryRun writes nothing at all (no state folder, no run.log); a normal run does write run.log
    $stateDir = Join-Path $Dir 'state'; if (Test-Path $stateDir) { Remove-Item $stateDir -Recurse -Force }
    [void](Run-Main $Dir (New-Cfg $Dir @{} @{}) -DryRun)
    if (Test-Path $stateDir) { [void]$f.Add('dryrun-created-state-folder') }
    New-Item -ItemType Directory -Force $stateDir | Out-Null     # state folder already exists: a DryRun must still not write run.log into it
    [void](Run-Main $Dir (New-Cfg $Dir @{} @{}) -DryRun)
    if (Test-Path (Join-Path $stateDir 'run.log')) { [void]$f.Add('dryrun-wrote-runlog') }
    [void](Run-Main $Dir (New-Cfg $Dir @{} @{}))
    if (-not (Test-Path (Join-Path $stateDir 'run.log'))) { [void]$f.Add('normal-run-wrote-no-runlog') }
    return ,$f
}

# ---- osv-scan.mjs error handling (argument check, OSV unreachable) ----
$nodeExe = (Get-Command node -ErrorAction SilentlyContinue).Source
function Assert-Osv([string]$ScriptPath) {
    $f = New-Object System.Collections.ArrayList
    $ErrorActionPreference = 'Continue'   # node writes errors to stderr in the mutant runs
    $o = (& $nodeExe $ScriptPath 'nonsense' 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 2 -or $o -notmatch 'bad-argument') { [void]$f.Add('osv-bad-argument-not-rejected') }
    $lock = Join-Path $tmp 'osv-lock.json'
    [IO.File]::WriteAllText($lock, '{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/left-pad":{"version":"1.3.0"}}}')
    $pre = Join-Path $tmp 'osv-preload.mjs'
    [IO.File]::WriteAllText($pre, "globalThis.fetch = async () => { throw new Error('offline') }`n")
    $o2 = (& $nodeExe '--import' ([Uri]$pre).AbsoluteUri $ScriptPath ("app=" + $lock) 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 3 -or $o2 -notmatch 'osv-api-unreachable') { [void]$f.Add('osv-unreachable-not-reported') }
    $ErrorActionPreference = 'Stop'
    return ,$f
}
$pass = 0; $fail = 0
# real
$v = Assert-Validators (Join-Path $proj 'lib-validate.ps1')
if ($v.Count -eq 0) { 'PASS validators-real | 0 failed assertions'; $pass++ } else { 'FAIL validators-real | ' + ($v -join ','); $fail++ }
$realDir = New-ProjectCopy 'real'
$m = Assert-Main $realDir
if ($m.Count -eq 0) { 'PASS main-real | 0 failed assertions'; $pass++ } else { 'FAIL main-real | ' + ($m -join ','); $fail++ }

# validator mutants (patch lib-validate.ps1 in a copy)
$libSrc = [IO.File]::ReadAllText((Join-Path $proj 'lib-validate.ps1'))
$libMutants = [ordered]@{
    'label-allows-metachars'  = @("'^[A-Za-z0-9@._:-]+`$'", "'^.+`$'")
    'rpath-allows-metachars'  = @("'^[A-Za-z0-9_@%+=:,./~-]+`$'", "'^.+`$'")
    'wpath-allows-quote'      = @("'^[A-Za-z0-9 _:\\/.()-]+`$'", "'^.+`$'")
    'target-allows-dash-start' = @("'^([A-Za-z0-9._][A-Za-z0-9._-]*@)?(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9._:-]*)`$'", "'^.+`$'")
    'ssh-args-no-double-dash' = @("return (`$a + @('--', `$Target))", "return (`$a + @(`$Target))")
    'no-quote-escaping'       = @('''\''''', '''''')
}
foreach ($name in $libMutants.Keys) {
    $pair = $libMutants[$name]
    if (-not $libSrc.Contains($pair[0])) { "FAIL mutant-$name | anchor not found"; $fail++; continue }
    $mp = Join-Path $tmp "lib-$name.ps1"; [IO.File]::WriteAllText($mp, $libSrc.Replace($pair[0], $pair[1]))
    $r = Assert-Validators $mp
    if ($r.Count -gt 0) { "PASS mutant-$name | FAULT_CAUGHT by: " + (($r | Select-Object -First 2) -join ','); $pass++ } else { "FAIL mutant-$name | NOT caught"; $fail++ }
}
# main-script mutants (patch daily-seccheck.ps1 in its own project copy)
$mainSrc = [IO.File]::ReadAllText((Join-Path $proj 'daily-seccheck.ps1'))
$mainMutants = [ordered]@{
    'null-items-not-dropped'    = @('function Get-Items($Value) { return @($Value | Where-Object { $null -ne $_ -and $_ -ne '''' }) }', 'function Get-Items($Value) { return ,@($Value) }')
    'service-validation-off'    = @('if ($badSvc.Count -gt 0) {', 'if ($false) {')
    'target-validation-off-both-layers' = @('if (-not (Test-SafeLabel $name) -or -not (Test-SafeSshTarget ([string]$h.target))) {', 'if ($false) {', 'if (-not (Test-SafeSshTarget $Target)) { Add-Err ''config-invalid:ssh-target''; return '''' }', '')
    'remote-path-validation-off' = @('if (-not (Test-SafeRemotePath ([string]$r.path))) {', 'if ($false) {')
    'node-path-validation-off'  = @('-or -not (Test-SafeWindowsPath $nodePath)) {', ') {')
    'dryrun-still-logs'         = @('function Write-RunLog([string]$Line) { if (-not $DryRun) {', 'function Write-RunLog([string]$Line) { if ($true) {')
    'dryrun-still-creates-state' = @('if (-not $DryRun) { New-Item -ItemType Directory -Force -Path $stateDir | Out-Null }', 'New-Item -ItemType Directory -Force -Path $stateDir | Out-Null')
}
foreach ($name in $mainMutants.Keys) {
    $pair = $mainMutants[$name]
    if (-not $mainSrc.Contains($pair[0])) { "FAIL mutant-$name | anchor not found"; $fail++; continue }
    $d = New-ProjectCopy ("main-$name")
    $mut = $mainSrc.Replace($pair[0], $pair[1])
    if ($pair.Count -ge 4) { if (-not $mut.Contains($pair[2])) { "FAIL mutant-$name | second anchor not found"; $fail++; continue }; $mut = $mut.Replace($pair[2], $pair[3]) }
    [IO.File]::WriteAllText((Join-Path $d 'daily-seccheck.ps1'), $mut)
    $r = Assert-Main $d
    if ($r.Count -gt 0) { "PASS mutant-$name | FAULT_CAUGHT by: " + (($r | Select-Object -First 2) -join ','); $pass++ } else { "FAIL mutant-$name | NOT caught"; $fail++ }
}
# osv-scan mutants
$osvSrc = [IO.File]::ReadAllText((Join-Path $proj 'osv-scan.mjs'))
$osvReal = Assert-Osv (Join-Path $proj 'osv-scan.mjs')
if ($osvReal.Count -eq 0) { 'PASS osv-real | 0 failed assertions'; $pass++ } else { 'FAIL osv-real | ' + ($osvReal -join ','); $fail++ }
$osvMutants = [ordered]@{
    'osv-arg-check-removed'      = @("if (eq < 1) { console.log(JSON.stringify({ error: 'bad-argument', scanned: 0, findings: [] })); process.exit(2) }", '')
    'osv-unreachable-unhandled'  = @("} catch { fail('osv-api-unreachable') }`nconst cache", "} catch { throw new Error('boom') }`nconst cache")
}
foreach ($name in $osvMutants.Keys) {
    $pair = $osvMutants[$name]
    if (-not $osvSrc.Contains($pair[0])) { "FAIL mutant-$name | anchor not found"; $fail++; continue }
    $mp = Join-Path $tmp "$name.mjs"; [IO.File]::WriteAllText($mp, $osvSrc.Replace($pair[0], $pair[1]))
    $r = Assert-Osv $mp
    if ($r.Count -gt 0) { "PASS mutant-$name | FAULT_CAUGHT by: " + ($r -join ','); $pass++ } else { "FAIL mutant-$name | NOT caught"; $fail++ }
}
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
"TOTAL hardening PASS=$pass FAIL=$fail"
if ($fail -gt 0) { exit 1 } else { exit 0 }
