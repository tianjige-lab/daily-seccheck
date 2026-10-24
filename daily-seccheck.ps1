<#
.SYNOPSIS
  Zero-model daily security check. Read-only: it never upgrades, restarts or changes anything.
.DESCRIPTION
  Runs a set of switchable modules, de-duplicates findings against a baseline, and stays quiet when nothing is new.
  Modules (all configured in config.json, see config.example.json):
    osv            package-lock.json files (local or fetched over ssh) against OSV (includes GitHub Advisory and OSSF malicious-package data)
    hosts          Debian/Ubuntu hosts over ssh: pending security upgrades, kernel/reboot state, OpenSSH/Caddy versions, services enabled at boot
    node           Node.js versions of the machines you list vs the latest security release on nodejs.org
    router         router firmware: latest version published at a URL vs the version you run
    windowsUpdate  days since the last installed Windows hotfix (local machine and optional remote Windows machines)
    kev            new CISA Known Exploited Vulnerabilities entries that match your keyword list
    keyleak        key-shaped strings in files changed recently (value-blind), fingerprint match against your active secrets, secrets folder ACL
  Output: one markdown alert file per run that has NEW findings (written to every directory in alertDirs), one line in run.log otherwise.
  Values from config.json that end up in a remote command are checked against allow-lists first (lib-validate.ps1); a bad value is reported as config-* and skipped.
.PARAMETER ConfigPath
  Path to config.json (default: config.json next to this script).
.PARAMETER Seed
  Record every current finding as already known and send no alert. Use on first deployment.
.PARAMETER DryRun
  Writes nothing at all (no alert file, no baseline, no run.log, no state folder); prints what would be reported.
.NOTES
  License: MIT. Windows PowerShell 5.1 or PowerShell 7. ASCII-only source on purpose (no BOM needed).
#>
param(
    [string]$ConfigPath = (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'config.json'),
    [switch]$Seed,
    [switch]$DryRun
)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
# Windows PowerShell 5.1 may default to old TLS versions; PowerShell 7 negotiates TLS 1.2/1.3 by itself and must not be pinned down.
if ($PSVersionTable.PSVersion.Major -lt 6) { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDir 'lib-validate.ps1')
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Expand-UserPath([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return $p }
    if ($p -eq '~') { return $env:USERPROFILE }
    if ($p.StartsWith('~/') -or $p.StartsWith('~\')) { return (Join-Path $env:USERPROFILE $p.Substring(2)) }
    if (-not [IO.Path]::IsPathRooted($p)) { return (Join-Path $scriptDir $p) }
    return $p
}
if (-not (Test-Path -LiteralPath $ConfigPath)) { Write-Error "config not found: $ConfigPath (copy config.example.json to config.json first)"; exit 2 }
$cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
function Test-Module([string]$Name) { return ($cfg.modules -and $cfg.modules.PSObject.Properties[$Name] -and [bool]$cfg.modules.$Name) }
# a missing key must mean "no items"; in Windows PowerShell 5.1 @($null) has one element, so drop nulls explicitly
function Get-Items($Value) { return @($Value | Where-Object { $null -ne $_ -and $_ -ne '' }) }

$stateDir = Expand-UserPath $(if ($cfg.stateDir) { [string]$cfg.stateDir } else { 'state' })
if (-not $DryRun) { New-Item -ItemType Directory -Force -Path $stateDir | Out-Null }
$alertDirs = @(); foreach ($d in (Get-Items $cfg.alertDirs)) { $alertDirs += (Expand-UserPath ([string]$d)) }
if ($alertDirs.Count -eq 0) { $alertDirs = @((Join-Path $scriptDir 'alerts')) }
$basePath = Join-Path $stateDir 'baseline.json'
$logPath = Join-Path $stateDir 'run.log'
$findings = New-Object System.Collections.ArrayList
$errors = New-Object System.Collections.ArrayList
function Add-Finding([string]$Id, [string]$Area, [string]$Severity, [string]$Summary, [string]$Note) { [void]$findings.Add([pscustomobject]@{ id = $Id; area = $Area; severity = $Severity; summary = $Summary; note = $Note }) }
function Add-Err([string]$What) { [void]$errors.Add($What) }
function Get-Json([string]$Url) { try { return (Invoke-RestMethod -Uri $Url -TimeoutSec 60 -UseBasicParsing) } catch { Add-Err "fetch-failed:$Url"; return $null } }

$nodeExe = 'node'
if ($cfg.node -and $cfg.node.localNode) { if (Test-SafeWindowsPath ([string]$cfg.node.localNode)) { $nodeExe = [string]$cfg.node.localNode } else { Add-Err 'config-invalid:node.localNode' } }
$sshKeyDefault = if ($cfg.ssh -and $cfg.ssh.keyFile) { Expand-UserPath ([string]$cfg.ssh.keyFile) } else { '' }

function Invoke-Ssh([string]$Target, [string]$KeyFile, [string]$Command) {
    if (-not (Test-SafeSshTarget $Target)) { Add-Err 'config-invalid:ssh-target'; return '' }
    $sshArgs = Get-SshArgs $Target $KeyFile
    return (& ssh @sshArgs $Command 2>$null | Out-String)
}
function Invoke-RemoteBash([string]$Target, [string]$KeyFile, [string]$Script) {
    # Windows PowerShell 5.1 strips double quotes from native-command arguments: ship the script as base64
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Script))
    return (Invoke-Ssh $Target $KeyFile ('echo ' + $b64 + ' | base64 -d | bash'))
}
function Invoke-RemotePowerShell([string]$Target, [string]$KeyFile, [string]$Script) {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))
    return (Invoke-Ssh $Target $KeyFile ('powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $enc))
}
function Get-HostKey($h) { if ($h.keyFile) { return (Expand-UserPath ([string]$h.keyFile)) } else { return $sshKeyDefault } }

# ---------------------------------------------------------------- osv
if (Test-Module 'osv') {
    try {
        $tmp = Join-Path $env:TEMP ('seccheck-' + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        $lockArgs = @()
        foreach ($l in (Get-Items $cfg.osv.locks)) {
            if (-not (Test-SafeLabel ([string]$l.label))) { Add-Err 'config-invalid:osv.locks.label'; continue }
            if ($l.path -and (Test-Path -LiteralPath (Expand-UserPath ([string]$l.path)))) { $lockArgs += ([string]$l.label + '=' + (Expand-UserPath ([string]$l.path))) }
        }
        $i = 0
        foreach ($r in (Get-Items $cfg.osv.remoteLocks)) {
            $i++
            if (-not (Test-SafeLabel ([string]$r.label)) -or -not (Test-SafeLabel ([string]$r.host))) { Add-Err 'config-invalid:osv.remoteLocks.label-or-host'; continue }
            if (-not (Test-SafeRemotePath ([string]$r.path))) { Add-Err "config-invalid:osv.remoteLocks.path:$($r.label)"; continue }
            $hostCfg = Get-Items $cfg.hosts | Where-Object { $_.name -eq $r.host } | Select-Object -First 1
            if (-not $hostCfg) { Add-Err "osv-remote-unknown-host:$($r.host)"; continue }
            $dst = Join-Path $tmp ("remote$i.json")
            $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('cat ' + (ConvertTo-SingleQuoted ([string]$r.path))))
            $txt = Invoke-Ssh ([string]$hostCfg.target) (Get-HostKey $hostCfg) ('echo ' + $b64 + ' | base64 -d | bash')
            [IO.File]::WriteAllText($dst, $txt, $utf8)
            if ((Get-Item $dst).Length -gt 1000) { $lockArgs += ([string]$r.label + '=' + $dst) } else { Add-Err "osv-remote-unreadable:$($r.label)" }
        }
        if ($lockArgs.Count -gt 0) {
            $minSev = if ($cfg.osv.minSeverity) { [string]$cfg.osv.minSeverity } else { 'HIGH' }
            $osvJson = & $nodeExe (Join-Path $scriptDir 'osv-scan.mjs') @lockArgs '--min-severity' $minSev 2>$null | Out-String
            $osv = $osvJson | ConvertFrom-Json
            if ($osv.error) { Add-Err ('osv:' + [string]$osv.error) }
            foreach ($f in @($osv.findings)) {
                if ($null -eq $f) { continue }
                if ($f.kind -eq 'advisory' -and -not $f.prod) { continue }   # advisories only for production dependencies; malicious packages always count
                $note = if ($f.kind -eq 'malware') { 'applies (malicious package match)' } elseif ($f.prod) { 'needs review (production dependency)' } else { 'low (dev dependency only)' }
                $sev = if ($f.kind -eq 'malware') { 'CRITICAL' } else { [string]$f.severity }
                Add-Finding ('osv:' + $f.id + ':' + $f.pkg + '@' + $f.ver) 'lockfile' $sev ("$($f.id) $($f.pkg)@$($f.ver) ($($f.kind)) in " + ($f.labels -join ',')) $note
            }
        }
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    } catch { Add-Err "osv:$($_.Exception.Message)" }
}

# ---------------------------------------------------------------- hosts
$hostInfo = @{}
if (Test-Module 'hosts') {
    foreach ($h in (Get-Items $cfg.hosts)) {
        $name = [string]$h.name
        if (-not (Test-SafeLabel $name) -or -not (Test-SafeSshTarget ([string]$h.target))) { Add-Err 'config-invalid:hosts.name-or-target'; continue }
        $svcs = @(Get-Items $h.services); $usvcs = @(Get-Items $h.userServices)
        $badSvc = @(@($svcs + $usvcs) | Where-Object { $null -ne $_ -and -not (Test-SafeLabel ([string]$_)) })
        if ($badSvc.Count -gt 0) { Add-Err "config-invalid:hosts.services:$name"; continue }
        $svcList = $svcs -join ' '
        $usvcList = $usvcs -join ' '
        $script = @"
echo "KERNEL_RUN=`$(uname -r)"
echo "KERNEL_INSTALLED=`$(dpkg -l 'linux-image-[0-9]*' | awk '/^ii/{print `$2}' | sed 's/linux-image-//' | sort -V | tail -1)"
echo "REBOOT_REQUIRED=`$([ -e /var/run/reboot-required ] && echo yes || echo no)"
echo "NODE_VER=`$(node -v 2>/dev/null)"
echo "UU_ACTIVE=`$(systemctl is-active unattended-upgrades)"
echo "UU_AUTOREBOOT=`$(apt-config dump | grep -c 'Unattended-Upgrade::Automatic-Reboot \"true\"')"
echo "UPG_KERNEL=`$(apt list --upgradable 2>/dev/null | grep -E 'linux-image|linux-generic' | cut -d/ -f1 | tr '\n' ' ')"
echo "UPG_SECURITY=`$(apt list --upgradable 2>/dev/null | grep security | cut -d/ -f1 | tr '\n' ' ')"
echo "UPG_SSH=`$(apt list --upgradable 2>/dev/null | grep -E '^openssh' | cut -d/ -f1 | tr '\n' ' ')"
echo "UPG_CADDY=`$(apt list --upgradable 2>/dev/null | grep -E '^caddy/' | awk '{print `$2}')"
echo "CADDY_VER=`$(caddy version 2>/dev/null | awk '{print `$1}')"
echo "UPTIME_DAYS=`$(awk '{print int(`$1/86400)}' /proc/uptime)"
for s in $svcList; do systemctl cat `$s >/dev/null 2>&1 && echo "SVC_`$s=`$(systemctl is-enabled `$s 2>&1)"; done
for s in $usvcList; do systemctl --user cat `$s >/dev/null 2>&1 && echo "USVC_`$s=`$(systemctl --user is-enabled `$s 2>&1)"; done
loginctl show-user "`$(id -un)" -p Linger 2>/dev/null | sed 's/^/USER_/'
"@
        $out = Invoke-RemoteBash ([string]$h.target) (Get-HostKey $h) $script
        $kv = @{}
        foreach ($line in ($out -split "`n")) { if ($line -match '^([A-Z_a-z0-9\-]+)=(.*)$') { $kv[$matches[1]] = $matches[2].Trim() } }
        if (-not $kv.ContainsKey('KERNEL_RUN')) { Add-Err "host-${name}-unreachable"; continue }
        $hostInfo[$name] = $kv
        if ($kv.UPG_KERNEL) { Add-Finding ("kernel-upgrade:${name}:" + ($kv.UPG_KERNEL -replace '\s+', '_')) 'kernel' 'HIGH' "host $name has kernel packages to upgrade: $($kv.UPG_KERNEL)" 'applies' }
        if ($kv.REBOOT_REQUIRED -eq 'yes' -and [int]$kv.UPTIME_DAYS -ge 2 -and $kv.UU_AUTOREBOOT -eq '0') { Add-Finding "reboot-pending:$name" 'kernel' 'MEDIUM' "host $name needs a reboot (installed kernel $($kv.KERNEL_INSTALLED), running $($kv.KERNEL_RUN), uptime $($kv.UPTIME_DAYS) days, automatic reboot is off)" 'applies' }
        elseif ($kv.REBOOT_REQUIRED -eq 'yes' -and [int]$kv.UPTIME_DAYS -ge 3) { Add-Finding "reboot-stuck:$name" 'kernel' 'MEDIUM' "host $name has needed a reboot for more than 3 days (automatic reboot setting = $($kv.UU_AUTOREBOOT))" 'applies' }
        if ($kv.KERNEL_RUN -ne $kv.KERNEL_INSTALLED -and $kv.REBOOT_REQUIRED -ne 'yes') { Add-Finding ("kernel-mismatch:${name}:" + $kv.KERNEL_INSTALLED) 'kernel' 'MEDIUM' "host $name runs kernel $($kv.KERNEL_RUN) but $($kv.KERNEL_INSTALLED) is installed" 'applies' }
        if ($kv.UPG_SECURITY) { foreach ($pkg in ($kv.UPG_SECURITY -split '\s+' | Where-Object { $_ })) { Add-Finding "apt-security:${name}:$pkg" 'apt' 'MEDIUM' "host $name has a pending security update: $pkg" 'usually installed automatically next day; follow up only if it persists' } }
        if ($kv.UPG_SSH) { Add-Finding ("openssh-upgrade:${name}:" + ($kv.UPG_SSH -replace '\s+', '_')) 'ssh' 'HIGH' "host $name has an OpenSSH package upgrade: $($kv.UPG_SSH)" 'applies' }
        if ($kv.UU_ACTIVE -ne 'active') { Add-Finding "uu-inactive:$name" 'apt' 'HIGH' "host $name unattended-upgrades is not active ($($kv.UU_ACTIVE))" 'applies' }
        foreach ($k in $kv.Keys) {
            if ($k -like 'SVC_*' -and $kv[$k] -ne 'enabled') { Add-Finding ("svc-not-enabled:${name}:" + $k.Substring(4)) 'autostart' 'HIGH' "host $name service $($k.Substring(4)) is not enabled at boot ($($kv[$k]))" 'will not come back after a reboot' }
            if ($k -like 'USVC_*' -and $kv[$k] -ne 'enabled') { Add-Finding ("usvc-not-enabled:${name}:" + $k.Substring(5)) 'autostart' 'HIGH' "host $name user service $($k.Substring(5)) is not enabled at boot ($($kv[$k]))" 'will not come back after a reboot' }
        }
        if ($h.checkLinger -and $kv['USER_Linger'] -and $kv['USER_Linger'] -ne 'yes') { Add-Finding "linger-off:$name" 'autostart' 'HIGH' "host $name user lingering is off" 'user services will not start after a reboot' }
        if ($kv.UPG_CADDY) { Add-Finding ("caddy-upgrade:${name}:" + $kv.UPG_CADDY) 'caddy' 'MEDIUM' "host $name Caddy can be upgraded to $($kv.UPG_CADDY) (now $($kv.CADDY_VER))" 'check the release notes, then schedule' }
    }
}

# ---------------------------------------------------------------- node (+ remote windows info reused by windowsUpdate)
$winInfo = @{}
if ((Test-Module 'node') -or (Test-Module 'windowsUpdate')) {
    foreach ($w in (Get-Items $cfg.remoteWindows)) {
        try {
            $wname = [string]$w.name
            $nodePath = if ($w.nodePath) { [string]$w.nodePath } else { 'C:\Program Files\nodejs\node.exe' }
            if (-not (Test-SafeLabel $wname) -or -not (Test-SafeSshTarget ([string]$w.target)) -or -not (Test-SafeWindowsPath $nodePath)) { Add-Err 'config-invalid:remoteWindows'; continue }
            $ps = '$n = & ''' + $nodePath + ''' -v 2>$null; "W_NODE=$n"; $h = (Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn; "W_HOTFIX=" + $h.ToString(''yyyy-MM-dd'')'
            $out = Invoke-RemotePowerShell ([string]$w.target) (Get-HostKey $w) $ps
            $kv = @{}
            foreach ($line in ($out -split "`n")) { if ($line -match '^(W_NODE|W_HOTFIX)=(.*)$') { $kv[$matches[1]] = $matches[2].Trim() } }
            $winInfo[$wname] = $kv
        } catch { Add-Err "remote-windows:$($w.name)" }
    }
}
if (Test-Module 'node') {
    $idx = Get-Json 'https://nodejs.org/dist/index.json'
    $nodeVers = @{}
    foreach ($n in $hostInfo.Keys) { $nodeVers[$n] = [string]$hostInfo[$n].NODE_VER }
    try { $nodeVers[$(if ($cfg.node.localLabel) { [string]$cfg.node.localLabel } else { 'local' })] = (& $nodeExe -v 2>$null | Select-Object -First 1) } catch { Add-Err 'node-local' }
    foreach ($n in $winInfo.Keys) { if ($winInfo[$n].W_NODE -match '^v\d+\.\d+\.\d+') { $nodeVers[$n] = $winInfo[$n].W_NODE } else { Add-Err "node-${n}" } }
    if ($idx) {
        foreach ($n in $nodeVers.Keys) {
            $cur = [string]$nodeVers[$n]
            if ($cur -notmatch '^v(\d+)\.(\d+)\.(\d+)') { continue }
            $major = $matches[1]; $curV = [version]($cur.TrimStart('v'))
            $latestSec = $idx | Where-Object { $_.version -like "v$major.*" -and $_.security -eq $true } | Select-Object -First 1
            if ($latestSec -and $curV -lt [version]($latestSec.version.TrimStart('v'))) { Add-Finding ("node:${n}:" + $cur + '->' + $latestSec.version) 'node' 'HIGH' "Node on $n is $cur; latest security release of the v$major line is $($latestSec.version)" 'applies (version behind)' }
        }
    }
}

# ---------------------------------------------------------------- router
if (Test-Module 'router') {
    try {
        $rname = if ($cfg.router.name) { [string]$cfg.router.name } else { 'router' }
        $txt = (Invoke-WebRequest -Uri ([string]$cfg.router.firmwareUrl) -UseBasicParsing -TimeoutSec 40).Content
        $mm = [regex]::Match([string]$txt, '\d+\.\d+\.\d+(?:\.\d+)?')
        if ($mm.Success) { if ([version]$mm.Value -gt [version][string]$cfg.router.currentVersion) { Add-Finding ('router:' + $rname + ':' + $mm.Value) 'router' 'HIGH' "$rname firmware $($mm.Value) is published (running $($cfg.router.currentVersion))" 'applies (upgrade by hand, then update currentVersion in config)' } } else { Add-Err 'router-parse' }
    } catch { Add-Err 'router-fetch' }
}

# ---------------------------------------------------------------- windows update age
if (Test-Module 'windowsUpdate') {
    $maxAge = if ($cfg.windowsUpdate.maxAgeDays) { [int]$cfg.windowsUpdate.maxAgeDays } else { 35 }
    try {
        $localLabel = if ($cfg.windowsUpdate.localLabel) { [string]$cfg.windowsUpdate.localLabel } else { 'local' }
        $last = (Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
        if ($last -and ((Get-Date) - $last).TotalDays -gt $maxAge) { Add-Finding "hotfix:$localLabel" 'windows' 'MEDIUM' ("$localLabel last Windows update was " + [int]((Get-Date) - $last).TotalDays + ' days ago') 'applies (install updates)' }
    } catch { Add-Err 'hotfix-local' }
    foreach ($n in $winInfo.Keys) {
        try {
            if ($winInfo[$n].W_HOTFIX -match '^\d{4}-\d{2}-\d{2}$') { $d = [datetime]$winInfo[$n].W_HOTFIX; if (((Get-Date) - $d).TotalDays -gt $maxAge) { Add-Finding "hotfix:$n" 'windows' 'MEDIUM' ("$n last Windows update was " + [int]((Get-Date) - $d).TotalDays + ' days ago') 'applies (install updates)' } } else { Add-Err "hotfix-${n}" }
        } catch { Add-Err "hotfix-${n}" }
    }
}

# ---------------------------------------------------------------- kev
$kevMax = ''
if (Test-Module 'kev') {
    $kevKeywords = @($cfg.kev.keywords | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ })
    $kev = Get-Json 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    if ($kev -and $kev.vulnerabilities) {
        $baseline0 = $null; if (Test-Path -LiteralPath $basePath) { try { $baseline0 = Get-Content -LiteralPath $basePath -Raw -Encoding UTF8 | ConvertFrom-Json } catch {} }
        $since = if ($baseline0 -and $baseline0.kevLastDate) { [string]$baseline0.kevLastDate } else { (Get-Date).AddDays(-14).ToString('yyyy-MM-dd') }
        $kevMax = ($kev.vulnerabilities | Measure-Object -Property dateAdded -Maximum).Maximum
        foreach ($v in $kev.vulnerabilities) {
            if ([string]$v.dateAdded -le $since) { continue }
            $hay = (($v.vendorProject + ' ' + $v.product + ' ' + $v.vulnerabilityName)).ToLowerInvariant()
            foreach ($k in $kevKeywords) { if ($hay.Contains($k)) { Add-Finding ('kev:' + $v.cveID) 'kev' 'HIGH' ("CISA KEV added $($v.cveID): $($v.vendorProject) $($v.product) ($($v.dateAdded))") ('needs review (keyword match: ' + $k + ')'); break } }
        }
    }
}

# ---------------------------------------------------------------- keyleak
if (Test-Module 'keyleak') {
    try {
        $klArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $scriptDir 'keyleak-scan.ps1'), '-Json')
        if ($cfg.keyleak.roots) { $klArgs += @('-Roots', ((Get-Items $cfg.keyleak.roots | ForEach-Object { Expand-UserPath ([string]$_) }) -join ',')) }
        if ($cfg.keyleak.secretsDir) { $klArgs += @('-SecretsDir', (Expand-UserPath ([string]$cfg.keyleak.secretsDir))) }
        if ($cfg.keyleak.activeFiles) { $klArgs += @('-ActiveFiles', ((Get-Items $cfg.keyleak.activeFiles | ForEach-Object { Expand-UserPath ([string]$_) }) -join ',')) }
        if ($cfg.keyleak.excludeDirs) { $klArgs += @('-ExcludeDirs', ((Get-Items $cfg.keyleak.excludeDirs) -join ',')) }
        if ($cfg.keyleak.hoursBack) { $klArgs += @('-HoursBack', [string][int]$cfg.keyleak.hoursBack) }
        $kl = ((& powershell.exe @klArgs) | Out-String) | ConvertFrom-Json
        foreach ($h in @($kl.findings)) {
            if ($null -eq $h) { continue }
            $summary = if ($h.kind -eq 'secrets-acl-widened') { "secrets folder permissions widened: $($h.principal) has access" } else { "file contains key-shaped string $($h.kind) (fingerprint $($h.fp)): $($h.path)" }
            $note = if ($h.active) { 'same fingerprint as a currently active secret: treat it as exposed and rotate it' } else { 'review the file' }
            Add-Finding $h.id 'keyleak' $h.severity $summary $note
        }
        foreach ($e in @($kl.errors)) { if ($e) { Add-Err "keyleak:$e" } }
    } catch { Add-Err 'keyleak-failed' }
}

# ---------------------------------------------------------------- baseline de-duplication
$baseline = [ordered]@{ acknowledged = @(); kevLastDate = ''; updated = '' }
if (Test-Path -LiteralPath $basePath) { try { $b0 = Get-Content -LiteralPath $basePath -Raw -Encoding UTF8 | ConvertFrom-Json; $baseline.acknowledged = @($b0.acknowledged); $baseline.kevLastDate = [string]$b0.kevLastDate } catch {} }
$known = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($k in $baseline.acknowledged) { [void]$known.Add([string]$k) }
$new = @($findings | Where-Object { -not $known.Contains($_.id) })
$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
function Write-RunLog([string]$Line) { if (-not $DryRun) { Add-Content -LiteralPath $logPath -Value $Line -Encoding UTF8 } }
if ($Seed) {
    $baseline.acknowledged = @($findings | ForEach-Object { $_.id })
    $baseline.kevLastDate = if ($kevMax) { [string]$kevMax } else { $baseline.kevLastDate }
    $baseline.updated = $ts
    if (-not $DryRun) { [IO.File]::WriteAllText($basePath, ($baseline | ConvertTo-Json -Depth 4), $utf8) }
    Write-RunLog ("$ts SEED findings=$($findings.Count) errors=$($errors.Count)" + $(if ($errors.Count) { ' err=' + ($errors -join ',') } else { '' }))
    Write-Output ("SEED findings=$($findings.Count) errors=$($errors.Count)")
    exit 0
}
if ($new.Count -gt 0 -and -not $DryRun) {
    $lines = $new | ForEach-Object { "- **[$($_.severity)] $($_.area)**: $($_.summary) | note: $($_.note)" }
    $body = "---`ntitle: daily security check`ndate: $ts`n---`n`n# Daily security check: $($new.Count) new finding(s)`n`n" + ($lines -join "`n") + "`n`n(Read-only check. Known items are kept in baseline.json. Failed checks: " + $(if ($errors.Count) { $errors -join ',' } else { 'none' }) + ")`n"
    $name = 'ALERT-seccheck-{0}.md' -f (Get-Date -Format 'yyyyMMdd-HHmm')
    foreach ($d in $alertDirs) { New-Item -ItemType Directory -Force -Path $d | Out-Null; [IO.File]::WriteAllText((Join-Path $d $name), $body, $utf8) }
    foreach ($f in $new) { $baseline.acknowledged += $f.id }
}
# keep only findings that still exist plus the ones just reported (a resolved finding that comes back is reported again)
$baseline.acknowledged = @($baseline.acknowledged | Where-Object { $id = $_; $findings | Where-Object { $_.id -eq $id } } | Select-Object -Unique)
if ($kevMax) { $baseline.kevLastDate = [string]$kevMax }
$baseline.updated = $ts
if (-not $DryRun) { [IO.File]::WriteAllText($basePath, ($baseline | ConvertTo-Json -Depth 4), $utf8) }
Write-RunLog ("$ts findings=$($findings.Count) new=$($new.Count) errors=$($errors.Count)" + $(if ($errors.Count) { ' err=' + ($errors -join ',') } else { '' }))
Write-Output ("findings=$($findings.Count) new=$($new.Count) errors=$($errors.Count)")
if ($DryRun) { 'ERRORS: ' + ($errors -join ','); $new | ForEach-Object { "NEW [$($_.severity)] $($_.id) :: $($_.summary)" } }
