# lib-validate.ps1 - input validation helpers for daily-seccheck. Dot-sourced by daily-seccheck.ps1 and by the tests.
# Every value that comes from config.json and is later placed into a remote shell command, a remote PowerShell script or an ssh argument list goes through
# one of these allow-list checks first. A value that fails is reported as a config error and the item is skipped (never passed on silently).
# ASCII-only on purpose.

function Test-SafeLabel([string]$Value) {
    # service names, host names and labels
    return ($Value -match '^[A-Za-z0-9@._:-]+$')
}
function Test-SafeRemotePath([string]$Value) {
    # absolute or relative POSIX-style path on a remote host: no spaces, quotes, shell metacharacters or control characters
    return ($Value -match '^[A-Za-z0-9_@%+=:,./~-]+$')
}
function Test-SafeWindowsPath([string]$Value) {
    # path of an executable on a remote Windows machine: letters, digits, space, drive colon, backslash, slash, dot, underscore, hyphen, parentheses
    # never a quote, so it can be wrapped in single quotes inside the remote PowerShell script
    return ($Value -match '^[A-Za-z0-9 _:\\/.()-]+$')
}
function Test-SafeSshTarget([string]$Value) {
    # [user@]host ; must not start with '-' (ssh would read it as an option)
    return ($Value -match '^([A-Za-z0-9._][A-Za-z0-9._-]*@)?(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9._:-]*)$')
}
function Get-SshArgs([string]$Target, [string]$KeyFile) {
    # option list for ssh. '--' ends option parsing so the target and the command can never be read as options.
    $a = @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=20')
    if ($KeyFile) { $a = @('-i', $KeyFile) + $a }
    return ($a + @('--', $Target))
}
function ConvertTo-SingleQuoted([string]$Value) {
    # POSIX shell single-quote escaping
    return ("'" + ($Value -replace "'", "'\''") + "'")
}
