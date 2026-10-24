# daily-seccheck

A zero-model, read-only daily security check for Windows PowerShell. It checks, reports only what is new, and never changes anything.

Modules (each one can be switched on or off in `config.json`): `osv` (package-lock.json against OSV), `hosts` (Debian/Ubuntu hosts over ssh), `node` (Node.js versions), `router` (firmware version), `windowsUpdate`, `kev` (CISA Known Exploited Vulnerabilities keyword match), `keyleak` (key-shaped strings in recently changed files, value-blind, plus secrets-folder permissions).

- Documentation (Traditional Chinese): [README.zh-TW.md](README.zh-TW.md)
- Quick start: copy `config.example.json` to `config.json`, edit it, run `.\daily-seccheck.ps1 -Seed` once, then schedule `.\daily-seccheck.ps1` daily.
- Safety notes: values from `config.json` that reach a remote command are checked against allow-lists; ssh runs with `BatchMode=yes` and never disables host key checking (accept each host key by hand once); `-DryRun` writes nothing.
- Tests: `tests\test-keyleak-scan.ps1`, `tests\test-hardening.ps1` (fault-injection style: each test must catch a deliberately broken copy of the code).
- Maintenance: best effort. Issues and pull requests are welcome, but there is no guaranteed response time. The script runs entirely on your own machine and does not depend on any service of ours, so an installed copy keeps working even if this project goes quiet.
- License: MIT, see `LICENSE`. Maintained by Tianjige Lab.
