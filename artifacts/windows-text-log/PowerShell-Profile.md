---
name: PowerShell-Profile
title-description: "PowerShell $PROFILE script — auto-executed on every PowerShell session start"
aliases:
- PowerShell profile
- $PROFILE script
- Microsoft.PowerShell_profile.ps1
- profile.ps1
link: persistence
tags:
- persistence-primary
- user-scope
- living-off-the-land
- itm:PR
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: PowerShell-Profile
platform:
  windows:
    min: '7'
    max: '11'
    note: "Windows PowerShell 5.x uses the \\WindowsPowerShell\\ subdirectory. PowerShell 7+ (PowerShell Core) uses \\PowerShell\\. Both engines consult their own profile script independently — dual-profile plants exist."
  windows-server:
    min: '2008R2'
    max: '2022'
location:
  path-user-ps5: "%USERPROFILE%\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1"
  path-user-ps5-all-hosts: "%USERPROFILE%\\Documents\\WindowsPowerShell\\profile.ps1"
  path-user-ps7: "%USERPROFILE%\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1"
  path-user-ps7-all-hosts: "%USERPROFILE%\\Documents\\PowerShell\\profile.ps1"
  path-all-users-ps5: "%WINDIR%\\System32\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1"
  path-all-users-ps5-all-hosts: "%WINDIR%\\System32\\WindowsPowerShell\\v1.0\\profile.ps1"
  path-all-users-ps7: "%PROGRAMFILES%\\PowerShell\\7\\Microsoft.PowerShell_profile.ps1"
  path-ise-user: "%USERPROFILE%\\Documents\\WindowsPowerShell\\Microsoft.PowerShellISE_profile.ps1"
  path-vscode-user: "%USERPROFILE%\\Documents\\PowerShell\\Microsoft.VSCode_profile.ps1"
  addressing: file-path
  note: "Six+ distinct profile script paths per user account. Each PowerShell HOST (console, ISE, VSCode, embedded runspaces) has its own profile name. Each SCOPE (current user vs. all users) has its own directory. Each ENGINE version (Windows PowerShell 5.1 vs PowerShell 7) reads from different roots. Persistence plants commonly target the CURRENT USER scope's Microsoft.PowerShell_profile.ps1 because it fires on the most common trigger (user opens a PowerShell console) without admin rights to install."
fields:
- name: profile-script
  kind: content
  location: profile .ps1 file contents
  encoding: utf-8 or utf-16le (PowerShell handles both)
  references-data:
  - concept: UserSID
    role: profileOwner
  note: "Arbitrary PowerShell code. Executes in the current user's security context every time a PowerShell session launches. Attacker-authored profile scripts commonly: (1) import a malicious module from disk or HTTP, (2) set aliases that replace common commands (gci, ls, dir) with attacker-wrapped versions, (3) run an in-memory payload directly via Invoke-Expression + base64-decoded string, (4) register a PSReadLine key-handler that logs user keystrokes."
- name: profile-mtime
  kind: timestamp
  location: .ps1 file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime. For a legitimate user profile, the file rarely changes after initial setup. A recent mtime outside documented script-editing windows = plant."
- name: profile-size
  kind: counter
  location: .ps1 file size
  encoding: uint64
  note: "Unexpectedly large profile size (> few KB) = lots of content that may include embedded encoded payloads. Unexpectedly tiny size on an otherwise-active user = legitimate minimal profile OR a recently-wiped previously-populated plant."
- name: ise-profile-present
  kind: flags
  location: Microsoft.PowerShellISE_profile.ps1 existence
  note: "Windows PowerShell ISE has its own profile file. On modern Windows (PowerShell 5.1 era) ISE is increasingly deprecated. An attacker targeting ISE specifically is unusual and may indicate targeting of admin-user workflow (ISE is a power-user tool)."
- name: dot-sourced-inclusions
  kind: path
  location: ". C:\\path\\to\\other.ps1 lines inside the profile script"
  note: "Dot-source inclusions (`. C:\\some\\other\\file.ps1`) chain other scripts. Attacker plants may use this to keep the profile file itself small (one line) while the actual payload lives elsewhere — inspect every dot-sourced path referenced by the profile."
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'PowerShell profile plants are an extremely durable user-scope
    persistence path: no admin required, no special triggers needed
    beyond "user opens PowerShell" — which admins, developers, SOC
    analysts, and increasingly ordinary users do routinely. The
    profile runs BEFORE any user command executes, giving attacker
    code first-access to the session. Because PSReadLine history
    lives in a sibling directory and the ConsoleHost_history.txt is
    what most responders grep first, the profile itself is frequently
    overlooked. Always inventory ALL six per-user profile paths,
    plus the two all-users paths, plus any VSCode / ISE variants.'
  qualifier-map:
    object.path: field:profile-script
    time.end: field:profile-mtime
anti-forensic:
  write-privilege: user
  integrity-mechanism: none (plain text, no signing)
  survival-signals:
  - Any profile .ps1 file present on a user account that claims not to use PowerShell = candidate plant
  - Profile mtime recent and content contains Invoke-Expression / IEX / base64-decoded blobs = likely attacker code
  - Dot-source inclusion of paths in %TEMP% / user-writable locations = redirection to attacker-controlled payload
  - ImportModule lines pointing to non-PSGallery / non-Microsoft module paths outside documented enterprise repositories = sideloaded attacker module
  - PSReadLineOption -HistorySaveStyle SaveNothing set inside the profile = anti-forensics suppression of ConsoleHost_history
provenance:
  - ms-about-profiles-powershell-profile-s
  - mitre-t1546-013
  - canary-2022-powershell-profile-persistence
---

# PowerShell $PROFILE Persistence

## Forensic value
PowerShell consults a hierarchy of profile scripts on every session start. Each script runs in the user's security context before any user command executes. The hierarchy is:

**Windows PowerShell 5.x** (`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`)
- All Users, All Hosts: `%WINDIR%\System32\WindowsPowerShell\v1.0\profile.ps1`
- All Users, Current Host: `%WINDIR%\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1`
- Current User, All Hosts: `%USERPROFILE%\Documents\WindowsPowerShell\profile.ps1`
- Current User, Current Host: `%USERPROFILE%\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`

**PowerShell 7+** (`%PROGRAMFILES%\PowerShell\7\pwsh.exe`)
- All Users: `%PROGRAMFILES%\PowerShell\7\Microsoft.PowerShell_profile.ps1`
- Current User: `%USERPROFILE%\Documents\PowerShell\Microsoft.PowerShell_profile.ps1`

**Host-specific** (each host appends its own profile name):
- ISE: `Microsoft.PowerShellISE_profile.ps1`
- VSCode: `Microsoft.VSCode_profile.ps1`

For a given user's `powershell.exe` console session, PowerShell sources all applicable profiles in order. Any of them can house a persistence plant.

## Why this is under-detected
- Profile script paths are numerous (8+ per user) — sweep playbooks often check only the Current User Current Host path
- The ConsoleHost_history.txt (PSReadline) frequently dominates analyst attention, shadowing the profile itself
- Legitimate users with customized profiles exist — the analyst must distinguish "personal customization" from "attacker plant," which requires content inspection

## Concept reference
- None direct — script-content artifact. References inside the script (paths, URLs) surface the concepts.

## Triage
```powershell
# Inventory all profile paths that EXIST across all users
$paths = @(
    "C:\Users\*\Documents\WindowsPowerShell\*.ps1",
    "C:\Users\*\Documents\PowerShell\*.ps1",
    "C:\Windows\System32\WindowsPowerShell\v1.0\*.ps1",
    "C:\Program Files\PowerShell\7\*.ps1"
)
foreach ($p in $paths) { Get-ChildItem $p -ErrorAction SilentlyContinue | Format-Table FullName, Length, LastWriteTime }
```

For each existing profile file, read the content and look for:
- `Invoke-Expression` / `IEX` with obfuscated / base64 / downloaded argument
- `Import-Module` pointing to non-standard paths
- Aliases overriding common cmdlets (`Set-Alias -Name ls -Value Attacker-Version`)
- `Add-Type` with inline C# source (in-memory compiled shellcode loader)
- `Register-EngineEvent` / `Register-ObjectEvent` for persistent background work
- `Set-PSReadLineOption -HistorySaveStyle SaveNothing` = anti-forensics

## Cross-reference
- PSReadline history (`ConsoleHost_history.txt`) for interactive evidence of the user editing the profile
- PowerShell Operational events 4104 (Script Block Logging) — profile load event may be logged with script-block content
- Amcache / Prefetch entry for `powershell.exe` / `pwsh.exe` = session-start evidence
- Sysmon 4104 / 400 / 600 if PowerShell module/scriptblock logging is on

## Practice hint
```powershell
# Test harness — observe the profile firing
Test-Path $PROFILE  # returns the current-host-current-user path
# Author:
Set-Content -Path $PROFILE -Value 'Write-Host "Profile fired at $(Get-Date)" -ForegroundColor Yellow' -Force
# Close PowerShell, open a new session — yellow banner appears before any prompt
# Clean up:
Remove-Item $PROFILE
```
That banner's timing — BEFORE the prompt — is why profile persistence is powerful. Attacker code runs before any detection you might type.
