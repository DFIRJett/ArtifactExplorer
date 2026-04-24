---
name: Startup-LNK
aliases:
- Startup folder shortcut
- LNK-based autorun
- Start Menu\Programs\Startup
link: persistence
tags:
- persistence-primary
- tamper-easy
- autorun
volatility: persistent
interaction-required: user-action
substrate: windows-lnk
substrate-instance: Startup-folder
substrate-hub: System scope
platform:
  windows:
    min: XP
    max: '11'
location:
  path-user: "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*.lnk"
  path-all-users: "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*.lnk"
  addressing: filesystem-path
fields:
- name: target-path
  kind: path
  location: LNK LinkTargetIDList + LinkInfo LocalBasePath
  note: executable (or script) launched at logon
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
- name: arguments
  kind: command
  location: LNK StringData.CommandLineArguments
  note: command-line arguments — key for PowerShell/VBS downloaders that launch via wscript.exe or powershell.exe in Startup-LNK
- name: working-directory
  kind: path
  location: LNK StringData.WorkingDir
- name: icon-path
  kind: path
  location: LNK StringData.IconLocation
  note: attackers sometimes mismatch icon vs target to deceive users scanning Startup folder
- name: tracker-machine-id
  kind: identifier
  location: LNK TrackerDataBlock → MachineID
  note: if non-local, indicates the LNK was created on another host and copied in (supply-chain or lateral drop)
  references-data:
  - concept: MachineNetBIOS
    role: trackerMachineId
- name: lnk-file-mac
  kind: timestamps
  location: $MFT of the Startup-LNK file
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: volume-serial
  kind: identifier
  location: embedded ShellLNK → LinkInfo\VolumeID\VolumeSerialNumber
  encoding: uint32-le (hex display)
  references-data:
  - concept: FilesystemVolumeSerial
    role: accessedAtSerial
  note: inherited from the embedded ShellLNK structure — attributes the LNK to a specific volume VSN at the moment of link creation
observations:
- proposition: PERSISTED
  ceiling: C3
  note: LNK-based logon autorun. Fires on interactive logon for the owning user (per-user scope) or for everyone (All Users scope).
  qualifier-map:
    actor.user: owning profile (per-user) OR system (all-users)
    object.persistence.executable: field:target-path
    object.persistence.arguments: field:arguments
    time.created: field:lnk-file-mac (Created)
anti-forensic:
  write-privilege: admin
  known-cleaners:
  - tool: manual file delete
    typically-removes: full
  - tool: Task Manager Startup-apps disable
    typically-removes: toggles via registry without removing file — LNK persists
provenance:
  - mitre-t1547-001
---

# Startup-LNK

## Forensic value
Classic logon-persistence mechanism. Any LNK file in the per-user or all-users Startup folder is launched when that user logs on interactively. Because the format is LNK, every entry carries the same rich metadata as Recent-LNK — target path, arguments, working directory, tracker data.

Distinct from Run-Keys persistence (registry) — Startup-LNK is filesystem-based, file-level, and easy to see if you know where to look. Often appears in malware because:
- No registry access needed
- Trivial drop with `copy evil.lnk %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`
- Looks like legitimate user-added shortcut

## The hook — target + arguments
Modern attackers rarely put raw malware binaries here. Instead, Startup-LNK points at:
- `powershell.exe -WindowStyle Hidden -Command <malicious one-liner>`
- `wscript.exe <path-to-jse-or-vbs>`
- `mshta.exe <url-or-local-hta>`
- `rundll32.exe <dll>,<export>`

The LNK's `StringData.CommandLineArguments` is the payload. A Startup-LNK where `target-path` = a LOLBin and `arguments` is a long base64/compressed string is a signature malicious pattern.

## Tracker indicator
If the LNK's `TrackerDataBlock.MachineID` is not the local hostname, the LNK was created on another host and copied in. Legitimate user-created Startup LNKs almost always show the local MachineID. Mismatch = supply-chain-drop or lateral-movement signal.

## Cross-references
- **Run-Keys** — registry-based equivalent; malware often uses one OR the other, not both
- **Sysmon-11** (FileCreate) captures the moment a new file lands in a Startup folder — high-signal detection event
- **Security-4688** / **Sysmon-1** — the process created at logon by the LNK launch

## Practice hint
```powershell
Get-ChildItem -Path $env:APPDATA\Microsoft\Windows\'Start Menu\Programs\Startup',
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Filter *.lnk -EA 0
```
Then LECmd each one to extract arguments. Flag any LOLBin targets with suspicious argument payloads.
