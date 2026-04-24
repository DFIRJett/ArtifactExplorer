---
name: ExecutablePath
kind: value-type
lifetime: persistent
link-affinity: application
link-affinity-secondary: file
description: |
  Full filesystem path to a program executable. Captured by many execution-
  evidence artifacts — Prefetch, Amcache, ShimCache, BAM/DAM, UserAssist,
  Security-4688, Sysmon-1, SRUM. Combining the path with a run timestamp
  is the cornerstone of "what executable ran and from where" questions.
canonical-format: "absolute filesystem path with drive letter or device path (e.g., 'C:\\Windows\\System32\\powershell.exe')"
aliases: [exe-path, image-path, program-path]
roles:
  - id: ranProcess
    description: "Executable that actually ran — captured by execution-evidence artifacts"
  - id: configuredPersistence
    description: "Executable configured to run via a persistence mechanism (Run keys, Services, Tasks, etc.)"
  - id: loadedModule
    description: "DLL loaded into a process (AppInit_DLLs, module-load events)"
  - id: actingProcess
    description: "Process that is the actor of a specific telemetry event (file create, registry set, DNS query, etc.)"
  - id: scannedTarget
    description: "Executable path scanned or matched by security tooling (AV, YARA)"
  - id: shellReference
    description: "Executable path referenced by shell-level caches without necessarily being executed"

known-containers:
  - Prefetch
  - Amcache-InventoryApplicationFile
  - Amcache-InventoryApplication
  - Amcache-InventoryApplicationShortcut
  - Amcache-InventoryDriverBinary
  - ShimCache
  - BAM
  - UserAssist
  - Security-4688
  - Security-4648
  - Sysmon-1
  - Sysmon-3
  - Sysmon-7
  - Sysmon-11
  - Sysmon-13
  - Sysmon-22
  - SRUM-Process
  - Run-Keys
  - Scheduled-Tasks
  - Services
  - AppInit-DLLs
  - Winlogon-Userinit-Shell
  - WMI-Subscriptions
  - MUICache
  - LastVisitedPidlMRU
  - Defender-MPLog
  - YARA-hits
---

# Executable Path

## What it is
The full path to a program that was executed on the system. Most execution-evidence artifacts capture it one way or another — sometimes as a registry value, sometimes inside a compressed prefetch file, sometimes as an EVTX event field.

This is the identity half of the core execution tuple: `EXECUTED(path, time, actor)`. The other concepts (ExecutableHash, RunCount) accompany it but don't substitute.

## Forensic value
- **Distinguishes benign-named malware from legitimate binaries.** `C:\Windows\Temp\svchost.exe` is suspect where `C:\Windows\System32\svchost.exe` is not. Path is load-bearing for that distinction.
- **Cross-artifact run-history reconstruction.** When Prefetch says `powershell.exe-<hashA>.pf` ran 3 times from path X, and Amcache lists path X first-seen at time Y, and BAM shows user Z last-ran path X at time W — you have four independent corroborations of one execution.
- **Anti-forensic signal via path anomaly.** Execution from `C:\Users\*\AppData\Local\Temp\*` or `\Device\HarddiskVolume*` (non-drive-letter paths) often warrants attention.

## Encoding variations

| Artifact | Where |
|---|---|
| Prefetch | in the header + in path strings referenced during loading |
| Amcache | `Root\InventoryApplicationFile\<Hash>\LowerCaseLongPath` |
| ShimCache | per-entry path field |
| BAM | value name under `State\UserSettings\<SID>` — the value name *is* the path |
| UserAssist | ROT13-encoded path in value name under `Count` subkey |
| Security-4688 | `NewProcessName` event field |
| Sysmon-1 | `Image` event field |
| SRUM | `AppId` (in some tables it's the path; others it's a SID-path compound) |

## Known quirks
- **Drive letter vs. device path.** Some artifacts capture `C:\...`, others capture `\Device\HarddiskVolume1\...`. Same file, two representations. Resolve via MountedDevices to normalize.
- **Case sensitivity.** Artifacts like Amcache deliberately lowercase (`LowerCaseLongPath`); others preserve case. Normalize for matching.
- **Truncation.** Security-4688 may truncate long command lines; check the audit policy for full-cmdline capture.
- **Symlinks and redirections** (SysWOW64 vs. System32) produce different paths for the same logical program on 32-vs-64-bit callers. Disambiguate via hash when available.
