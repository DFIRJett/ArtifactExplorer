---
name: SessionManager-Persistence
title-description: "Session Manager persistence values (BootExecute / Execute / SubSystems / SetupExecute / S0InitialCommand / WOWCommandLine)"
aliases:
- smss persistence
- BootExecute
- Session Manager native executables
link: persistence
tags:
- persistence-primary
- early-boot
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: NT3.1
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SYSTEM
  path: CurrentControlSet\Control\Session Manager
  addressing: hive+key-path
fields:
- name: boot-execute
  kind: path
  location: BootExecute value
  type: REG_MULTI_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "native-mode executables run by smss.exe at very early boot — before Win32 subsystem loads. Default on clean systems is just 'autocheck autochk *'. Any additional entries are persistence; commonly abused because they run before AV / EDR user-mode agents start."
- name: execute
  kind: path
  location: Execute value
  type: REG_MULTI_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "run by smss.exe slightly after BootExecute. Normally empty on clean systems. Non-empty = likely persistence."
- name: s0-initial-command
  kind: path
  location: S0InitialCommand value
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "the FIRST Win32 program smss.exe runs during Session 0 startup. Default wininit.exe on Vista+, csrss.exe on XP. Tampering here replaces the first Session 0 program — very high-confidence persistence signal."
- name: setup-execute
  kind: path
  location: SetupExecute value
  type: REG_MULTI_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "runs on the first boot after Windows Setup completes. Should be EMPTY on any post-setup system. Populated = either setup didn't finish cleanly or persistence injection."
- name: sub-systems
  kind: path
  location: SubSystems\Windows + \Optional + \Required values
  type: REG_SZ / REG_MULTI_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "environment subsystems loaded at boot. Default: csrss.exe for Windows, OS2/POSIX historically. Non-default additions = exotic subsystem persistence; rare but powerful because it runs in Session 0 privileged context."
- name: wow-command-line
  kind: path
  location: WOW\cmdline value
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "command line used to launch 16-bit Windows (WoW) processes. Rarely relevant on modern 64-bit Windows but leaves an historical persistence surface."
- name: key-last-write
  kind: timestamp
  location: Session Manager key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'Session Manager persistence values run during the earliest phases of
    boot — before Win32 subsystem / AV / EDR. BootExecute in particular
    runs in native-mode (only Nt* APIs available) and executes under the
    effective privilege of smss.exe (SYSTEM). This is one of the oldest
    persistence mechanisms in Windows and remains effective because it
    predates most endpoint security hooks.'
  qualifier-map:
    setting.registry-path: Session Manager\<value>
    setting.binary: field:boot-execute
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  survival-signals:
  - BootExecute contains anything other than 'autocheck autochk *' (plus 'autocheck autochk /k:<drive>' variants for scheduled chkdsk)
  - Execute non-empty = persistence
  - SetupExecute non-empty on a system whose setup completed weeks/months ago = tamper
  - S0InitialCommand != wininit.exe (Vista+) = replacement of the first Session 0 binary
provenance: [ms-session-manager-subsystem-smss-exe, carvey-2022-windows-forensic-analysis-tool, mitre-t1547]
---

# Session Manager persistence

## Forensic value
The Session Manager subkey (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`) hosts six values that can each run attacker-controlled code as SYSTEM during early boot:

| Value | When it fires | Default state |
|---|---|---|
| `BootExecute` | Native-mode, before Win32 subsystem loads | `autocheck autochk *` only |
| `Execute` | After BootExecute, still pre-user | empty |
| `S0InitialCommand` | First Session 0 program | `wininit.exe` (Vista+) |
| `SetupExecute` | First post-setup boot | empty on all normal systems |
| `SubSystems\Windows` / `Optional` / `Required` | Subsystem loaders | `csrss.exe` for `Windows` |
| `WOW\cmdline` | 16-bit WoW launches | default cmd.exe |

All six run before endpoint-detection agents start. Any non-default entry is a high-signal persistence finding.

## Concept reference
- ExecutablePath (each value → one or more executable paths)

## Triage
```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v BootExecute
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v Execute
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v S0InitialCommand
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SetupExecute
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems"
```
Clean-system baseline: BootExecute = `autocheck autochk *`, Execute empty, S0InitialCommand = `wininit.exe`, SetupExecute empty, SubSystems\Windows = the default csrss config string.
