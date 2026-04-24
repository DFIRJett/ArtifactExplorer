---
name: AppInit-DLLs
aliases:
- AppInit_DLLs
- load-on-every-process DLL injection
- legacy DLL persistence
link: persistence
tags: []
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: NT3.1
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SOFTWARE
  path: Microsoft\Windows NT\CurrentVersion\Windows
  addressing: hive+key-path
fields:
- name: appinit-dlls
  kind: path
  location: AppInit_DLLs value
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: space-separated list of DLLs; EVERY user32-loading process loads them
- name: load-appinit-dlls
  kind: flags
  location: LoadAppInit_DLLs value
  type: REG_DWORD
  note: 0 = disabled, 1 = enabled; must be 1 for AppInit_DLLs to actually load
- name: require-signed-appinit-dlls
  kind: flags
  location: RequireSignedAppInit_DLLs value (Win7+)
  type: REG_DWORD
  note: if 1, only Microsoft-signed DLLs load; default on Win8+ under Secure Boot
- name: key-last-write
  kind: timestamp
  location: Windows key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'Historical DLL-injection persistence. Any DLL in AppInit_DLLs is

    loaded into every user32.dll-linking process. Mitigated on Win8+ by

    the signature requirement but still occasionally seen in the wild,

    particularly on legacy / older-Win7 systems.

    '
  qualifier-map:
    setting.registry-path: Windows\AppInit_DLLs
    setting.dll-list: field:appinit-dlls
    setting.enabled: field:load-appinit-dlls
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: RequireSignedAppInit_DLLs setting (post-Win8) is a GUARDRAIL — but can be disabled by tampering
  survival-signals:
  - LoadAppInit_DLLs=1 on modern Windows with non-Microsoft DLL paths = classic persistence attack
  - RequireSignedAppInit_DLLs=0 on Win8+ = guardrail disabled, likely intentional
provenance:
  - mitre-t1546
  - mitre-t1546-010
  - online-2021-registry-hive-file-format-prim
---

# AppInit_DLLs

## Forensic value
Legacy DLL-injection persistence. Any DLL listed in AppInit_DLLs gets loaded into every user-mode process that links against user32.dll — a universal inject mechanism. Heavily abused in the XP/Vista era; Microsoft mitigated with signature requirements on Win8+ but the key still exists.

For pre-Win8 forensics or older corporate images: check AppInit_DLLs FIRST for any persistence investigation. On modern Windows, mostly idle but still worth verifying it's not being tampered as part of a broader weakening of security controls.

## Concept reference
- ExecutablePath (dll list)

## Quick triage
```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /v LoadAppInit_DLLs /v RequireSignedAppInit_DLLs
```
- `AppInit_DLLs` should be empty on clean systems
- `LoadAppInit_DLLs` should be 0 on clean systems
- `RequireSignedAppInit_DLLs` should be 1 on clean Win8+ systems
