---
name: Sysmon-10
title-description: "ProcessAccess"
aliases:
- Sysmon ProcessAccess
- LSASS read detection
link: security
tags:
- credential-access
- injection
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Sysmon/Operational
platform:
  windows:
    min: '7'
    max: '11'
    note: requires Sysmon installed + event 10 configured (noisy without rules)
location:
  channel: Microsoft-Windows-Sysmon/Operational
  event-id: 10
  provider: Microsoft-Windows-Sysmon
  log-file: "%WINDIR%\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx"
fields:
- name: RuleName
  kind: label
  location: EventData → RuleName
  note: Matching config rule name. Event 10 is very noisy — named rules are the only sane way to run SIEM alerting on it.
- name: SourceProcessGUID
  kind: identifier
  location: EventData → SourceProcessGUID
- name: SourceProcessId
  kind: identifier
  location: EventData → SourceProcessId
  references-data:
  - concept: ProcessId
    role: actingProcess
- name: SourceThreadId
  kind: identifier
  location: EventData → SourceThreadId
  encoding: uint32
  note: TID of the thread in the source process that called OpenProcess. Useful for correlating with Sysmon-8 NewThreadId (the thread created post-access) during inject-then-run sequences.
- name: SourceImage
  kind: path
  location: EventData → SourceImage
  references-data:
  - concept: ExecutablePath
    role: actingProcess
- name: TargetProcessGUID
  kind: identifier
  location: EventData → TargetProcessGUID
- name: TargetProcessId
  kind: identifier
  location: EventData → TargetProcessId
  references-data:
  - concept: ProcessId
    role: targetProcess
  note: "PID of the process being OpenProcess'd. Join to Sysmon-1.process-id for the target's image+parent+command-line lineage."
- name: TargetImage
  kind: path
  location: EventData → TargetImage
  note: typically lsass.exe in credential-access cases
  references-data:
  - concept: ExecutablePath
    role: actingProcess
- name: GrantedAccess
  kind: flags
  location: EventData → GrantedAccess
  note: hex bitmask of PROCESS_* access rights granted via OpenProcess. Key values — 0x1010 and 0x1410 are the PROCESS_VM_READ + PROCESS_QUERY_INFORMATION patterns used by credential-dump tools
- name: CallTrace
  kind: stacktrace
  location: EventData → CallTrace
  type: caller-stack-string
  note: module+offset stack of the OpenProcess call; CRITICAL for attribution because the calling module often identifies the tool
- name: SourceUser
  kind: identifier
  location: EventData → SourceUser
  encoding: "'DOMAIN\\username'"
  note: User context of the process calling OpenProcess (Sysmon 13+).
- name: TargetUser
  kind: identifier
  location: EventData → TargetUser
  encoding: "'DOMAIN\\username'"
  note: User context of the target process (Sysmon 13+). TargetUser != SourceUser is frequently a privilege-boundary crossing signal.
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 100ns
observations:
- proposition: CREDENTIAL_ACCESS_ATTEMPT
  ceiling: C3
  note: Cross-process OpenProcess with memory-read rights against lsass.exe is the gold-standard credential-dump signal.
  qualifier-map:
    actor.process: field:SourceImage
    target.process: field:TargetImage
    object.access.mask: field:GrantedAccess
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - tool: Sysmon config exclude
    typically-removes: future events only
detection-priorities:
  - TargetImage=lsass.exe AND GrantedAccess in (0x1010, 0x1410, 0x1FFF) AND SourceImage not in AV/EDR allowlist — mimikatz / procdump / comsvcs.dll / direct-syscall dumper
  - CallTrace containing UNKNOWN(...) offsets — indirect-syscall/direct-syscall evasion
  - CallTrace containing dbghelp.dll!MiniDumpWriteDump — procdump-family credential dump
provenance:
  - ms-sysmon-system-monitor
  - hartong-2024-sysmon-modular-10-process-acce
  - specterops-2021-understanding-and-defending-ag
---

# Sysmon-10 (ProcessAccess)

## Forensic value
Logged when one process calls `OpenProcess` against another with specific access rights. The richest signal in Sysmon for **credential theft** (LSASS reads) and **injection precursors** (write/create-thread rights).

Noisy by default — every benign process-list query generates 10. Production Sysmon configs (SwiftOnSecurity, Olaf Hartong) filter aggressively; an effective config whitelists legitimate query patterns and emits 10 only for high-interest access masks against high-value targets.

## Access mask interpretation
Windows `PROCESS_*` access rights bit-encoded:
- `0x0010` PROCESS_VM_READ
- `0x0008` PROCESS_VM_WRITE  (with 0x0020 PROCESS_VM_OPERATION = injection primitive)
- `0x0002` PROCESS_CREATE_THREAD
- `0x0040` PROCESS_DUP_HANDLE
- `0x0400` PROCESS_QUERY_INFORMATION
- `0x1000` PROCESS_QUERY_LIMITED_INFORMATION

Combined masks seen in the wild:
- **0x1010** = QUERY_INFO + VM_READ → `mimikatz sekurlsa::logonpasswords` classic pattern
- **0x1410** = + 0x400 QUERY_INFORMATION → older Win7 LSASS read pattern
- **0x1FFF** = PROCESS_ALL_ACCESS → heavy-handed; any tool requesting this on lsass is suspicious

## CallTrace is the tell
The CallTrace field is the highest-value sub-field. It records the caller-stack at OpenProcess time, e.g.:
```
C:\Windows\SYSTEM32\ntdll.dll+9e924|C:\Windows\System32\KERNELBASE.dll+24d47|C:\tools\mimikatz.exe+4521c
```
The last frame is the calling module. Benign AV paths are a short list; anything else warrants pivot to that process's Sysmon-1.

**Evasion signal:** CallTrace entries of `UNKNOWN(0x...)` indicate direct-syscall or indirect-syscall invocation — the caller bypassed ntdll's exported Zw* stubs to evade userland hooks. This is a deliberate evasion tactic.

## Practice hint
Focused LSASS-read hunt:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} |
  Where-Object { ($_.Properties[6].Value) -like '*lsass.exe' } |
  Select-Object TimeCreated,
    @{N='Src';E={$_.Properties[4].Value}},
    @{N='Mask';E={$_.Properties[7].Value}},
    @{N='CallTrace';E={$_.Properties[8].Value}}
```
