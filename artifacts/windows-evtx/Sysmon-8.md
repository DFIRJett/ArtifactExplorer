---
name: Sysmon-8
title-description: "CreateRemoteThread detected"
aliases:
- Sysmon CreateRemoteThread
- injection primitive
link: security
tags:
- injection
- lateral-movement
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Sysmon/Operational
platform:
  windows:
    min: '7'
    max: '11'
    note: requires Sysinternals Sysmon installed and configured to emit event 8
location:
  channel: Microsoft-Windows-Sysmon/Operational
  event-id: 8
  provider: Microsoft-Windows-Sysmon
  log-file: "%WINDIR%\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx"
fields:
- name: RuleName
  kind: label
  location: EventData → RuleName
  note: Matching config rule name. Event 8 benefits from named rules because discriminating benign sources (AV, debuggers) from suspicious ones is rule-driven.
- name: SourceProcessGuid
  kind: identifier
  location: EventData → SourceProcessGuid
  note: Sysmon-assigned process GUID; joins with Sysmon-1 ProcessGuid field
- name: SourceProcessId
  kind: identifier
  location: EventData → SourceProcessId
  references-data:
  - concept: ProcessId
    role: actingProcess
- name: SourceImage
  kind: path
  location: EventData → SourceImage
  note: process creating the remote thread
  references-data:
  - concept: ExecutablePath
    role: actingProcess
- name: TargetProcessGuid
  kind: identifier
  location: EventData → TargetProcessGuid
- name: TargetProcessId
  kind: identifier
  location: EventData → TargetProcessId
  references-data:
  - concept: ProcessId
    role: targetProcess
- name: TargetImage
  kind: path
  location: EventData → TargetImage
  note: process receiving the remote thread — commonly lsass.exe, explorer.exe, or a legitimate binary being hollowed
  references-data:
  - concept: ExecutablePath
    role: actingProcess
- name: NewThreadId
  kind: identifier
  location: EventData → NewThreadId
- name: StartAddress
  kind: address
  location: EventData → StartAddress
  note: virtual address where the new thread begins execution — if outside the target's loaded modules, strong injection signal
- name: StartModule
  kind: path
  location: EventData → StartModule
  note: module owning StartAddress (blank if into allocated heap — SUSPICIOUS)
- name: StartFunction
  kind: label
  location: EventData → StartFunction
  note: exported symbol at StartAddress (blank if into raw allocated memory — SUSPICIOUS)
- name: SourceUser
  kind: identifier
  location: EventData → SourceUser
  encoding: "'DOMAIN\\username'"
  note: User context of the source process (Sysmon 13+). Split source/target identities expose cross-user injection attempts.
- name: TargetUser
  kind: identifier
  location: EventData → TargetUser
  encoding: "'DOMAIN\\username'"
  note: User context of the target process (Sysmon 13+). TargetUser != SourceUser is often a strong signal (e.g., a user-mode process injecting into a SYSTEM service).
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 100ns
observations:
- proposition: INJECTED
  ceiling: C3
  note: CreateRemoteThread cross-process. A high-confidence injection signal; benign sources exist (AV, debuggers) but should be a short list.
  qualifier-map:
    actor.process: field:SourceImage
    target.process: field:TargetImage
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - tool: Sysmon config rule exclude
    typically-removes: prevents future emission
detection-priorities:
  - StartModule blank AND StartFunction blank — thread starts in raw allocated memory (classic shellcode injection)
  - TargetImage = lsass.exe from SourceImage ≠ legitimate AV — credential-theft attempt
  - SourceImage in %TEMP% or %APPDATA% targeting a legitimate system process — hollowing
provenance: [ms-sysmon-system-monitor, hartong-2024-sysmon-modular-8-create-remote, uws-event-90008]
---

# Sysmon-8 (CreateRemoteThread)

## Forensic value
Sysmon hooks `NtCreateThreadEx` / `NtCreateThread` kernel APIs and emits event 8 when any process creates a thread in a DIFFERENT process. This is the canonical signal for **process injection**.

The event discriminates "process injecting into itself" (trivial, unlogged) from "process starting execution inside another process" (injection primitive).

## Benign source allowlist
Normal environments have a short list of legitimate CreateRemoteThread sources:
- CSRSS (process init)
- Some AV/EDR console agents
- Legitimate debuggers attaching

Anything outside that allowlist with `TargetImage = lsass.exe` or a system binary is high-priority investigation.

## StartModule / StartFunction heuristic
The richest discriminator:
- **Populated StartModule + StartFunction** → thread starts in a loaded DLL's exported function (often legitimate RPC / message-pump work, or LoadLibrary-based injection — still suspicious but less severe)
- **Blank StartModule + blank StartFunction** → thread starts in raw allocated virtual memory. No loaded module owns that address. This is **shellcode** or a manually-mapped PE. High-confidence malicious.

## Correlation
- **Sysmon-10** (ProcessAccess) with OpenProcess rights 0x1FFF or PROCESS_VM_WRITE typically precedes the 8 by milliseconds — the inject-and-launch sequence
- **Sysmon-7** (ImageLoad) in the target process may follow if the injection pulls in a DLL
- **Sysmon-3** from the target process post-injection if the injected code opens network connections (C2)

## Practice hint
In a training VM with Sysmon + SwiftOnSecurity config:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=8} -MaxEvents 50 |
  Where-Object { $_.Properties[8].Value -eq "" -and $_.Properties[9].Value -eq "" } |
  Format-Table TimeCreated, @{N='Src';E={$_.Properties[4].Value}}, @{N='Tgt';E={$_.Properties[6].Value}}
```
Filter isolates blank StartModule/StartFunction cases — shellcode-injection candidates.
