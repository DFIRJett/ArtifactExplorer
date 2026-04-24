---
name: Sysmon-13
title-description: "RegistryEvent (Value Set)"
aliases:
- Sysmon RegistryEvent SetValue
- Sysmon registry value write
link: persistence
tags:
- timestamp-carrying
- tamper-hard
volatility: runtime
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Sysmon/Operational
platform:
  windows:
    min: '7'
    max: '11'
    note: Sysmon required
location:
  channel: Microsoft-Windows-Sysmon/Operational
  event-id: 13
fields:
- name: rule-name
  kind: label
  location: EventData\RuleName
  encoding: utf-16le
  note: Matching config rule name. Persistence-oriented rules typically carry named identifiers (e.g. 'RunKey', 'Service-ImagePath') so SIEM queries can alert by mechanism.
- name: utc-time
  kind: timestamp
  location: EventData\UtcTime
  encoding: iso8601-utc
  clock: system
  resolution: 1ms
- name: process-guid
  kind: identifier
  location: EventData\ProcessGuid
  encoding: guid-string
- name: process-id
  kind: identifier
  location: EventData\ProcessId
  encoding: uint32
  references-data:
  - concept: ProcessId
    role: actingProcess
- name: image
  kind: path
  location: EventData\Image
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: actingProcess
- name: event-type
  kind: enum
  location: EventData\EventType
  encoding: '''SetValue'''
- name: target-object
  kind: path
  location: EventData\TargetObject
  encoding: utf-16le
  note: full registry path being modified — 'HKLM\...\Run\<name>' etc.
- name: details
  kind: identifier
  location: EventData\Details
  encoding: utf-16le
  note: value data written; may be truncated for large REG_BINARY
- name: user
  kind: identifier
  location: EventData\User
  encoding: '''DOMAIN\username'''
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'Registry SetValue event with process + user attribution. Direct

    evidence of *when* a specific registry value was modified and

    *by which process*. For persistence-mechanism tampering (Run keys,

    Services ImagePath, etc.), this is the authoritative detection event.

    '
  qualifier-map:
    setting: field:target-object
    value: field:details
    actor.process: field:image
    actor.user: field:user
    time.start: field:utc-time
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX checksums
provenance: [ms-sysmon-system-monitor, hartong-2024-sysmon-modular-13-registry-eve, uws-event-90013]
---

# Sysmon Event 13 — Registry SetValue

## Forensic value
Per-process registry value write with full target path + value data. For persistence-oriented attacker techniques (modifying Run keys, Services, Image File Execution Options, WMI subscriptions via registry), Sysmon 13 captures the exact moment of modification attributed to the actor process.

## Concept reference
- ExecutablePath (image — the process doing the modification)

## Known quirks
- **High volume on active systems.** Default Sysmon configs filter heavily to focus on persistence-relevant paths. SwiftOnSecurity's config is a good reference.
- **Details field truncation.** Long REG_BINARY writes are truncated; use event 12 (CreateKey/DeleteKey) + registry snapshots for full data.
- **Three registry-event IDs:** 12 (Create/Delete Key), 13 (SetValue), 14 (RenameKey). Different forensic semantics.

## Practice hint
Add a Run-key entry manually via `reg add HKCU\...\Run /v test /d "notepad.exe"`. Observe Sysmon event 13 with image=reg.exe (or the ultimate parent, PowerShell) and target-object matching the Run-key path. Then remove; observe the DeleteValue variant.
