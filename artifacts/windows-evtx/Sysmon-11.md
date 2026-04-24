---
name: Sysmon-11
title-description: "FileCreate"
aliases:
- Sysmon FileCreate
- file creation event
link: file
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
  event-id: 11
fields:
- name: rule-name
  kind: label
  location: EventData\RuleName
  encoding: utf-16le
  note: Matching config rule name. FileCreate is high-volume; named rules drive scoped alerts (drop-to-temp, executable-in-user-dir, etc.).
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
  note: the process that created the file
- name: target-filename
  kind: path
  location: EventData\TargetFilename
  encoding: utf-16le
- name: creation-utc-time
  kind: timestamp
  location: EventData\CreationUtcTime
  encoding: iso8601-utc
  clock: system
  resolution: 1ms
  note: NTFS $SI.created timestamp for the new file — same as kernel-timestamped creation
- name: user
  kind: identifier
  location: EventData\User
  encoding: '''DOMAIN\username'''
observations:
- proposition: CREATED
  ceiling: C4
  note: 'File creation event attributed to specific process. Canonical source

    for ''which process wrote this file'' questions. Fires on actual

    filesystem create — doesn''t fire on pure metadata updates.

    '
  qualifier-map:
    object.path: field:target-filename
    actor.process: field:image
    actor.user: field:user
    time.start: field:creation-utc-time
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX checksums
provenance:
  - ms-sysmon-system-monitor
  - hartong-2024-sysmon-modular-11-file-create
  - sans-2022-the-importance-of-sysmon-event
---

# Sysmon Event 11 — FileCreate

## Forensic value
Canonical "process X created file Y at time T" event. Fires on filesystem-level file creation with process attribution. Crucial for tracking malware staging, dropper behavior, data collection pre-exfil.

## Concept reference
- ExecutablePath (image — the creating process)

## Known quirks
- **Default Sysmon configs filter aggressively.** File creation is high-volume; configs limit to suspicious paths (Temp, AppData, user directories).
- **FileCreate vs FileCreateStreamHash.** Event 11 is pure creation; event 15 (FileCreateStreamHash) is the hash-on-create variant for specific files.
- **ADS creation** fires separate FileCreate events for the primary file and each stream.

## Practice hint
With Sysmon running and default-config FileCreate rules, download a file from a browser. Observe the event 11 from the browser process creating the target-filename. The `creation-utc-time` should match the $SI-created timestamp in $MFT.
