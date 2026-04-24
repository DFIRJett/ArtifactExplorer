---
name: AppLocker-8004
title-description: "File was allowed to run (audit) / File was not allowed to run (enforce)"
aliases: [AppLocker execution blocked]
link: security
tags: [detection, audit-dependent]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-AppLocker/EXE and DLL
platform:
  windows: {min: '7', max: '11'}
location:
  channel: Microsoft-Windows-AppLocker/EXE and DLL
  event-id: 8004
  provider: Microsoft-Windows-AppLocker
fields:
- name: UserSid
  kind: identifier
  location: EventData → UserSid
  references-data:
  - {concept: UserSID, role: actingUser}
- name: FullFilePath
  kind: path
  location: EventData → FullFilePath
  references-data:
  - {concept: ExecutablePath, role: scannedTarget}
- name: FileHash
  kind: hash
  location: EventData → FileHash
  references-data:
  - {concept: ExecutableHash, role: scannedHash}
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: EXECUTION_BLOCKED
  ceiling: C3
  note: "AppLocker policy blocked an execution attempt. Direct evidence that SOMEONE tried to run the binary AND AppLocker was active."
  qualifier-map:
    actor.user.sid: field:UserSid
    object.file.path: field:FullFilePath
    object.file.hash: field:FileHash
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance:
  - ms-applocker-policy-storage-and-enforc
---

# AppLocker-8004

## Forensic value
AppLocker-blocked execution attempt. Pair with the broader AppLocker channels (EXE and DLL, MSI and Script, Packaged app) to see the full block history. Every 8004 is a deliberate-run-attempt by a user or process.

## Cross-references
- **Security-4688** / **Sysmon-1** — process-creation attempts that would be blocked
- **CodeIntegrity-3077** — kernel-level block (WDAC / HVCI)
- **Defender-1116** — sometimes paired when Defender also detected the binary
