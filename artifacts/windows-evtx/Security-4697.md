---
name: Security-4697
title-description: "A service was installed in the system"
aliases:
- Service installed (auditable)
- Service creation audit
link: persistence
tags:
- persistence-primary
- privilege-elevation
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows:
    min: '10'
    max: '11'
  windows-server:
    min: '2016'
    max: '2025'
location:
  channel: Security
  event-id: 4697
  provider: Microsoft-Windows-Security-Auditing
  log-file: "%WINDIR%\\System32\\winevt\\Logs\\Security.evtx"
fields:
- name: SubjectUserSid
  kind: identifier
  location: EventData → SubjectUserSid
  references-data:
  - concept: UserSID
    role: actingUser
- name: SubjectUserName
  kind: label
  location: EventData → SubjectUserName
- name: SubjectDomainName
  kind: label
  location: EventData → SubjectDomainName
- name: SubjectLogonId
  kind: identifier
  location: EventData → SubjectLogonId
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: logon ID of the installing session — joins to the originating 4624
- name: ServiceName
  kind: identifier
  location: EventData → ServiceName
  references-data:
  - concept: ServiceName
    role: installedService
- name: ServiceFileName
  kind: path
  location: EventData → ServiceFileName
  note: the ImagePath configured for the new service — raw string, often includes arguments
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
- name: ServiceType
  kind: flags
  location: EventData → ServiceType
  note: 0x10 = user-mode-own-process, 0x20 = share-process, 0x110 = interactive (rare outside legacy)
- name: ServiceStartType
  kind: flags
  location: EventData → ServiceStartType
  note: 2 = Automatic (start at boot), 3 = Manual, 4 = Disabled
- name: ServiceAccount
  kind: label
  location: EventData → ServiceAccount
  note: account the service runs as — LocalSystem, NetworkService, LocalService, or explicit
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: PERSISTED
  ceiling: C3
  note: Service install via ChangeServiceConfig/CreateService API. Pair with System-7045 for redundancy; 4697 requires SACL audit, 7045 is always emitted.
  qualifier-map:
    actor.user: field:SubjectUserName
    object.service.name: field:ServiceName
    object.service.executable: field:ServiceFileName
    time.created: field:TimeCreated
anti-forensic:
  write-privilege: service
  known-cleaners:
  - tool: wevtutil clear-log Security
    typically-removes: emits 1102
detection-priorities:
  - ServiceAccount = LocalSystem with ServiceFileName pointing to %TEMP%, %APPDATA%, or non-standard paths — high Cobalt Strike indicator
  - ServiceStartType = 2 (Automatic) on a hand-named service recently installed — reboot-persistence intent
  - Service installed by a non-admin SubjectUserSid followed by SeAssignPrimaryTokenPrivilege use — token-impersonation escalation path
provenance: [ms-event-4697, uws-event-4697]
---

# Security-4697

## Forensic value
Service-installation audit. Requires "Audit Security System Extension" subcategory enabled (part of System audit policy); on most default-config hosts this is NOT on, so 4697 may be silent. When 4697 is on, it's richer than System-7045 — carries the SubjectUserSid of the installer.

## Correlate with System-7045
- **Security-4697** — comes from LSA audit subsystem; requires audit policy; carries installer SID.
- **System-7045** — comes from SCM; emitted unconditionally; no installer SID.

When both fire for the same ServiceName within seconds of each other, you have the full picture (who did what). When only 7045 fires, you know the service was installed but not by whom — pivot to Security-4688 for process-creation context around the same timestamp.

## Cobalt Strike indicator
Cobalt Strike's `jump psexec` creates a service with a random-hex ServiceName and ImagePath pointing to `C:\Windows\<random>.exe`. Filter for:
- ServiceName matching `[0-9a-f]{7,8}` pattern
- ServiceFileName starting with `%%\windir%%` or raw `C:\Windows\` with a hex-random filename

## Practice hint
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697} |
  Select-Object TimeCreated,
    @{N='Service';E={$_.Properties[4].Value}},
    @{N='ImagePath';E={$_.Properties[5].Value}}
```
