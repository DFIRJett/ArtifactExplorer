---
name: System-7045
title-description: "A service was installed in the system"
aliases:
- Service installed (SCM)
- New service installation
link: persistence
tags:
- persistence-primary
- tamper-hard
- always-emitted
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: System
platform:
  windows:
    min: XP
    max: '11'
location:
  channel: System
  event-id: 7045
  provider: Service Control Manager
  log-file: "%WINDIR%\\System32\\winevt\\Logs\\System.evtx"
fields:
- name: ServiceName
  kind: identifier
  location: EventData → ServiceName
  references-data:
  - concept: ServiceName
    role: installedService
- name: ImagePath
  kind: path
  location: EventData → ImagePath
  note: raw binary-plus-args as configured; may include service-host host PID or DLL path for svchost-style services
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
- name: ServiceType
  kind: flags
  location: EventData → ServiceType
- name: StartType
  kind: flags
  location: EventData → StartType
  note: auto-start | demand-start | system | boot | disabled
- name: AccountName
  kind: label
  location: EventData → AccountName
  note: service account (LocalSystem, NetworkService, etc., or explicit SID/name)
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: PERSISTED
  ceiling: C4
  note: Service-installed audit from the Service Control Manager. Emitted unconditionally — no audit policy dependency. Highest-confidence service-persistence evidence.
  qualifier-map:
    object.service.name: field:ServiceName
    object.service.executable: field:ImagePath
    time.created: field:TimeCreated
anti-forensic:
  write-privilege: service
  known-cleaners:
  - tool: wevtutil clear-log System
    typically-removes: emits 104 event
detection-priorities:
  - ImagePath in %TEMP%, %APPDATA%, or with random-hex filename — classic lateral-movement service drop
  - StartType = 2 (auto) on a one-off hand-named service — reboot-survivability intent
  - Cluster of 7045 events with staggered timing across hosts — lateral movement sequence
provenance:
  - ms-scm-events
  - mitre-t1543
  - mitre-t1543-003
---

# System-7045

## Forensic value
The **always-on** service-installation audit. Comes from the SCM (Service Control Manager) itself, not the LSA audit subsystem, so it does NOT require Security-audit policy to be enabled. If a service was installed on Windows, System-7045 fired.

Compare:
- **Security-4697** — audit-policy dependent; carries installer SID; silent when audit off
- **System-7045** — unconditional; no installer SID

Investigators default to 7045 because it's reliable. When both present, 4697 adds the "who" via SubjectUserSid.

## What it catches
Any `ChangeServiceConfig` / `CreateService` API call succeeds → SCM emits 7045. This includes:
- Legitimate installer-driven service creation (most of 7045 traffic)
- `sc create` from command line
- PsExec / remote-service-install tools (PsExec creates PSEXESVC temporarily)
- Cobalt Strike `jump psexec` variants
- Ransomware deployment via service-wrapped droppers

## Context artifacts
- **Prefetch** for the ImagePath confirms the service actually ran
- **Security-4688** process creation for the service, if audit enabled
- **Security-4672** privileges assigned if the service started under LocalSystem

## Lateral movement signature
PSEXESVC service installation is the PsExec signature:
```
ServiceName: PSEXESVC
ImagePath: C:\Windows\PSEXESVC.exe
StartType: 3 (Demand)
AccountName: LocalSystem
```
Variants with renamed binaries (`svchos.exe`, random hex) retain the service-install pattern.

## Practice hint
For historical review on a host with suspected persistence:
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Select-Object TimeCreated,
    @{N='Service';E={$_.Properties[0].Value}},
    @{N='ImagePath';E={$_.Properties[1].Value}},
    @{N='StartType';E={$_.Properties[3].Value}}
```
