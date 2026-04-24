---
name: System-7036
title-description: "A service entered the running / stopped state"
aliases:
- Service state change
- Service running / stopped
link: persistence
tags:
- service-lifecycle
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
  event-id: 7036
  provider: Service Control Manager
fields:
- name: ServiceName
  kind: identifier
  location: EventData → param1
  references-data:
  - concept: ServiceName
    role: stateChangeTarget
- name: StateText
  kind: status
  location: EventData → param2
  note: localized string — 'running' | 'stopped' | ...
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: SERVICE_STATE_CHANGED
  ceiling: C3
  note: "Service state transitions. Very high-volume event (every auto-start service at boot emits two 7036s) — value comes from correlating unexpected state changes with threat timeline."
  qualifier-map:
    object.service.name: field:ServiceName
    object.service.state: field:StateText
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: service
detection-priorities:
  - "rapid stop→start of a security service (Windows Defender, AV, audit service) — tampering indicator"
  - "service running state outside normal hours for that service"
provenance:
  - ms-scm-events
---

# System-7036

## Forensic value
Every service start and stop on the system. Noisy by default — useful when correlated against an attack timeline or against a specific ServiceName of interest. Pair with System-7045 (service install) and Security-4697 (audited service install) to reconstruct full service lifecycle.

## Join-key use
ServiceName links to the Services registry artifact and to System-7045. When a state change fires shortly after install, the sequence is "installed at T1 → started at T2" — confirming the new service not only got created but actually ran. Joining on ServiceName across Services + System-7045 + System-7036 reveals the full lifecycle.
