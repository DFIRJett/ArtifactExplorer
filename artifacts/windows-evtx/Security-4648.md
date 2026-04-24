---
name: Security-4648
title-description: "A logon was attempted using explicit credentials"
aliases:
- explicit credential logon
- runas event
- Security 4648
link: user
tags:
- timestamp-carrying
- tamper-hard
volatility: runtime
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  channel: Security
  event-id: 4648
fields:
- name: time-created
  kind: timestamp
  location: System\TimeCreated SystemTime
  encoding: iso8601-utc
  clock: system
  resolution: 1us
- name: subject-user-sid
  kind: identifier
  location: EventData\SubjectUserSid
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: actingUser
  note: the user account that initiated the runas/explicit-credential action
- name: subject-user-name
  kind: identifier
  location: EventData\SubjectUserName
  encoding: utf-16le
- name: subject-domain-name
  kind: identifier
  location: EventData\SubjectDomainName
  encoding: utf-16le
- name: subject-logon-id
  kind: identifier
  location: EventData\SubjectLogonId
  encoding: hex-uint64
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: logon ID of the CALLER's session (the session that supplied alternate credentials)
- name: logon-guid
  kind: identifier
  location: EventData\LogonGuid
  encoding: guid-string
  note: "Subject-side Kerberos correlation GUID. Often all-zero. When non-zero, joins 4648 to the caller's 4624 / 4769 for Kerberos lateral-movement reconstruction."
- name: target-user-name
  kind: identifier
  location: EventData\TargetUserName
  encoding: utf-16le
  note: the account whose credentials were supplied for the operation
- name: target-domain-name
  kind: identifier
  location: EventData\TargetDomainName
  encoding: utf-16le
- name: target-logon-guid
  kind: identifier
  location: EventData\TargetLogonGuid
  encoding: guid-string
  note: "Target-side Kerberos correlation GUID. On a successful 4648, pairs with the LogonGuid on the remote 4624 that completes the chain — the fingerprint that confirms 'this 4648 on host-A produced that 4624 on host-B.'"
- name: target-server-name
  kind: identifier
  location: EventData\TargetServerName
  encoding: utf-16le
  note: server/service the credentials were used against — 'localhost' for local runas
- name: target-info
  kind: identifier
  location: EventData\TargetInfo
  encoding: utf-16le
- name: process-id
  kind: identifier
  location: EventData\ProcessId
  encoding: hex-uint32
  references-data:
  - concept: ProcessId
    role: actingProcess
  note: PID of the process that issued the explicit-credential call (consent.exe, runas.exe, mstsc.exe, ...). Joins to Sysmon-1 / Security-4688 for full process context.
- name: process-name
  kind: path
  location: EventData\ProcessName
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: actingProcess
  note: the process that called the explicit-credential API — e.g., consent.exe (UAC), runas.exe, mstsc.exe
- name: ip-address
  kind: identifier
  location: EventData\IpAddress
  encoding: ip-address-string
  references-data:
  - concept: IPAddress
    role: authSourceIp
- name: ip-port
  kind: counter
  location: EventData\IpPort
  encoding: uint16
  note: "source port. 0 for local / interactive callers; non-zero for remote-origin explicit-credential calls (hunt signal)."
observations:
- proposition: AUTHENTICATED
  ceiling: C4
  note: 'Fires when credentials are EXPLICITLY supplied for an operation —

    UAC consent, runas, scheduled task creation requiring creds, mapped

    network drive with different creds, etc. Distinct from 4624 (passive

    authentication of the logon session itself).

    '
  qualifier-map:
    principal: field:target-user-name
    target: field:target-server-name
    method: explicit-credential
    source: field:ip-address
    time.start: field:time-created
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX checksums
  survival-signals:
  - sudden spike of 4648 events with varying TargetUserName = credential-stuffing or lateral-movement attempt
provenance:
  - ms-event-4648
  - uws-event-4648
  - jpcert-2017-lateral-movement-detection-v2
---

# Security Event 4648 — Explicit Credential Logon

## Forensic value
"A logon was attempted using explicit credentials." Fires whenever a process supplies credentials that differ from the caller's current session context:
- `runas` (user switching)
- UAC elevation
- Mapped network drive with different creds
- Scheduled task creation with stored credentials
- RDP to another host with explicit creds

Distinct from 4624 (which records the actual session establishment). 4648 captures the INTENT to use other credentials; 4624 captures the resulting session.

## Concept references
- UserSID (SubjectUserSid — who initiated)
- ExecutablePath (ProcessName — the runas/impersonation tool)
- IPAddress (when remote)

## Forensic lateral-movement pattern
Classic detection:
1. 4648 on host-A with TargetServerName=host-B and non-default target user
2. 4624 on host-B with IpAddress=host-A and the same target user
3. Subsequent activity on host-B under that user

This pattern is "Lateral Movement with Alternate Credentials" in ATT&CK (T1078).
