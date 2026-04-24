---
name: Security-4741
title-description: "A computer account was created"
aliases: [4741, computer account created, AD computer add]
link: system
tags: [ad-audit, account-lifecycle]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows-server: {min: '2008', max: '2022'}
  windows: {min: '7', max: '11'}
location:
  channel: Security
  event-id: 4741
  provider: Microsoft-Windows-Security-Auditing
  addressing: evtx-record
  note: "Fires on a DC when a computer account is created in AD. Paired with 4742 (changed) and 4743 (deleted). Attacker-relevant: creating a computer account allows MS-DS-MachineAccountQuota abuse (NTLM relay / Kerberos unconstrained delegation targets)."
fields:
- name: target-computer-sid
  kind: identifier
  location: "EventData → TargetSid"
  encoding: SID
  references-data: [{concept: UserSID, role: identitySubject}]
- name: target-computer-name
  kind: label
  location: "EventData → TargetUserName (ends with $)"
  encoding: utf-16le
  references-data: [{concept: MachineNetBIOS, role: trackerMachineId}]
- name: subject-user-sid
  kind: identifier
  location: "EventData → SubjectUserSid"
  encoding: SID
  references-data: [{concept: UserSID, role: actingUser}]
- name: subject-logon-id
  kind: identifier
  location: "EventData → SubjectLogonId"
  encoding: hex LUID
  references-data: [{concept: LogonSessionId, role: sessionContext}]
- name: event-time
  kind: timestamp
  location: "System/TimeCreated"
  encoding: xs:dateTime UTC
  clock: DC system
  resolution: 1ms
observations:
- proposition: ACCOUNT_CREATED
  ceiling: C3
  qualifier-map:
    actor.user: field:subject-user-sid
    object.user: field:target-computer-sid
    time.start: field:event-time
provenance: [ms-event-4741, ms-audit-computer-account-management, ms-kb5008102-samr-hardening-cve-2021-42278, ms-samr-user-account-codes, ms-kb-useraccountcontrol]
---

# Security-4741 — Computer Account Created
AD computer-account add. Alert on non-admin SubjectUserSid (default MachineAccountQuota=10 allows any authenticated user to create 10 computer accounts).
