---
name: Security-4719
title-description: "System audit policy was changed"
aliases: [4719, audit policy change, SACL change]
link: persistence
link-secondary: system
tags: [audit-tamper, anti-forensics]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: {min: '7', max: '11'}
  windows-server: {min: '2008R2', max: '2022'}
location:
  channel: Security
  event-id: 4719
  provider: Microsoft-Windows-Security-Auditing
  addressing: evtx-record
  note: "Fires when the system audit policy (per-subcategory Success/Failure enable) is changed. Critical anti-forensic signal: attacker disabling subcategories like 'Audit Process Creation' or 'Audit Kerberos Operations' before performing noisy actions. Subcategory: 'Audit Policy Change' (ON by default)."
fields:
- name: subcategory-guid
  kind: identifier
  location: "EventData → SubcategoryGuid"
  encoding: guid-string
  note: "GUID of the audit subcategory being changed. Well-known values: {0CCE922B} = Process Creation, {0CCE9211} = Logon, {0CCE9226} = Kerberos Authentication Service, {0CCE9216} = File System. Disabling these = classic pre-attack tamper."
- name: audit-change
  kind: content
  location: "EventData — AuditPolicyChanges"
  encoding: "Success/Failure add/remove flags"
  note: "String describing the change. '%%8452 %%8448' = Success audit added + Failure audit added. '%%8449' = Success removed (audit disabled). Flip from enabled → disabled is the attacker pattern."
- name: subject-user-sid
  kind: identifier
  location: "EventData → SubjectUserSid"
  encoding: SID
  references-data: [{concept: UserSID, role: actingUser}]
  note: "Account that changed the policy. SYSTEM = automatic policy refresh from GPO. User SID = direct tamper."
- name: subject-logon-id
  kind: identifier
  location: "EventData → SubjectLogonId"
  encoding: hex LUID
  references-data: [{concept: LogonSessionId, role: sessionContext}]
- name: event-time
  kind: timestamp
  location: "System/TimeCreated"
  encoding: xs:dateTime UTC
  clock: system
  resolution: 1ms
observations:
- proposition: AUDIT_TAMPERED
  ceiling: C4
  note: '4719 itself cannot be prevented by disabling — the Audit Policy Change subcategory is hard-coded on. So even an attacker flipping audit off LEAVES 4719 as the signal. Detection: any 4719 where the change REMOVES Success or Failure auditing on security-critical subcategories (Process Creation, Logon, Kerberos, File System) with a non-SYSTEM SubjectUserSid = tamper.'
  qualifier-map:
    actor.user: field:subject-user-sid
    time.start: field:event-time
provenance: [ms-event-4719, mitre-t1562-002]
---

# Security-4719 — Audit Policy Change (Tamper Indicator)

The self-protecting audit event — cannot be suppressed by disabling subcategories. Any 4719 disabling Process Creation / Logon / Kerberos / File System with a non-SYSTEM actor = deliberate tamper prep.
