---
name: Security-4781
title-description: "The name of an account was changed"
aliases: [4781, account renamed, SAM rename]
link: user
tags: [account-lifecycle, ad-audit]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: {min: '7', max: '11'}
  windows-server: {min: '2008R2', max: '2022'}
location:
  channel: Security
  event-id: 4781
  provider: Microsoft-Windows-Security-Auditing
  addressing: evtx-record
fields:
- name: target-user-sid
  kind: identifier
  location: "EventData → TargetSid"
  encoding: SID
  references-data: [{concept: UserSID, role: identitySubject}]
  note: "SID of the renamed account — PERSISTENT across the rename (SID doesn't change). Cross-reference with both old and new SAM name."
- name: old-name
  kind: label
  location: "EventData → OldTargetUserName"
  encoding: utf-16le
- name: new-name
  kind: label
  location: "EventData → NewTargetUserName"
  encoding: utf-16le
  note: "Attacker pattern: rename an existing account to masquerade as a different user. The SID stays — so SID-based audit trails still trace the original account."
- name: subject-user-sid
  kind: identifier
  location: "EventData → SubjectUserSid"
  encoding: SID
  references-data: [{concept: UserSID, role: actingUser}]
- name: event-time
  kind: timestamp
  location: "System/TimeCreated"
  encoding: xs:dateTime UTC
  clock: system
  resolution: 1ms
observations:
- proposition: ACCOUNT_MODIFIED
  ceiling: C3
  note: 'Rename-for-impersonation detection. Since the SID is persistent, downstream auth audits still reflect the original identity even after the rename.'
  qualifier-map:
    actor.user: field:subject-user-sid
    object.user: field:target-user-sid
    time.start: field:event-time
provenance: [ms-event-4781, ms-audit-user-account-management, velazco-2021-hunting-samaccountname-spoofing]
---

# Security-4781 — Account Rename
SID stays; SAM name changes. Use TargetSid for timeline continuity across the rename.
