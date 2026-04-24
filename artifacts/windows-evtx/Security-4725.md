---
name: Security-4725
title-description: "A user account was disabled"
aliases: [4725, account disabled]
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
  event-id: 4725
  provider: Microsoft-Windows-Security-Auditing
  addressing: evtx-record
fields:
- name: target-user-sid
  kind: identifier
  location: "EventData → TargetSid"
  encoding: SID
  references-data: [{concept: UserSID, role: targetUser}]
  note: "Account that was disabled. Pair with 4722 (enabled) for lifecycle. Attacker post-ops: disable legitimate admin accounts to force reactivation via their chosen channel."
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
  clock: system
  resolution: 1ms
observations:
- proposition: ACCOUNT_DISABLED
  ceiling: C3
  note: 'Pairs with 4722 (account enabled) for lifecycle audit. Attacker-disabled rival admin accounts = persistence / tamper pattern.'
  qualifier-map:
    actor.user: field:subject-user-sid
    object.user: field:target-user-sid
    time.start: field:event-time
provenance: [ms-event-4725]
---

# Security-4725 — Account Disabled
Pairs with 4722 (enabled). Alert on 4725 targeting admin accounts during incident windows.
