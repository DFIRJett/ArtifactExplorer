---
name: Security-4704
title-description: "A user right was assigned"
aliases: [4704, right assigned, user rights]
link: user
link-secondary: persistence
tags: [privilege-grant, persistence-primary]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: {min: '7', max: '11'}
  windows-server: {min: '2008R2', max: '2022'}
location:
  channel: Security
  event-id: 4704
  provider: Microsoft-Windows-Security-Auditing
  addressing: evtx-record
  note: "Fires when a user right (privilege) is granted to an account — typically via Local Security Policy / GPO / secedit. Pairs with 4705 (user right REMOVED). Subcategory: 'Audit Authorization Policy Change'. Logs the specific privilege name and target SID."
fields:
- name: target-user-sid
  kind: identifier
  location: "EventData → TargetSid"
  encoding: SID
  references-data: [{concept: UserSID, role: targetUser}]
  note: "Account receiving the new right. Attacker-useful grants: SeDebugPrivilege (debug processes — credential dump), SeTakeOwnershipPrivilege (overwrite ACLs), SeBackupPrivilege (bypass NTFS ACLs — read any file), SeLoadDriverPrivilege (load unsigned driver)."
- name: privilege-list
  kind: label
  location: "EventData → PrivilegeList"
  encoding: "whitespace-separated privilege-name list"
  note: "Privileges granted. Alert on grants of SeDebug, SeBackup, SeTakeOwnership, SeLoadDriver, SeTrustedCredManAccess, SeImpersonatePrivilege to non-admin accounts. The privilege name is the definitive field — cross-reference against organizational allow-list."
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
- proposition: PRIVILEGE_GRANTED
  ceiling: C3
  note: 'Privilege-escalation persistence — attacker grants themselves (or a controlled account) SeDebug / SeBackup / SeLoadDriver so that future logons gain the privilege without re-elevation. Pair with Security-4672 (special privileges assigned at logon) to confirm the grant took effect on subsequent sessions.'
  qualifier-map:
    actor.user: field:subject-user-sid
    object.user: field:target-user-sid
    time.start: field:event-time
provenance: [ms-event-4704]
---

# Security-4704 — User Right Assigned

Privilege-grant persistence. Pairs with 4705 (removed) for lifecycle tracking. Watch for: SeDebug / SeBackup / SeTakeOwnership / SeLoadDriver granted to non-admin accounts or to attacker-controlled service accounts.
