---
name: Security-4728
title-description: "A member was added to a security-enabled global group"
aliases:
- 4728
- Global group member added
link: user
link-secondary: persistence
tags:
- privilege-accumulation
- ad-audit
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows-server:
    min: '2008R2'
    max: '2022'
  windows:
    min: '7'
    max: '11'
location:
  channel: Security
  event-id: 4728
  provider: "Microsoft-Windows-Security-Auditing"
  addressing: evtx-record
  note: "Fires on a Domain Controller when a member is added to a domain GLOBAL security group. Companion to Security-4729 (removed from global group), Security-4732 (added to local group), Security-4756 (added to universal group). Domain-admin-scope visibility — this is the core event for enterprise group-change auditing. Subcategory: 'Audit Security Group Management'."
fields:
- name: member-sid
  kind: identifier
  location: "EventData → MemberSid"
  encoding: SID
  references-data:
  - concept: UserSID
    role: identitySubject
  note: "SID of the account added. NTDS-dit lookup resolves to current account attributes + cross-reference against Security-4738 for any simultaneous attribute changes."
- name: member-dn
  kind: label
  location: "EventData → MemberName"
  encoding: distinguished-name
  note: "Full AD DN of the added member. For users: 'CN=...,OU=...,DC=...'. For other groups (nested group-in-group adds): same format for the group DN."
- name: target-group-sid
  kind: identifier
  location: "EventData → TargetSid"
  encoding: SID
  note: "SID of the GLOBAL group the member was added to. High-privilege global SIDs to alert on: S-1-5-21-<domain>-512 (Domain Admins), -516 (Domain Controllers), -519 (Enterprise Admins), -518 (Schema Admins)."
- name: target-group-name
  kind: label
  location: "EventData → TargetUserName + TargetDomainName"
  encoding: utf-16le
  note: "Group sAMAccountName. 'Domain Admins' / 'Enterprise Admins' / application-specific privileged groups."
- name: subject-user-sid
  kind: identifier
  location: "EventData → SubjectUserSid"
  encoding: SID
  references-data:
  - concept: UserSID
    role: actingUser
  note: "Account that made the add. Privileged-group-add actor tracking."
- name: subject-logon-id
  kind: identifier
  location: "EventData → SubjectLogonId"
  encoding: hex LUID
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: "Session LUID of the acting admin. Threads to Security-4624 for full session context."
- name: event-time
  kind: timestamp
  location: "System/TimeCreated"
  encoding: xs:dateTime UTC
  clock: DC system
  resolution: 1ms
  note: "Group-add moment. For forensic timeline + insider / mover investigations."
observations:
- proposition: PRIVILEGE_GRANTED
  ceiling: C3
  note: 'Security-4728 is the domain-wide privilege-change audit event
    for global security group adds. Domain Admins / Enterprise Admins
    / Schema Admins additions are the top-severity alert — attacker
    privileges or insider-admin scope creep. Pair with Security-4738
    (account changed) and Security-4720 (account created) for full
    lifecycle. For Mover (PR032) scenarios the 4728 timeline maps
    the accumulating privilege scope.'
  qualifier-map:
    actor.user: field:subject-user-sid
    actor.session: field:subject-logon-id
    object.user: field:member-sid
    object.group: field:target-group-name
    time.start: field:event-time
anti-forensic:
  write-privilege: service
  integrity-mechanism: DC EVTX + replicated via AD to other DCs
  survival-signals:
  - 4728 adding to Domain Admins with SubjectUserSid = a non-IT admin account = compromise OR delegated-admin abuse
  - 4728 bracketed by Security-4624 for the acting account showing logon from unusual workstation / IP = attacker-initiated
  - Member SID for a service / disabled account being added to Domain Admins = dormant-privilege weaponization
provenance: [ms-event-4728, mitre-t1098-007, ms-audit-security-group-management, ms-technet-wiki-4728-4729, uws-event-4728, eventsentry-event-4728]
---

# Security-4728 — Member Added to Global Security Group

## Forensic value
DC-side audit of global-security-group member-add operations. Critical for enterprise privilege-change tracking: Domain Admins / Enterprise Admins / Schema Admins adds are the top-severity alerts. Mover (PR032) investigations use 4728 to track privilege accumulation across transfers.

## Concept references
- UserSID (MemberSid + SubjectUserSid), LogonSessionId (SubjectLogonId)

## Cross-reference
- **Security-4729** — global group member removed (cleanup event)
- **Security-4732** — local group member added
- **Security-4756** — universal group member added
- **Security-4738** — user account changed (concurrent attribute changes)
- **NTDS-dit** — canonical group-membership source
