---
name: Security-4732
title-description: "A member was added to a security-enabled local group"
aliases:
- 4732
- Local group member added
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
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  channel: Security
  event-id: 4732
  provider: "Microsoft-Windows-Security-Auditing"
  addressing: evtx-record
  note: "Fires on the machine whose SAM holds the local group OR on the DC if the group is a domain local group. Pairs with Security-4733 (member removed from local group), Security-4728 (global group add), Security-4756 (universal group add). Subcategory: 'Audit Security Group Management'."
fields:
- name: member-sid
  kind: identifier
  location: "EventData → MemberSid"
  encoding: SID
  references-data:
  - concept: UserSID
    role: identitySubject
  note: "SID of the account added to the group. Joins to NTDS-dit / SAM for account context."
- name: member-name
  kind: label
  location: "EventData → MemberName"
  encoding: utf-16le
  note: "Distinguished name or sAMAccountName of the added member. For domain groups, DN format; for local groups, account name."
- name: target-group-sid
  kind: identifier
  location: "EventData → TargetSid"
  encoding: SID (well-known for built-in groups)
  note: "SID of the group. Well-known high-privilege SIDs to alert on: S-1-5-32-544 (Administrators), S-1-5-32-551 (Backup Operators), S-1-5-32-548 (Account Operators), S-1-5-32-549 (Server Operators), S-1-5-32-578 (Hyper-V Administrators)."
- name: target-group-name
  kind: label
  location: "EventData → TargetUserName + TargetDomainName"
  encoding: utf-16le
  note: "Group name. 'Administrators' / 'Backup Operators' / custom-named groups."
- name: subject-user-sid
  kind: identifier
  location: "EventData → SubjectUserSid"
  encoding: SID
  references-data:
  - concept: UserSID
    role: actingUser
  note: "Account that performed the group-add. For mover / privilege-abuse investigations this is the person who added the member."
- name: subject-logon-id
  kind: identifier
  location: "EventData → SubjectLogonId"
  encoding: hex LUID
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: "Session LUID of the acting admin. Threads to Security-4624 for context."
- name: event-time
  kind: timestamp
  location: "System/TimeCreated"
  encoding: xs:dateTime UTC
  clock: system (DC or host)
  resolution: 1ms
  note: "Group-add moment. For mover-pattern analysis, compare against documented transfer-date."
observations:
- proposition: PRIVILEGE_GRANTED
  ceiling: C3
  note: 'Security-4732 captures additions to local security groups —
    including high-privilege groups like Administrators, Backup
    Operators, and Account Operators. Attackers use local-group
    additions as stealth persistence (less auditing attention than
    domain group changes). For mover-privilege-accumulation
    scenarios (Mover PR032) it''s the core event.'
  qualifier-map:
    actor.user: field:subject-user-sid
    actor.session: field:subject-logon-id
    object.user: field:member-sid
    object.group: field:target-group-name
    time.start: field:event-time
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX-level
  survival-signals:
  - Subject user SID (actor) = target-user SID (member added) = user added themselves to a group (usually requires prior elevation — worth investigating HOW they achieved that)
  - Multiple 4732 events adding members to high-privilege groups in a single session = bulk privilege grant (mover + tamper combo)
  - 4732 on a privileged group with target a disabled account (Security-4738 earlier showed enable) = dormant-account reactivation + privilege grant combo
provenance: [ms-event-4732, mitre-t1098-007, ms-audit-security-group-management, uws-event-4732]
---

# Security-4732 — Member Added to Local Security Group

## Forensic value
Captures local-group member-add operations. High-privilege group adds (Administrators, Backup Operators, Account Operators, Server Operators) are near-universal attacker persistence / privilege-escalation actions. For Mover (PR032) cases documents cumulative privilege growth across role-transition.

## Concept references
- UserSID (MemberSid + SubjectUserSid), LogonSessionId (SubjectLogonId)

## Well-known local-group SIDs to prioritize
- S-1-5-32-544 — BUILTIN\Administrators
- S-1-5-32-551 — BUILTIN\Backup Operators (can read protected files)
- S-1-5-32-548 — BUILTIN\Account Operators (can modify most users)
- S-1-5-32-549 — BUILTIN\Server Operators
- S-1-5-32-578 — BUILTIN\Hyper-V Administrators

## Cross-reference
- **Security-4733** — member removed (cleanup event)
- **Security-4728** — global group member added
- **Security-4756** — universal group member added
- **Security-4624** — subsequent logon by the newly-added member
- **Security-4672** — special privileges granted at logon (downstream effect)
