---
name: Security-4738
title-description: "A user account was changed"
aliases:
- 4738
- User account changed
link: user
link-secondary: persistence
tags:
- account-lifecycle
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
  event-id: 4738
  provider: "Microsoft-Windows-Security-Auditing"
  addressing: evtx-record
  note: "Fires on the machine whose SAM or AD holds the account — i.e., the local host for local accounts, the DC for domain accounts. Triggered by any change to a user account's attributes (password change, attribute edit, disable/enable, SID history add, UserAccountControl flags). Subcategory: 'Audit User Account Management'."
fields:
- name: target-user-sid
  kind: identifier
  location: "EventData → TargetSid"
  encoding: SID
  references-data:
  - concept: UserSID
    role: identitySubject
  note: "SID of the account that was changed. Joins to NTDS-dit / SAM for account-context and to subsequent auth events."
- name: target-username
  kind: label
  location: "EventData → TargetUserName + TargetDomainName"
  encoding: utf-16le
  note: "SAM account name + domain. Format: DOMAIN\\user. Cross-reference against Security-4624 / 4776 post-change."
- name: subject-user-sid
  kind: identifier
  location: "EventData → SubjectUserSid"
  encoding: SID
  references-data:
  - concept: UserSID
    role: actingUser
  note: "Account that MADE the change. For auditing: attacker-initiated changes (password reset, UAC flags, SID history addition) reveal who performed the modification."
- name: subject-logon-id
  kind: identifier
  location: "EventData → SubjectLogonId"
  encoding: hex LUID
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: "Session LUID of the acting user — threads to Security-4624 for context."
- name: changed-attributes
  kind: content
  location: "EventData — AttributeName / OldValue / NewValue AND UserAccountControl bit deltas"
  encoding: utf-16le
  note: "Set of attribute changes applied in this event. Key fields: PasswordLastSet (password reset), UserAccountControl (enable/disable, password-never-expires, don't-require-preauth — preauth-off = AS-REP roasting exposure), PrimaryGroupId, SidHistory, UserParameters. Multiple changes in one event = bulk edit (admin tooling or attacker script)."
- name: user-account-control
  kind: flags
  location: "EventData → UserAccountControl (before + after bitmask)"
  encoding: MS-SAMR USER_ACCOUNT bitmask (see note)
  note: "Encoding caveat (2026-04-23): OldUacValue/NewUacValue carry MS-SAMR USER_ACCOUNT codes (MS-SAMR §2.2.1.12), NOT AD userAccountControl schema values. Bit layouts differ — e.g., DONT_REQ_PREAUTH = 0x00010000 (SAM) vs 0x00400000 (AD); SMARTCARD_REQUIRED = 0x00001000 (SAM) vs 0x00040000 (AD); TRUSTED_FOR_DELEGATION = 0x00002000 (SAM) vs 0x00080000 (AD). See ms-samr-user-account-codes for the authoritative bitmask and ms-kb-useraccountcontrol for AD-side cross-reference. Cited bit values below reflect legacy annotations and MUST be re-verified against MS-SAMR before SIEM rule-building. Attacker-useful changes (conceptual, encoding-independent): enable disabled account, clear DONT_EXPIRE_PASSWORD, set DONT_REQ_PREAUTH (AS-REP-roast exposure), set TRUSTED_FOR_DELEGATION (Kerberos unconstrained delegation)."
- name: event-time
  kind: timestamp
  location: "System/TimeCreated"
  encoding: xs:dateTime UTC
  clock: system (DC for domain; host for local)
  resolution: 1ms
  note: "Change-apply time. For Mover investigations: bracket 4738 events for the Mover's account vs the date-of-transfer to distinguish legitimate transfer-related changes from unexpected later modifications."
observations:
- proposition: ACCOUNT_MODIFIED
  ceiling: C3
  note: 'Security-4738 captures account-attribute changes with before
    and after values for UserAccountControl plus per-attribute deltas
    when specific attributes changed. For Mover (PR032) investigations
    and attacker-account-manipulation cases (enable dormant account,
    clear DONT_EXPIRE, set preauth-off for AS-REP roasting), 4738 is
    the primary audit record. Pairs with Security-4728 (group-add)
    and Security-4720 (account-created) for full account-lifecycle
    reconstruction.'
  qualifier-map:
    object.user: field:target-user-sid
    actor.user: field:subject-user-sid
    actor.session: field:subject-logon-id
    time.start: field:event-time
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX-level; replicated across DCs via AD replication for domain events
  survival-signals:
  - 4738 showing DONT_REQ_PREAUTH set on a service account = AS-REP roasting exposure deliberately introduced
  - 4738 clearing Account-Disabled flag on a long-dormant admin account = reactivation (attacker-grade)
  - 4738 with PasswordLastSet change + no corresponding 4724 (admin-initiated password change) = user changed own password; discrepancy vs expected pattern = investigate
provenance: [ms-event-4738, mitre-t1098, ms-audit-user-account-management, ms-samr-user-account-codes, ms-kb-useraccountcontrol, uws-event-4738]
---

# Security-4738 — User Account Was Changed

## Forensic value
Captures any change to a user account's attributes (password reset, disable/enable, UserAccountControl flag changes, group-primary changes, SID history edits). On domain hosts fires on the DC; on standalone / local-account hosts fires locally.

## High-signal UAC flag changes
- **DONT_REQ_PREAUTH cleared → set**: opens the account to AS-REP roasting (attacker extraction of Kerberos hashes without prior auth)
- **Account-Disabled cleared**: dormant account reactivation
- **PASSWD_NOTREQD set**: account allowed to have blank password
- **TRUSTED_FOR_DELEGATION set**: Kerberos unconstrained delegation

## Concept references
- UserSID (TargetSid + SubjectUserSid), LogonSessionId (SubjectLogonId)

## Cross-reference
- **Security-4720** — account created
- **Security-4724** — admin reset password
- **Security-4728** — added to global group
- **Security-4732** — added to local security group
- **Security-4740** — account locked out
- **NTDS-dit** — canonical attribute source for the changed account

## Practice hint
On a lab domain: `Set-ADUser <user> -DoesNotRequirePreAuth $true`. Observe 4738 on the DC with UserAccountControl delta showing bit 0x400000 set. This is the AS-REP-roast-opening edit attackers perform.
