---
name: Security-4720
title-description: "A user account was created"
aliases:
- user account created
- local user creation audit
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
  event-id: 4720
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
  note: the account that CREATED the new user (admin/SYSTEM)
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
  note: session in which the creation was performed — joins to the 4624 that opened the admin session
- name: privilege-list
  kind: flags
  location: EventData\PrivilegeList
  note: privileges exercised during the user-creation call (often empty or "-"; admin subjects typically don't need named privileges for account management)
- name: target-user-sid
  kind: identifier
  location: EventData\TargetSid
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: targetUser
  note: SID of the NEW user account
- name: target-user-name
  kind: identifier
  location: EventData\TargetUserName
  encoding: utf-16le
- name: target-domain-name
  kind: identifier
  location: EventData\TargetDomainName
  encoding: utf-16le
- name: sam-account-name
  kind: identifier
  location: EventData\SamAccountName
  encoding: utf-16le
- name: display-name
  kind: label
  location: EventData\DisplayName
  encoding: utf-16le
  note: AD displayName attribute. '-' or '<value not set>' for locally-created accounts.
- name: user-principal-name
  kind: identifier
  location: EventData\UserPrincipalName
  encoding: utf-16le
  note: UPN form (user@domain.tld). Populated for domain accounts; blank for local.
- name: home-directory
  kind: path
  location: EventData\HomeDirectory
  encoding: utf-16le
  note: UNC path to user's home directory. Attacker-created accounts frequently leave this at default '-' / '<value not set>'.
- name: home-path
  kind: path
  location: EventData\HomePath
  encoding: utf-16le
  note: drive letter mapped to the home directory (homeDrive attribute)
- name: script-path
  kind: path
  location: EventData\ScriptPath
  encoding: utf-16le
  note: logon-script path. Non-empty on a local-account creation is unusual — local accounts don't typically run logon scripts. Hunt signal.
- name: profile-path
  kind: path
  location: EventData\ProfilePath
  encoding: utf-16le
  note: roaming-profile path if set
- name: user-workstations
  kind: label
  location: EventData\UserWorkstations
  encoding: utf-16le
  note: comma-separated list of workstations the account is allowed to log on from. Legitimate admin creations often leave this unrestricted.
- name: password-last-set
  kind: timestamp
  location: EventData\PasswordLastSet
  encoding: filetime-or-enum
  note: "when the password was last set. '%%1794' = never (no password yet). Populated with a concrete timestamp on account creation if the caller set a password."
- name: account-expires
  kind: timestamp
  location: EventData\AccountExpires
  encoding: filetime-or-enum
  note: "account-expiration timestamp. '%%1794' = never expires. Non-%%1794 values indicate deliberate time-bounded access."
- name: primary-group-id
  kind: identifier
  location: EventData\PrimaryGroupId
  encoding: uint32
  note: "RID of the primary group. 513 = Domain Users / Users; 512 = Domain Admins; 515 = Domain Computers. Non-513 at creation = deliberate privileged setup."
- name: allowed-to-delegate-to
  kind: label
  location: EventData\AllowedToDelegateTo
  encoding: utf-16le
  note: SPN list for constrained delegation. Non-empty on a user-account creation is rare outside administrative setup — flag for delegation-abuse review.
- name: old-uac-value
  kind: flags
  location: EventData\OldUacValue
  encoding: hex-uint32
  note: "always 0x0 on 4720 (the account didn't exist before)"
- name: new-uac-value
  kind: flags
  location: EventData\NewUacValue
  encoding: hex-uint32
  note: "SAM USER_ACCOUNT flags at creation. NOTE — this is the SAM [MS-SAMR] encoding, NOT the AD userAccountControl schema; the two differ (bit values don't map 1:1). Common: 0x15 = Normal/PasswordNotReq/AccountDisabled bundle at initial create."
- name: user-account-control
  kind: flags
  location: EventData\UserAccountControl
  encoding: comma-separated flag names
  note: "decoded UAC flag set — %%-coded (e.g., '%%2080 %%2082' = account-disabled + password-never-expires). Look up %%<N> codes in the event-log message table (winevt.dll)."
- name: user-parameters
  kind: content
  location: EventData\UserParameters
  encoding: utf-16le
  note: RAS / dial-in settings. Rarely populated on modern systems.
- name: sid-history
  kind: identifier
  location: EventData\SidHistory
  encoding: sid-string-list
  note: "prior SIDs from cross-domain migration. Populated only on migrated accounts; non-empty at local account creation = SID-history injection attempt (classic domain-persistence technique)."
- name: logon-hours
  kind: label
  location: EventData\LogonHours
  encoding: utf-16le
  note: "%%1793 = All (unrestricted). Restricted hours are a legitimate admin configuration but also a signal of deliberate access-windowing."
observations:
- proposition: CREATED
  ceiling: C4
  note: 'Audit event for local user-account creation. For hands-on-keyboard

    attackers, creating a new account is common persistence; this event

    is the canonical detection signal.

    '
  qualifier-map:
    object.user-sid: field:target-user-sid
    object.username: field:target-user-name
    actor.user: field:subject-user-sid
    time.start: field:time-created
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX checksums
  survival-signals:
  - 4720 event with subject-user-sid = SYSTEM and target in Administrators group = classic privesc-followed-by-persistence
  - 4720 close in time to 4728 (user added to security group) with the same TargetSid = attacker is establishing administrative
    persistence
  - 4720 with non-empty SidHistory on a locally-created account = SID-history injection
  - 4720 with non-empty AllowedToDelegateTo on a non-service account = delegation abuse setup
provenance: [ms-event-4720, uws-event-4720]
---

# Security Event 4720 — User Account Created

## Forensic value
Canonical audit event for local user creation. For targeted attacks involving hands-on keyboard time on the host, creating a new local account is a common persistence technique — this event is the primary detection signal.

Cousin events to look for:
- **4722** — user account enabled
- **4724** — password reset attempt
- **4728** — user added to security group
- **4738** — user account changed
- **4726** — user account deleted (cleanup of created accounts)

## Concept reference
- UserSID (both the actor and the new target account)

## Follow-up correlation
4720 → 4728 (same TargetSid, group = Administrators): privesc via new-admin-account creation. Classic APT pattern.

## Practice hint
On a Windows system with Account Management auditing enabled, run `net user pentester P@ssw0rd! /add` then `net localgroup administrators pentester /add`. Observe 4720 for the creation + 4728 for the group addition — same TargetSid, same SubjectUserSid.
