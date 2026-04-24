---
name: Security-4625
title-description: "An account failed to log on"
aliases:
- failed logon event
- account-logon-failure audit
link: user
tags:
- timestamp-carrying
- tamper-hard
volatility: runtime
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: { min: Vista, max: "11" }
  windows-server: { min: "2008", max: "2022" }

location:
  channel: Security
  event-id: 4625

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
  note: SID reporting the failure — typically SYSTEM (S-1-5-18) for interactive / network logons, or the account of the process attempting auth for service logons
- name: subject-user-name
  kind: identifier
  location: EventData\SubjectUserName
  encoding: utf-16le
  note: usually the machine account ($) or SYSTEM
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
  note: logon ID of the REPORTING session (0x3e7 for SYSTEM)
- name: target-user-sid
  kind: identifier
  location: EventData\TargetUserSid
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: authenticatingUser
  note: "'S-1-0-0' (null SID) when the account doesn't exist — distinguishes typo from valid-user-wrong-password"
- name: target-user-name
  kind: identifier
  location: EventData\TargetUserName
  encoding: utf-16le
- name: target-domain-name
  kind: identifier
  location: EventData\TargetDomainName
  encoding: utf-16le
- name: failure-reason
  kind: enum
  location: EventData\FailureReason
  encoding: enum-string
  note: "%%2304=unknown user/bad password, %%2307=account-locked, %%2310=password-expired, %%2311=logon-type-not-allowed, etc."
- name: status
  kind: enum
  location: EventData\Status
  encoding: hex-uint32
  note: "NTSTATUS — 0xC000006D=generic bad-user-or-pass, 0xC0000064=user-not-found, 0xC000006A=wrong-password-for-valid-user, 0xC0000234=locked-out"
- name: sub-status
  kind: enum
  location: EventData\SubStatus
  encoding: hex-uint32
  note: more specific than Status; often the actionable field
- name: logon-type
  kind: enum
  location: EventData\LogonType
  encoding: uint32
  note: same values as 4624
- name: logon-process-name
  kind: identifier
  location: EventData\LogonProcessName
  encoding: utf-16le
  note: e.g., 'User32', 'Advapi', 'NtLmSsp', 'Kerberos', 'Seclogo'
- name: authentication-package
  kind: identifier
  location: EventData\AuthenticationPackageName
  encoding: utf-16le
  note: NTLM / Kerberos / Negotiate. Same spray/brute-force typically hits NTLM in one bucket and Kerberos in another — useful split.
- name: transmitted-services
  kind: identifier
  location: EventData\TransmittedServices
  encoding: utf-16le
  note: Kerberos S4U transit list. '-' when no delegation.
- name: lm-package-name
  kind: identifier
  location: EventData\LmPackageName
  encoding: utf-16le
  note: "NTLM version: 'NTLM V1' / 'NTLM V2' / 'LM'. '-' unless AuthenticationPackageName == NTLM. NTLM V1 failures in a modern environment = likely downgrade / legacy-protocol probing."
- name: key-length
  kind: counter
  location: EventData\KeyLength
  encoding: uint32
  note: NTLM session key length. 0 for Kerberos or Negotiate-Kerberos.
- name: process-id
  kind: identifier
  location: EventData\ProcessId
  encoding: hex-uint64
  note: PID of the process attempting the logon on behalf of the target user
- name: workstation-name
  kind: identifier
  location: EventData\WorkstationName
  encoding: utf-16le
- name: source-ip
  kind: identifier
  location: EventData\IpAddress
  encoding: ip-address-string
  references-data:
  - concept: IPAddress
    role: authSourceIp
- name: source-port
  kind: counter
  location: EventData\IpPort
  encoding: uint16
- name: process-name
  kind: path
  location: EventData\ProcessName
  encoding: utf-16le
  note: the process that attempted the logon on behalf of the user

observations:
- proposition: AUTHENTICATED
  ceiling: C4
  note: |
    Audit of failed logon attempt. Forensically critical: brute-force,
    password-spray, and credential-stuffing attacks surface here in bulk.
    A single 4625 is thin signal; a cluster of 4625s against one account
    OR many accounts from one source-ip is high-confidence attack signal.
  qualifier-map:
    principal: field:target-user-sid
    target: this-system
    result: failure
    method: field:logon-type
    source: field:source-ip
    time.start: field:time-created

anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX checksums
  survival-signals:
  - 4625 spike against one user across minutes = brute-force against that account
  - 4625 against many accounts from one source-ip in short window = password-spray
  - 4625 with SubStatus 0xC0000064 (user-not-found) for many usernames = username enumeration
  - sudden 4625 cessation after prior spike = attacker got in (check for subsequent 4624 with same source-ip)
provenance: [ms-event-4625, uws-event-4625]
---

# Security Event 4625 — Failed Logon

## Forensic value
Authentication-failure audit. Complements 4624 (success). For brute-force / password-spray / credential-stuffing detection, 4625 is the primary source. For targeted-attack reconstruction, 4625 clusters often precede a 4624 success — the "attack window."

## Concept references
- UserSID (TargetUserSid — authenticatingUser)
- IPAddress (IpAddress — authSourceIp)

## Sub-status decoding (the actionable field)
| SubStatus | Meaning |
|---|---|
| 0xC000005E | No logon servers available |
| 0xC0000064 | Username doesn't exist |
| 0xC000006A | Correct username, wrong password |
| 0xC000006D | Generic bad username-or-password |
| 0xC000006F | Logon outside authorized hours |
| 0xC0000070 | Logon from unauthorized workstation |
| 0xC0000071 | Password expired |
| 0xC0000072 | Account disabled |
| 0xC000015B | Logon type not granted |
| 0xC0000224 | User must change password at next logon |
| 0xC0000234 | Account locked out |

Different SubStatus values reveal different attack intents.

## Practice hint
Parse a week's worth of Security.evtx. Group 4625 by TargetUserName + SourceIP. Any user with >10 failures in an hour from one IP = likely brute-force. Any single IP hitting >5 distinct accounts = likely password-spray.
