---
name: Security-4634
title-description: "An account was logged off"
aliases:
- logoff event
- session-end event
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
    max: '2025'
location:
  channel: Security
  event-id: 4634
  log-file: '%WINDIR%\System32\winevt\Logs\Security.evtx'
  addressing: channel+event-id
fields:
- name: time-created
  kind: timestamp
  location: System\TimeCreated SystemTime
  encoding: iso8601-utc
  clock: system
  resolution: 1us
- name: target-user-sid
  kind: identifier
  location: EventData\TargetUserSid
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: authenticatingUser
- name: target-user-name
  kind: identifier
  location: EventData\TargetUserName
  encoding: utf-16le
- name: target-domain-name
  kind: identifier
  location: EventData\TargetDomainName
  encoding: utf-16le
- name: target-logon-id
  kind: identifier
  location: EventData\TargetLogonId
  encoding: hex-uint64
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: same LogonId value that appeared in the corresponding 4624 logon event — use as session pairing key
- name: logon-type
  kind: enum
  location: EventData\LogonType
  encoding: uint32
  note: logon type of the session being ended; matches the type from the paired 4624
observations:
- proposition: AUTHENTICATED
  ceiling: C4
  note: 'Logoff event — the canonical session-end marker. Paired with 4624

    (logon) by matching TargetLogonId, gives the complete session window.

    4634 alone is less useful than 4624; forensic value comes from the

    pairing.

    '
  qualifier-map:
    principal: field:target-user-sid
    target: this-system
    result: session-ended
    time.start: field:time-created
  preconditions:
  - Security.evtx retention includes the target window
  - Audit policy has Logon success auditing enabled
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX record/chunk checksums
  known-cleaners:
  - tool: wevtutil clear-log Security
    typically-removes: full
  - tool: disable Logon auditing before logoff
    typically-removes: prospective
    note: attackers who disabled audit post-logon but before logoff leave 4624 but no 4634
  survival-signals:
  - 4624 events with TargetLogonId not matched by any 4634 = sessions still open OR logoff audit was disabled/cleared after
    logon
  - 4634 present but no matching 4624 = 4624 was pruned (older than Security.evtx retention) or selectively deleted
provenance: [ms-event-4634, uws-event-4634]
---

# Security Event 4634 — Account Logoff

## Forensic value
Logoff companion to 4624. Alone, relatively thin (just "this session ended"). Paired with 4624 via TargetLogonId, gives the complete session window — when a user was actively logged on.

Session-window reconstruction is the canonical use:
1. Filter Security.evtx to 4624 + 4634 for a target user SID
2. Match each 4624's TargetLogonId with the corresponding 4634's TargetLogonId
3. Each pair = one session, with start and end timestamps
4. Unpaired 4624 = session still open OR logoff pruned/suppressed

## Concept reference
- UserSID (TargetUserSid)

## Known quirks
- **No IpAddress / WorkstationName.** Unlike 4624, 4634 doesn't carry source-origin fields. If you need source context for the session, you must get it from the paired 4624.
- **Token-elevation not repeated.** The elevation state you'd want for post-logon analysis is on 4624; 4634 doesn't repeat it.
- **LogonType preserved.** Useful when matching without logonID is necessary (ambiguous cases).
- **Event 4647** (user-initiated logoff) is similar but fires for *explicit* logoff actions only. 4634 fires on all session ends. Both are worth collecting.

## Practice hint
On a Windows box with Security auditing on, log in as a test user, work briefly, log out. Parse Security.evtx — find the 4624 and 4634 for your user SID. Verify TargetLogonId matches between them. Compute session duration from timestamps.
