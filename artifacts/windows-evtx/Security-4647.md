---
name: Security-4647
title-description: "User initiated logoff"
aliases:
- User-initiated logoff
link: user
tags:
- authentication
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows:
    min: Vista
    max: '11'
location:
  channel: Security
  event-id: 4647
  provider: Microsoft-Windows-Security-Auditing
fields:
- name: TargetUserSid
  kind: identifier
  location: EventData → TargetUserSid
  references-data:
  - concept: UserSID
    role: actingUser
- name: TargetLogonId
  kind: identifier
  location: EventData → TargetLogonId
  note: matches the LUID assigned in the session-opening 4624 — closes the session window for any 4688/4663/etc. sharing this LUID
  references-data:
  - concept: LogonSessionId
    role: sessionContext
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: SESSION_CLOSED_BY_USER
  ceiling: C3
  note: "User clicked Sign out / Log off. Distinct from 4634 (system-initiated logoff, e.g., timeout). Defines the authentic end of a user-deliberate session."
  qualifier-map:
    actor.user.sid: field:TargetUserSid
    actor.session.id: field:TargetLogonId
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance: [ms-event-4647, uws-event-4647]
---

# Security-4647

## Forensic value
A user-initiated logoff. Critical session-closure event — pairs with the original 4624/4648 by matching TargetLogonId to define the session's temporal envelope. Windows also emits 4634 for forced / timeout logoffs; together 4624+4647 (or 4624+4634) bound the window during which all other intra-session events are authentic.

## Join-key use
LogonSessionId links 4624 → 4647 → every in-session 4688 / 4663 / 4672 / 5140. Joining on LUID reconstructs the complete session trace.
