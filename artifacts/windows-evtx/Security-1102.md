---
name: Security-1102
title-description: "The audit log was cleared"
aliases:
- audit log cleared
- Security log cleared
- log clear event
link: security
tags:
- timestamp-carrying
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: { min: Vista, max: "11" }
  windows-server: { min: "2008", max: "2022" }

location:
  channel: Security
  event-id: 1102
  note: |
    Uniquely, this event is written BY the act of clearing the log. After
    wevtutil clear-log or MMC Event Viewer "Clear Log" on Security, the
    CLEARED Security.evtx starts fresh with event 1102 as its first entry —
    naming who cleared it and when.

fields:
- name: time-created
  kind: timestamp
  location: System\TimeCreated SystemTime
  encoding: iso8601-utc
  clock: system
  resolution: 1us
- name: subject-user-sid
  kind: identifier
  location: UserData\LogFileCleared\SubjectUserSid
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: actingUser
  note: SID of the account that cleared the Security log — almost always an admin
- name: subject-user-name
  kind: identifier
  location: UserData\LogFileCleared\SubjectUserName
  encoding: utf-16le
- name: subject-domain-name
  kind: identifier
  location: UserData\LogFileCleared\SubjectDomainName
  encoding: utf-16le
- name: subject-logon-id
  kind: identifier
  location: UserData\LogFileCleared\SubjectLogonId
  encoding: hex-uint64

observations:
- proposition: DELETED
  ceiling: C4
  note: |
    "Security audit log cleared" — the canonical forensic-tampering signal.
    An investigator finding a 1102 in the first-few-events position of
    Security.evtx knows the log was cleared by the named user at the named
    time. Attackers who understand this sometimes avoid `wevtutil clear`
    in favor of service-stop-and-file-delete to avoid leaving 1102.
  qualifier-map:
    object.resource: Security.evtx channel
    actor.user: field:subject-user-sid
    change-type: channel-wipe
    time.start: field:time-created

anti-forensic:
  write-privilege: unknown
  integrity-mechanism: EVTX record checksum
  known-cleaners:
  - tool: stop EventLog service + delete Security.evtx + restart
    typically-removes: "avoids emitting 1102 — but leaves System-log traces of EventLog service stop"
  - tool: wevtutil clear-log Security
    typically-removes: "emits 1102 as first event of cleared channel — self-reporting"
  survival-signals:
  - 1102 present at beginning of Security.evtx = audit was cleared. Treat ALL subsequent 4624/4625/4688/etc. as post-clear-only coverage.
  - multiple 1102 events across Security.evtx = repeated clearing attempts. Each clear emits 1102 that survives in the next clear's reset.
provenance: [ms-event-1102, uws-event-1102]
---

# Security Event 1102 — Audit Log Cleared

## Forensic value
The canonical Windows detection for Security-log tampering. When the Security channel is cleared via `wevtutil clear-log` or MMC Event Viewer, the newly-emptied Security.evtx starts with event 1102 recording WHO performed the clear.

For any investigation where Security.evtx is suspiciously sparse or starts from a recent timestamp, CHECK FOR 1102 FIRST. Its presence is ground truth that the log was cleared.

## Concept reference
- UserSID (SubjectUserSid — actingUser, the clearer)

## Detection logic in one sentence
If the oldest event in Security.evtx is 1102 and its TimeCreated is much more recent than the system installation date, the Security channel has been actively cleared.

## Bypass pattern
Sophisticated attackers avoid `wevtutil clear` specifically to avoid 1102. Alternatives:
- Stop EventLog service → delete Security.evtx file → restart service (new file created without 1102, but System log records service stops)
- Service-token injection to write directly to the event store (rare, advanced)

In both bypass cases, OTHER signals remain: System-log service-control events, gaps in event-ID sequence, Security.evtx size anomalies.

## Practice hint
On a test VM with admin: `wevtutil cl Security` → then re-query Security.evtx. The first event you see is 1102, naming yourself + the clear time. Every forensic case worth its salt starts with this check.
