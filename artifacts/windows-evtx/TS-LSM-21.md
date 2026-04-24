---
name: TS-LSM-21
title-description: "Remote Desktop Services — session logon succeeded"
aliases:
- TerminalServices-LocalSessionManager 21
- RDP logon success
- session logon event
link: user
tags:
- timestamp-carrying
volatility: runtime
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  channel: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
  event-id: 21
fields:
- name: time-created
  kind: timestamp
  location: System\TimeCreated SystemTime
  encoding: iso8601-utc
  clock: system
  resolution: 1us
- name: user
  kind: identifier
  location: UserData\EventXML\User
  encoding: utf-16le
  note: '''DOMAIN\username'' or machine\username'
- name: session-id
  kind: counter
  location: UserData\EventXML\SessionID
  encoding: uint32
- name: source-ip
  kind: identifier
  location: UserData\EventXML\Address
  encoding: ip-address
  references-data:
  - concept: IPAddress
    role: authSourceIp
  note: '''LOCAL'' for console logons, IP for RDP'
observations:
- proposition: AUTHENTICATED
  ceiling: C3
  note: 'RDP + console session logon. Complements Security-4624 with per-session

    scope — TS-LSM-21 is the TerminalServices subsystem''s own session event

    and captures successful logon regardless of Security channel configuration.

    '
  qualifier-map:
    principal: field:user
    source: field:source-ip
    method: RDP / console
    time.start: field:time-created
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX checksums
  survival-signals:
  - TS-LSM-21 present for RDP session but no matching Security-4624 = Security channel was cleared/disabled but TS channel
    survived — common partial-cleanup pattern
provenance:
  - ms-tsv-lsm-operational
---

# TerminalServices-LocalSessionManager Event 21

## Forensic value
Session-establishment event for RDP and console logons. Independent of Security channel — useful when 4624 is suppressed or cleared because TS-LSM channel often survives partial cleanup.

Companion events in the same channel:
- **22** — Shell start
- **23** — Session logoff
- **24** — Session disconnected (but not logged off)
- **25** — Session reconnect

## Concept reference
- IPAddress (Address field)

## Known quirks
- **"LOCAL" vs IP in Address field.** LOCAL = console logon; IP = network (RDP).
- **UserData XML schema** differs from standard EventData — parsers must handle both.
- **Session-ID as correlation key** across the TS-LSM channel events for the same session lifecycle.

## Practice hint
RDP into a test VM. Check `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` for events 21 → 22 → 25 → 23 as you connect, interact, disconnect, reconnect, log off. Each event's SessionID ties the sequence together.
