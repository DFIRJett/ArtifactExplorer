---
name: Sysmon-22
title-description: "DnsQuery"
aliases:
- Sysmon DNS query
- Sysmon DnsQuery event
link: network
tags:
- timestamp-carrying
- tamper-hard
volatility: runtime
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Sysmon/Operational
platform:
  windows:
    min: '10'
    max: '11'
    note: Sysmon required
location:
  channel: Microsoft-Windows-Sysmon/Operational
  event-id: 22
  log-file: '%WINDIR%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx'
  addressing: channel+event-id
fields:
- name: rule-name
  kind: label
  location: EventData\RuleName
  encoding: utf-16le
  note: Matching config rule name. DNS-hunt rules frequently use named rules for DGA pattern, exfil-over-DNS, or suspicious-TLD detection.
- name: utc-time
  kind: timestamp
  location: EventData\UtcTime
  encoding: iso8601-utc
  clock: system
  resolution: 1ms
- name: process-guid
  kind: identifier
  location: EventData\ProcessGuid
  encoding: guid-string
- name: process-id
  kind: identifier
  location: EventData\ProcessId
  encoding: uint32
  references-data:
  - concept: ProcessId
    role: actingProcess
  note: PID of the process that issued the DNS query. Join to Sysmon-1.process-id for the resolver caller's image+command-line.
- name: image
  kind: path
  location: EventData\Image
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: actingProcess
  note: process that made the DNS query — unique visibility Sysmon provides that the OS resolver doesn't
- name: query-name
  kind: identifier
  location: EventData\QueryName
  encoding: utf-16le
  references-data:
  - concept: DomainName
    role: dnsResolvedName
- name: query-status
  kind: enum
  location: EventData\QueryStatus
  encoding: uint32
  note: 0 = success; non-zero codes include NXDOMAIN (3), SERVFAIL, etc.
- name: query-results
  kind: identifier
  location: EventData\QueryResults
  encoding: compound string ';'-separated A/AAAA/CNAME responses
  note: per-record results — parse for individual IPs/CNAMEs
- name: user
  kind: identifier
  location: EventData\User
  encoding: '''DOMAIN\username'''
observations:
- proposition: COMMUNICATED
  ceiling: C4
  note: 'Per-process DNS query with resolver response. Uniquely attributes

    DNS resolution to specific process — answers "WHICH process looked

    up evil.com?" which no other artifact natively captures.

    '
  qualifier-map:
    direction: sent
    peer.host: field:query-name
    actor.process: field:image
    actor.user: field:user
    time.start: field:utc-time
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX record/chunk checksums
  known-cleaners:
  - tool: Sysmon config filter exclusion
    typically-removes: selective
    note: a DNS-query-event exclusion filter in Sysmon config silently suppresses
  survival-signals:
  - Sysmon process-create for a process + no DNS-query events from same process = DNS queries suppressed OR the process uses
    direct IP (no lookup)
provenance:
  - ms-sysmon-system-monitor
  - hartong-2024-sysmon-modular-22-dns-query-ru
  - trustedsec-2021-sysmon-event-22-dns-query-anal
---

# Sysmon Event 22 — DNS Query

## Forensic value
Per-process DNS query telemetry. Unlike OS-level DNS cache (host-scope, no process attribution), Sysmon 22 ties each query to the process that issued it. Answers "which program tried to resolve malicious.com" — crucial for malware analysis and beaconing detection.

## Concept references
- DomainName (query-name)
- ExecutablePath (image)

## Known quirks
- **Sysmon-only.** Requires Sysmon installed with DNS logging enabled (some configs exclude DNS events due to volume).
- **High volume.** DNS queries happen constantly. Default Sysmon configs often filter out common benign domains to keep log volume manageable — check your config for exclusion rules.
- **Query-results field is compound.** Multiple A/AAAA responses in one query — parse ';' -separated.
- **Failed lookups still logged.** NXDOMAIN queries help detect DGA malware and typo-squats.

## Practice hint
On a Sysmon-instrumented VM with DNS events enabled, open a browser and visit a site. Query the Sysmon channel for event ID 22 — observe the specific process (chrome.exe, msedge.exe) making queries, and the responses. Compare against host DNSCache for the same domains.
