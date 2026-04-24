---
name: Sysmon-3
title-description: "Network Connection"
aliases:
- Sysmon network connection
- Sysmon NetworkConnect
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
    note: Sysmon required (MS 'Runs on' block — Client Win10+, Server 2016+; matches Sysmon-22 corpus sibling)
  windows-server:
    min: '2016'
    max: '2025'
location:
  channel: Microsoft-Windows-Sysmon/Operational
  event-id: 3
fields:
- name: rule-name
  kind: label
  location: EventData\RuleName
  encoding: utf-16le
  note: "Matching config rule name (empty if not named). Hunt queries frequently filter by RuleName to get targeted alerting."
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
  note: Sysmon-assigned — joins to Sysmon-1.process-guid for the full initiating-process lineage.
- name: process-id
  kind: identifier
  location: EventData\ProcessId
  encoding: uint32
  references-data:
  - concept: ProcessId
    role: actingProcess
- name: image
  kind: path
  location: EventData\Image
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: actingProcess
- name: user
  kind: identifier
  location: EventData\User
  encoding: '''DOMAIN\username'''
- name: protocol
  kind: enum
  location: EventData\Protocol
  encoding: '''tcp'' / ''udp'''
- name: initiated
  kind: flags
  location: EventData\Initiated
  encoding: bool
  note: true = outbound from this host, false = inbound
- name: source-is-ipv6
  kind: flags
  location: EventData\SourceIsIpv6
  encoding: bool
  note: whether source-ip is IPv6. Pair with destination-is-ipv6; mixed-stack behavior can surface IPv6-preferring malware on dual-stack hosts.
- name: source-ip
  kind: identifier
  location: EventData\SourceIp
  encoding: ip-address
  references-data:
  - concept: IPAddress
    role: sourceIp
- name: source-hostname
  kind: identifier
  location: EventData\SourceHostname
  encoding: utf-16le
  note: reverse-PTR lookup of source-ip. Frequently blank; don't over-interpret.
- name: source-port
  kind: counter
  location: EventData\SourcePort
  encoding: uint16
- name: source-port-name
  kind: label
  location: EventData\SourcePortName
  encoding: utf-16le
  note: "IANA service-name lookup for source-port (e.g. 'http', 'https', 'ssh'). Empty for ephemeral ports above 49152."
- name: destination-is-ipv6
  kind: flags
  location: EventData\DestinationIsIpv6
  encoding: bool
- name: destination-ip
  kind: identifier
  location: EventData\DestinationIp
  encoding: ip-address
  references-data:
  - concept: IPAddress
    role: destinationIp
- name: destination-hostname
  kind: identifier
  location: EventData\DestinationHostname
  encoding: utf-16le
  references-data:
  - concept: DomainName
    role: httpRequestHost
  note: "reverse-PTR lookup of destination-ip — NOT the name the process resolved. For the actually-queried name, pair with Sysmon-22 (DNS) by matching process-guid + nearby timestamp."
- name: destination-port
  kind: counter
  location: EventData\DestinationPort
  encoding: uint16
- name: destination-port-name
  kind: label
  location: EventData\DestinationPortName
  encoding: utf-16le
  note: IANA service-name for destination-port.
observations:
- proposition: CONNECTED
  ceiling: C4
  note: 'Per-process TCP/UDP connection event. Captures full 4-tuple + process

    attribution. Most detailed native-to-endpoint network event available.

    '
  qualifier-map:
    actor.process: field:image
    peer.ip: field:destination-ip
    peer.hostname: field:destination-hostname
    via.port: field:destination-port
    via.protocol: field:protocol
    direction: derived from initiated field
    time.start: field:utc-time
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX checksums
  known-cleaners:
  - tool: Sysmon config exclude of network events
    typically-removes: selective
provenance:
  - ms-sysmon-system-monitor
  - hartong-2024-sysmon-modular-3-network-conne
  - trustedsec-2022-sysinternals-sysmon-a-swiss-ar
---

# Sysmon Event 3 — Network Connection

## Forensic value
Per-process TCP/UDP connection event. Unique attribution: which process connected to which peer at what time. Complements firewall logs (which see the packet but not the process) and DNS cache (which sees name resolution but not follow-up connection).

## Three concept references
- ExecutablePath (image)
- IPAddress (source + destination)
- DomainName (destination-hostname when resolved)

## Known quirks
- **High volume.** Sysmon configs often exclude common benign destinations (Microsoft update servers, browser DNS prefetch). Check config filters.
- **DestinationHostname** is Sysmon's reverse-lookup — may be blank or unreliable for short-lived connections.
- **UDP connectionless.** UDP "connections" are flow-based; Sysmon creates an event per first-packet observation.

## Practice hint
With Sysmon running, make a simple HTTP request. Observe events 22 (DNS query) followed by 3 (network connection) for the same process-guid. Chain them for full "lookup → connect" narrative.
