---
name: DNSClient-3006
title-description: "Client DNS resolution failed"
aliases: [DNS query initiated]
link: network
tags: [network-telemetry, high-volume]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-DNS-Client/Operational
platform:
  windows: {min: '8.1', max: '11'}
  note: "DNS-Client/Operational is DISABLED by default on most Windows builds; requires `wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true` or Group Policy"
location:
  channel: Microsoft-Windows-DNS-Client/Operational
  event-id: 3006
  provider: Microsoft-Windows-DNS-Client
fields:
- name: QueryName
  kind: hostname
  location: EventData → QueryName
  references-data:
  - {concept: DomainName, role: dnsResolvedName}
- name: QueryType
  kind: flag
  location: EventData → QueryType
  note: "1=A, 28=AAAA, 5=CNAME, 15=MX, 16=TXT, ..."
- name: QueryOptions
  kind: flags
  location: EventData → QueryOptions
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: DNS_QUERY_INITIATED
  ceiling: C3
  note: "DNS query issued by this host. High-volume when enabled. Key value: queries for C2 domains, DNS-tunneling TXT queries, unusual high-volume A lookups."
  qualifier-map:
    object.domain: field:QueryName
    object.query.type: field:QueryType
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance:
  - mitre-t1071-004
  - ms-dns-client-operational
---

# DNSClient-3006

## Forensic value
Per-query DNS trace from the client side. Complementary to Sysmon-22 (same concept, different provider). Very high volume when enabled — expect tens of thousands of events per active-user day. Value is in filtering to specific QueryName patterns (C2 domains, DGA-like strings, unusually-long TXT queries).

## Cross-references
- **Sysmon-22** — process-attributed DNS queries (richer but requires Sysmon)
- **DNSCache** (registry) — resolved-name cache (host answer, not client-side query)
- **Sysmon-3** — actual network connection to the resolved IP
