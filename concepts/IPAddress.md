---
name: IPAddress
kind: value-type
lifetime: persistent
link-affinity: network
link-affinity-secondary: device
description: |
  IPv4 or IPv6 address. Captured by any artifact involving network
  communication — resolver caches, connection logs, firewall events,
  proxy records, TCP/UDP session artifacts.
canonical-format: "IPv4 dotted-quad (1.2.3.4) or IPv6 colon-hex (::1, fe80::...)"
aliases: [ip, ipv4, ipv6]
roles:
  - id: sourceIp
    description: "Originator of a network flow or audited action"
  - id: destinationIp
    description: "Target of a network connection"
  - id: resolvedIp
    description: "IP produced by DNS resolution"
  - id: authSourceIp
    description: "Source IP recorded on an authentication event"
  - id: relayHop
    description: "Intermediate SMTP relay captured in a Received-by header chain"
  - id: proxyClientIp
    description: "Client IP in a web-proxy access log"

known-containers:
  - DNSCache
  - Sysmon-3
  - firewall-log
  - proxy-log
  - Security-4624
  - Security-4625
  - Security-4648
  - NetworkList-profiles
  - TS-LSM-21
  - TS-Client-MRU
  - Outlook-PST
  - Zone-Identifier-ADS
provenance:
  - rfc-791-ipv4
  - rfc-4291-ipv6-addressing-architecture
---

# IP Address

## What it is
The numeric half of a network communication event. Complements DomainName (the human-readable half). Captured anywhere name resolution, connection establishment, or packet flow is recorded.

## Forensic value
- **Threat-intel pivot.** IPs on block lists, known C2 infrastructure.
- **Geolocation / ASN lookup.** Correlates to hosting provider, country.
- **Flow reconstruction.** Same src/dst IP across multiple artifacts = same connection.

## Normalization
- **IPv4:** decimal dotted-quad. No leading zeros, no integer representations.
- **IPv6:** lowercase colon-hex, double-colon compression per RFC 5952.
- Match across artifacts is byte-level; representation differences need normalization first.

## Encoding variations

| Artifact | Where |
|---|---|
| DNSCache | resolved IP field |
| Sysmon-3 | DestinationIp / SourceIp event fields |
| firewall-log | src-ip / dst-ip columns |
| proxy-log | client-ip / dest-ip |
| Security-4624 | IpAddress event field (network/RDP logons) |
| NetworkList-profiles | configured-interface IP assignments |
