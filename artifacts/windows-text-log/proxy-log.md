---
name: proxy-log
aliases:
- web proxy log
- Squid log
- Zscaler log
- forward-proxy access log
link: network
tags:
- timestamp-carrying
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: proxy access log
platform:
  windows:
    min: any
    max: any
  linux:
    min: any
    max: any
  cloud:
    any: true
location:
  path: 'deployment-specific — Squid: /var/log/squid/access.log ; Zscaler: cloud; ISA/TMG: W3C-formatted in custom path'
  addressing: log-line-per-request
fields:
- name: timestamp
  kind: timestamp
  location: log line prefix
  encoding: epoch-seconds OR ISO-8601 depending on proxy
  clock: proxy-system
  resolution: 1ms-1s
- name: client-ip
  kind: identifier
  location: client-IP column
  encoding: ip-address-string
  references-data:
  - concept: IPAddress
    role: proxyClientIp
- name: destination-host
  kind: identifier
  location: URL column — parsed host part
  encoding: ascii-lowercased
  references-data:
  - concept: DomainName
    role: httpRequestHost
- name: destination-url
  kind: path
  location: URL column — full request target
  encoding: ascii
  references-data:
  - concept: URL
    role: proxyRequestUrl
- name: http-method
  kind: enum
  location: method column
  encoding: GET / POST / CONNECT / ...
- name: response-code
  kind: enum
  location: HTTP status column
  encoding: uint16
- name: bytes-transferred
  kind: counter
  location: size column
  encoding: uint64
  note: large PUT/POST bytes = potential exfiltration signal
- name: user-agent
  kind: identifier
  location: user-agent column (when logged)
  encoding: ascii
- name: authenticated-user
  kind: identifier
  location: auth-user column (NTLM/Kerberos-authenticated proxies)
  encoding: ascii
  note: when available, ties the request directly to a Windows user
observations:
- proposition: COMMUNICATED
  ceiling: C3
  note: 'Proxy logs are authoritative for outbound HTTP/HTTPS traffic that

    traverses the proxy. For environments with mandatory proxies, nothing

    leaves without a log entry. Large POST bytes + unusual destinations =

    exfiltration signature.

    '
  qualifier-map:
    direction: sent
    peer.host: field:destination-host
    peer.url: field:destination-url
    peer.ip: field:client-ip
    content-size: field:bytes-transferred
    time.start: field:timestamp
anti-forensic:
  write-privilege: admin
  integrity-mechanism: depends on deployment — many proxies forward to SIEM for immutable storage
  known-cleaners:
  - tool: local log rotation / truncation
    typically-removes: partial
  - tool: attacker with proxy admin — unlikely in targeted-endpoint investigations
    typically-removes: full
  survival-signals:
  - SIEM copy of proxy logs vs. local copy mismatch = local-log tampering
  - Gaps in log sequence aligned with known incident window = deletion attempt
provenance: []
provenance: [kape-files-repo]
---

# Web Proxy Access Log

## Forensic value
Centralized record of outbound HTTP/HTTPS from managed endpoints. In enterprise environments, the proxy log is often the most complete network-communication record available — more reliable than endpoint DNS cache (volatile) or firewall logs (coarse).

## Concept references
- DomainName (destination-host)
- URL (destination-url)
- IPAddress (client-ip)

## Format variations
- **Squid access.log** — space-separated W3C-extended
- **W3C/IIS format** — field directives at top of file
- **Zscaler / cloud proxies** — JSON export via API
- **Custom enterprise proxies** — vendor-specific

Parsers must be format-aware. For forensic ingest, Plaso has modules for most common formats.

## Practice hint
If you're in an environment with a proxy, request a week's worth of logs filtered to a target host. Group by destination-host + count requests + sum bytes-transferred. Hosts with high bytes-transferred + low request count = potential exfil target (few large uploads).
