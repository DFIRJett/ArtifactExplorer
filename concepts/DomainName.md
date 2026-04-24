---
name: DomainName
kind: value-type
lifetime: permanent
link-affinity: network
description: |
  Fully-qualified or partial DNS domain name. Captured by any artifact that
  records name resolution, network communication, or domain-associated
  content. Primary pivot for "where did this host go?" questions.
canonical-format: "lowercase ASCII dot-separated labels (e.g., 'example.com', 'sub.example.co.uk')"
aliases: [hostname, FQDN, dns-name]
roles:
  - id: emailDomain
    description: "Domain portion of an email address (from/to/cc or message-header source)"
  - id: httpRequestHost
    description: "Authority host of an HTTP/HTTPS request or browsed URL"
  - id: dnsResolvedName
    description: "Hostname that was resolved (DNS cache entry or DNS-query event)"
  - id: networkProfileDnsSuffix
    description: "DNS suffix configured for a known network profile"
  - id: targetDomain
    description: "Domain of an authenticated account — AutoLogon DefaultDomainName, 4624 TargetDomainName, cached-credential domain"

known-containers:
  - DNSCache
  - Chrome-History
  - Firefox-places
  - Sysmon-22
  - Sysmon-3
  - firewall-log
  - proxy-log
  - Outlook-PST
  - NetworkList-profiles
  - TS-Client-MRU
  - AutoLogon
provenance:
  - rfc-1035-domain-names
  - rfc-5891-idn-in-applications
---

# Domain Name

## What it is
DNS domain name — the human-readable half of a network-communication event. Captured anywhere name resolution happens or domain-associated content is stored: DNS caches, browser histories, email recipient fields, proxy/firewall logs, TLS SNI fields.

## Forensic value
- **Threat-intel cross-reference.** Domains appear on block lists, known-bad feeds, DGA-detection patterns.
- **Activity reconstruction.** Browser history + DNS cache + firewall log for the same domain gives three independent confirmations of a user reaching that host.
- **Beaconing detection.** Regular-interval DNS queries for the same domain outside business hours = C2 signature.

## Normalization
Always lowercase before cross-artifact match. Different artifacts preserve case inconsistently (DNS cache canonicalizes, browsers preserve user input case, TLS SNI can be either).

## Encoding variations

| Artifact | Where |
|---|---|
| DNSCache | `HKLM\SYSTEM\...\DNSCache` registry key names + `Get-DnsClientCache` output |
| Chrome-History | `urls.url` column, parsed for host part |
| Sysmon-22 (DNS-query events) | `QueryName` event field |
| firewall log | hostname column (if DNS logging enabled) |
| Outlook-PST | recipient/sender email domain part |
