---
name: DNS-NRPT
title-description: "Name Resolution Policy Table (NRPT) registry — per-namespace DNS redirection rules"
aliases:
- NRPT
- Name Resolution Policy Table
- DNS policy redirect
link: network
tags:
- dns-redirect
- tamper-signal
- itm:ME
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: '7'
    max: '11'
  windows-server:
    min: '2008R2'
    max: '2022'
location:
  hive: SOFTWARE (HKLM)
  path: "Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig\\<rule-GUID>"
  alt-path-user: "HKCU\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig (user-scope rules — rare)"
  companion-live: "Get-DnsClientNrptPolicy PowerShell cmdlet enumerates live effective policy"
  addressing: hive+key-path
  note: "NRPT is the Windows DNS client's policy framework for routing specific DNS namespace queries through specific DNS servers, DoH servers, or custom resolvers. Originally deployed for DirectAccess (split-tunnel DNS — .corp.example.com routed to internal DNS, .other.com to public). Now expanded to support DNS-over-HTTPS per-namespace, DNSSEC per-namespace, and custom encryption. For DFIR: attacker-added NRPT rules can REDIRECT specific domains to attacker-controlled DNS servers, bypassing enterprise DNS telemetry. Pre-resolution redirect — the DNS client never consults normal DNS for the namespace. Hard to detect without auditing the NRPT registry itself."
fields:
- name: namespace
  kind: label
  location: "DnsPolicyConfig\\<rule-GUID>\\Name value"
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: DomainName
    role: dnsResolvedName
  note: "DNS namespace the rule applies to. Formats: '.corp.example.com' (suffix match), 'exact.example.com' (exact), '*.example.com' (wildcard), 'example.com' (exact without dot). Attacker-authored rule targeting a specific sensitive domain = redirect that domain's queries to attacker infrastructure while leaving other DNS normal."
- name: generic-dns-servers
  kind: identifier
  location: "DnsPolicyConfig\\<rule-GUID>\\GenericDNSServers value"
  type: REG_SZ (semicolon-separated list)
  encoding: IP addresses (v4 / v6)
  references-data:
  - concept: IPAddress
    role: destinationIp
  note: "DNS server(s) to route the matching namespace's queries to. Multiple servers allowed. An attacker IP here + sensitive namespace in Name = queries for sensitive domains go to attacker server → attacker sees internal DNS patterns + can serve malicious A records."
- name: doh-template
  kind: identifier
  location: "DnsPolicyConfig\\<rule-GUID>\\DohTemplate value"
  type: REG_SZ
  references-data:
  - concept: URL
    role: embeddedReferenceUrl
  note: "For rules using DNS-over-HTTPS: the DoH template URL (e.g., https://attacker.example/dns-query). Attacker-configured DoH target bypasses enterprise DNS telemetry AND enterprise TLS inspection (DoH goes over HTTPS to a single server — looks like normal HTTPS traffic)."
- name: dnssec-validation
  kind: flags
  location: "DnsPolicyConfig\\<rule-GUID>\\DNSSECValidationRequired value"
  type: REG_DWORD
  note: "1 = require DNSSEC validation for this namespace; 0 = don't require. Attacker disabling DNSSEC validation for a specific namespace = allows spoofed responses to be accepted."
- name: config-options
  kind: flags
  location: "DnsPolicyConfig\\<rule-GUID>\\ConfigOptions value"
  type: REG_DWORD
  note: "Bitmask of rule options — encryption requirement, lookahead, custom resolver behavior. See Microsoft DnsClient CSP docs for flag meanings."
- name: rule-version
  kind: counter
  location: "DnsPolicyConfig\\<rule-GUID>\\Version value"
  type: REG_DWORD
  note: "Internal version counter. Advances on rule edit."
- name: key-last-write
  kind: timestamp
  location: DnsPolicyConfig subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on DnsPolicyConfig or per-rule subkey advances when a rule is added / modified / removed. Correlate with Security-4688 for the reg.exe / PowerShell Set-DnsClientNrptRule invocation."
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'NRPT rules are pre-resolution DNS policy — the Windows DNS
    client consults this registry BEFORE normal DNS resolution. An
    attacker-added NRPT rule can redirect queries for a specific
    namespace to an attacker-controlled DNS server, WITHOUT leaving
    traces in the normal DNS resolution path (DNSCache, Sysmon-22).
    Enterprise defenders who rely on DNS-server-log analysis miss
    redirected queries entirely because the host never asked their
    DNS server. For DFIR in investigations involving DNS anomalies,
    NRPT registry enumeration is mandatory.'
  qualifier-map:
    setting.registry-path: "Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig"
    peer.name: field:namespace
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  known-cleaners:
  - tool: Remove-DnsClientNrptRule (admin PowerShell)
    typically-removes: the rule
  survival-signals:
  - DnsPolicyConfig subkey with namespace referencing known sensitive internal-infrastructure FQDN + GenericDNSServers pointing to non-enterprise IP = redirect attack
  - DoH template pointing to non-approved DoH resolver = DNS tunneling / enterprise-DNS bypass
  - DNSSECValidationRequired=0 for high-value namespaces = spoof attack surface
  - Recent LastWrite outside documented enterprise DNS policy change window = tamper timeline
provenance: [ms-name-resolution-policy-table-nrpt-r, mitre-t1071-004]
---

# DNS NRPT (Name Resolution Policy Table)

## Forensic value
NRPT rules route specific DNS namespace queries to specific DNS servers / DoH templates / custom resolvers. Pre-resolution — the DNS client consults NRPT BEFORE doing normal DNS.

Location: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\<rule-GUID>`.

Originally designed for DirectAccess (split-tunnel DNS). Now broadly used for:
- DoH per-namespace
- DNSSEC per-namespace
- Custom-encryption DNS

An attacker-added rule can redirect specific sensitive domains to attacker-controlled DNS — queries never hit the enterprise DNS server, so enterprise DNS telemetry never sees them.

## Concept references
- DomainName (Name field)
- IPAddress (GenericDNSServers)
- URL (DohTemplate)

## Triage
```powershell
Get-DnsClientNrptPolicy
Get-DnsClientNrptRule
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig" /s
```

Red flags:
- Namespace entries targeting known-sensitive internal FQDNs
- GenericDNSServers pointing to external / non-enterprise IPs
- DohTemplate to unapproved DoH resolvers
- DNSSECValidationRequired=0 for authoritative zones

## Cross-reference
- **DNSCache** (HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters) — in-memory cache
- **Hosts-File** — legacy overlap
- **Microsoft-Windows-DNS-Client/Operational** EVTX — DNS query events
- **Sysmon-22 (DnsQuery)** — per-process DNS query telemetry

## Practice hint
Lab VM (admin): `Add-DnsClientNrptRule -Namespace ".example.com" -NameServers "8.8.8.8"`. Inspect `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\` — new GUID subkey with Name=.example.com, GenericDNSServers=8.8.8.8. Queries for *.example.com now route to 8.8.8.8. `Remove-DnsClientNrptRule -GatewayIPAddress 8.8.8.8` to clean up.
