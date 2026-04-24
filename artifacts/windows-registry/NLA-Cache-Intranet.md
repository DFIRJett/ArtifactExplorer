---
name: NLA-Cache-Intranet
title-description: "NetworkList NLA Cache Intranet — FQDNs of corporate / intranet networks the host has been on"
aliases:
- NLA Intranet Cache
- NetworkList Nla Cache Intranet
- intranet FQDN cache
link: network
tags:
- network-history
- domain-join-trace
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
  path: "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Nla\\Cache\\Intranet"
  sibling: "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Nla\\Cache\\IpSubnet (IP-subnet cache for non-domain networks)"
  addressing: hive+key-path
  note: "Network Location Awareness (NLA) caches the intranet / corporate FQDNs it has successfully resolved while on a managed network. Each value name is an intranet FQDN (e.g., 'corp.example.com', 'internal.company.net'). The companion IpSubnet sibling caches the IP subnets for networks NLA treated as non-domain. THIS key specifically captures corporate intranet connection history — useful for tracking which internal networks a roaming laptop has joined and for rebuilding domain-join timelines."
fields:
- name: intranet-fqdn
  kind: identifier
  location: "Nla\\Cache\\Intranet\\<fqdn> value names"
  encoding: utf-16le
  references-data:
  - concept: DomainName
    role: dnsResolvedName
  note: "Value NAME is the intranet FQDN itself. Value DATA is typically minimal / flag-value. Each entry = one corporate or intranet DNS suffix the host has encountered. For a laptop that roams across multiple enterprise networks (MSP contractor, consultant, multi-tenant environments), this key preserves the full list of intranet domains touched. Critical for lateral-movement investigations — an attacker who pivoted through an intranet leaves its FQDN here."
- name: ipsubnet-cache
  kind: identifier
  location: "Nla\\Cache\\IpSubnet\\<subnet> value names (sibling)"
  encoding: utf-16le
  note: "Value NAME is a CIDR-ish IP subnet entry. Covers non-domain (home, hotel, public) networks by subnet rather than FQDN. Pairs with NLA-Signatures-Unmanaged for a complete non-domain connection picture."
- name: key-last-write
  kind: timestamp
  location: Nla\\Cache\\Intranet key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on the parent Intranet key advances on any new cache entry. Each value's individual LastWrite is not separately exposed, but the key-level LastWrite serves as 'most-recent cache update time'."
- name: companion-nla-event
  kind: identifier
  location: "Microsoft-Windows-NlaSvc/Operational EVTX channel"
  note: "NLA logs network-transition events with event IDs 4001 (connected to network), 4002 (disconnected). Cross-reference with Nla\\Cache to correlate individual cache entries to specific connection events when the EVTX channel is enabled."
observations:
- proposition: COMMUNICATED
  ceiling: C3
  note: 'NLA Cache Intranet is a focused but valuable artifact for
    tracking which intranet / corporate networks a Windows host has
    been on. Different from NetworkList-profiles (which captures
    specific network profile metadata) and NLA-Signatures-Unmanaged
    (which captures consumer WiFi / home gateway history): this key
    is specifically about managed / domain-joined networks the host
    has authenticated to. For enterprise investigations, it helps
    reconstruct the "where has this laptop been" timeline at the
    corporate-network granularity — especially useful for
    contractor / consultant / MSP-partner machines that touch many
    different intranet environments.'
  qualifier-map:
    peer.name: field:intranet-fqdn
    time.end: field:key-last-write
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: none
  survival-signals:
  - Intranet FQDN values matching unexpected third-party corporate domains (vendor / partner / competitor networks) on a host that should not have been there
  - Unfamiliar intranet domains matching threat-intel-tracked attacker infrastructure (unusual but possible)
provenance:
  - ms-network-location-awareness-nla-serv
---

# NLA Cache Intranet

## Forensic value
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache\Intranet\` holds one value per corporate / intranet FQDN the Network Location Awareness service has resolved while connected to that managed network. Sibling `\Nla\Cache\IpSubnet\` holds subnet entries for non-domain networks.

Where NetworkList-profiles captures specific profiles (home, work, public) and NLA-Signatures-Unmanaged captures WiFi / gateway MAC history, **NLA-Cache-Intranet specifically captures managed-intranet FQDN history**.

## Use case
A contractor laptop touches multiple enterprise intranets. NLA cache accumulates FQDNs across each:
- `corp.clientA.com`
- `internal.clientB.net`
- `staging.vendor.io`
- `hidden.attacker-infra.example` ← this one doesn't belong

Triage yields the odd-one-out immediately.

## Concept reference
- DomainName (each cached intranet FQDN)

## Triage
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache\Intranet"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache\IpSubnet"
```

## Cross-reference
- **NetworkList-profiles** — per-profile metadata with dates
- **NLA-Signatures-Unmanaged** — non-domain gateway MAC / SSID history
- **Microsoft-Windows-NlaSvc/Operational** EVTX — events 4001 / 4002

## Practice hint
On a domain-joined laptop: connect to corporate WiFi, let NLA detect the domain network. Inspect `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache\Intranet` — the domain's AD FQDN appears. Disconnect, connect to another domain (if available). The new intranet FQDN joins the cache. Historical entries accumulate indefinitely — this is the persistence property that makes the key forensically useful.
