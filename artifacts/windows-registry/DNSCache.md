---
name: DNSCache
aliases:
- DNS resolver cache
- dnscache
- Windows DNS client cache
link: network
tags:
- timestamp-carrying
- volatile
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: '2000'
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  live-access: Get-DnsClientCache  /  ipconfig /displaydns  (live system — runtime cache, not registry-persistent)
  registry-persistence-area: SYSTEM\CurrentControlSet\Services\Dnscache\Parameters (config only, not cache entries)
  addressing: runtime resolver state — capture via live tools or memory
  note: unlike most registry artifacts, DNS cache is primarily in-memory; registry path here is for the CONFIG of the cache
    service
fields:
- name: hostname
  kind: identifier
  location: cache entry name (live-query output)
  encoding: ascii
  references-data:
  - concept: DomainName
    role: dnsResolvedName
- name: resolved-ip
  kind: identifier
  location: cache entry IP field
  encoding: IPv4 or IPv6 address string
- name: record-type
  kind: enum
  location: entry type code
  encoding: A, AAAA, CNAME, PTR, etc.
- name: ttl-remaining
  kind: counter
  location: entry TTL field
  encoding: uint32
  note: seconds remaining before cache expiry; 0 = just-resolved or permanently cached
- name: cache-observed-timestamp
  kind: timestamp
  location: observation time (at acquisition)
  encoding: examiner-set; not preserved in cache itself
  clock: system
  resolution: 1s
  note: DNS cache entries don't carry the query timestamp directly; examiner must record when they captured the state
observations:
- proposition: CONNECTED
  ceiling: C2
  note: 'Presence of a hostname in DNS cache proves the system RESOLVED that

    name recently (within TTL). Does NOT prove a TCP connection followed

    — name resolution can happen speculatively or from browser prefetch.

    Corroborate with firewall/proxy logs to upgrade to actual connection.

    '
  qualifier-map:
    peer.hostname: field:hostname
    peer.ip: field:resolved-ip
    time.start: field:cache-observed-timestamp
  preconditions:
  - live-system acquisition OR memory dump with dnscache service state
  - cache flushed by reboot; acquire before restart
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: none
  known-cleaners:
  - tool: ipconfig /flushdns
    typically-removes: full
    note: trivial; no audit trail
  - tool: system reboot
    typically-removes: full
  survival-signals:
  - DNS cache contains domains present in browser history but NOT in firewall logs = possibly speculative DNS lookup not followed
    by connection; OR firewall logging was off
  - DNS cache flushed within last minute + suspicious browser activity = deliberate evidence destruction
provenance:
  - ms-name-resolution-policy-table-nrpt-r
---

# Windows DNS Resolver Cache

## Forensic value
Runtime cache of recently-resolved hostnames. Each entry: hostname + resolved IP + record type + TTL remaining. Lives in the Dnscache service's memory — not persistently written to registry.

Highly volatile: `ipconfig /flushdns` clears it instantly, reboots destroy it, and entries age out on their TTL (often 5 minutes to a few hours). Forensically, DNS cache is **live-system evidence or memory-dump evidence only** — an offline hive analysis gives you nothing from DNS cache.

## Concept reference
- DomainName (hostname)

## Known quirks
- **Not registry-persistent.** Don't look for cache entries in the registry — only the cache service's configuration lives there. Live-capture via `Get-DnsClientCache` (PowerShell) or `ipconfig /displaydns` (cmd), or extract from memory.
- **TTLs can be very short.** A hostname resolved 10 minutes ago may already be gone from the cache. Low-TTL names (common for CDN-fronted services) disappear fastest.
- **Negative entries.** The cache also stores "NAME NOT FOUND" responses with a negative TTL — useful to detect attempted-but-failed resolutions.
- **Browser DNS caches are separate.** Chromium maintains its own internal DNS cache on top of the OS cache; acquire browser internals separately (Chrome's `chrome://net-internals/#dns`).

## Acquisition
- Live system: `Get-DnsClientCache | Export-Csv dns-cache.csv` (PowerShell — Windows 8+)
- Legacy: `ipconfig /displaydns > dns-cache.txt`
- Memory dump: Volatility plugin `windows.dnscache` (or `linux.dnscache` equivalent)

## Practice hint
On your test system, visit a few websites in a browser. Within a minute, run `Get-DnsClientCache` — every site's hostname should appear. Wait 10+ minutes or reboot — they evaporate. The volatility is the lesson: for any investigation, DNS cache must be acquired ASAP.
