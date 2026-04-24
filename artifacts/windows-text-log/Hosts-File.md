---
name: Hosts-File
title-description: "Windows hosts and lmhosts files (local name-to-IP resolution override)"
aliases:
- hosts file
- lmhosts
- etc\\hosts on Windows
link: network
tags:
- dns-tamper
- local-resolution-override
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: etc-hosts
platform:
  windows:
    min: NT3.1
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  path-hosts: '%WINDIR%\System32\drivers\etc\hosts'
  path-lmhosts: '%WINDIR%\System32\drivers\etc\lmhosts (optional — .sam template ships default)'
  addressing: file-path
fields:
- name: mapping
  kind: identifier
  location: "each non-comment line in hosts — format: '<ip-address>  <hostname> [alias ...]'"
  encoding: ascii / utf-8
  references-data:
  - concept: IPAddress
    role: resolvedIp
  - concept: DomainName
    role: dnsResolvedName
  note: "The DNS client resolves each hostname against hosts FIRST, before any real DNS query. Attacker-authored mappings redirect name resolution — e.g., pointing security-products' update hosts to 127.0.0.1 blocks AV updates; pointing legitimate domains to attacker IPs hijacks traffic."
- name: lmhosts-mapping
  kind: identifier
  location: "each non-comment line in lmhosts — format: '<ip-address>  <NetBIOS-name> [#PRE | #DOM:<domain> ...]'"
  encoding: ascii / utf-8
  references-data:
  - concept: IPAddress
    role: resolvedIp
  - concept: MachineNetBIOS
    role: trackerMachineId
  note: "NetBIOS-name to IP pre-loading. Largely obsolete on modern Windows with DNS-only resolution, but still honored when NetBIOS-over-TCP/IP is enabled. #PRE entries are pre-cached. An attacker-populated lmhosts can intercept SMB connections by name."
- name: file-mtime
  kind: timestamp
  location: hosts file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS modified time. Default stock hosts file (just comments plus the localhost entries on older Windows) shows an mtime matching the OS install or a Windows Update that touched it. Any mtime outside those windows = edit."
- name: file-size
  kind: counter
  location: hosts file size
  encoding: uint32
  note: "Default stock hosts on Win10/11 is ~824 bytes (comments + empty mapping section). Size > 1 KB on a stock install = entries were added. Security products sometimes legitimately add blocklist entries here (making it massive); cross-reference against the product installed."
- name: comment-text
  kind: content
  location: lines starting with '#'
  encoding: ascii / utf-8
  note: "Stock comments describe the file format and attribution. Attackers sometimes add comments to mask their entries as legitimate. Comment-only diff vs stock = mild signal."
observations:
- proposition: CONFIGURED_RESOLUTION_OVERRIDE
  ceiling: C3
  note: 'hosts / lmhosts tamper is one of the oldest persistence / evasion
    techniques on Windows. Pre-DNS name resolution means any mapping
    here overrides public DNS — even if DNS is hardened or logged, the
    OS never issues the DNS query. Hunt signals: hostnames of AV /
    EDR update endpoints pointed to 127.0.0.1, known-C2 domains
    pointed to attacker-controlled IPs, or sudden size jumps on hosts
    that have no Pi-Hole-style blocklist management.'
  qualifier-map:
    setting.file: field:mapping
    time.start: field:file-mtime
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none — plain text, no signing
  survival-signals:
  - hosts file mtime more recent than the most-recent Windows Update without a corresponding installer event = manual edit
  - non-comment entries mapping known-legitimate domains (windowsupdate.com, microsoft.com, defender update endpoints) to 127.0.0.1 / 0.0.0.0 = AV/update tamper
  - mappings pointing to external IPs for legitimate host names = traffic hijack
  - lmhosts file non-empty on a modern client (should normally be the stock .sam template only) = NetBIOS interception setup
provenance: [ms-tcp-ip-and-nbt-configuration-parame, mitre-t1562, isc-2020-checking-the-hosts-file-as-an]
---

# hosts / lmhosts

## Forensic value
The Windows DNS Client resolves hostnames in this order: hosts file → DNS cache → configured DNS servers. Any entry in `%WINDIR%\System32\drivers\etc\hosts` wins — the OS never issues a DNS query for a hostname that matches. Same pattern for NetBIOS names in lmhosts (when NetBIOS-over-TCP/IP is enabled).

Attack uses:
- **Block AV/EDR updates** — point vendor update hostnames to 127.0.0.1
- **Block Windows Update** — point `*.windowsupdate.com` to 0.0.0.0
- **Hijack traffic** — point a legitimate-looking hostname to an attacker IP for phishing / MITM
- **Block telemetry** — legitimate privacy tools do this; so do actors covering tracks

## Concept references
- IPAddress (per mapping)
- DomainName (per hosts line)
- MachineNetBIOS (per lmhosts line)

## Baseline
Stock Windows 10/11 hosts file contents:
- ~20 lines of comments explaining the format
- Empty mapping section (localhost resolution was moved to the DNS Client service — no literal `127.0.0.1 localhost` line on modern builds)
- File size ≈ 824 bytes

lmhosts file: typically absent; only `lmhosts.sam` (a template) present unless NetBIOS-over-TCP/IP is deliberately configured.

## Triage
```powershell
Get-Content $env:WINDIR\System32\drivers\etc\hosts
(Get-Item $env:WINDIR\System32\drivers\etc\hosts).LastWriteTime
(Get-Item $env:WINDIR\System32\drivers\etc\hosts).Length
Test-Path $env:WINDIR\System32\drivers\etc\lmhosts
```

For an incident, diff current content against the stock baseline for the target OS build.

## Practice hint
Add a harmless mapping like `127.0.0.1 example-fake-host.local` to hosts. From any tool, `ping example-fake-host.local` should resolve to 127.0.0.1 without touching the network. Observe that no DNS query is sent (confirm via `Resolve-DnsName -NoHostsFile` — which *bypasses* hosts and goes straight to DNS).
