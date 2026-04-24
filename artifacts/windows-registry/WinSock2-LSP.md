---
name: WinSock2-LSP
title-description: "Winsock 2 Layered Service Provider catalog — DLLs injected into every network-connected process"
aliases:
- WinSock LSP
- Layered Service Provider
- LSP catalog
- Winsock Service Provider Interface
link: persistence
tags:
- persistence-primary
- network-hijack
- itm:ME
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: NT5.0
    max: '11'
    note: "LSP is a legacy Winsock-2 extension mechanism. Microsoft formally deprecated third-party LSP development starting with Win8 (in favor of WFP — Windows Filtering Platform) but the catalog is still read and LSPs still load into any process that uses WinSock."
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SYSTEM
  path-32bit: "CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9"
  path-64bit: "CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog_64"
  path-namespace: "CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5 / NameSpace_Catalog_64"
  addressing: hive+key-path
  note: "Four sibling catalogs — one protocol catalog and one namespace catalog per architecture (32-bit, 64-bit). Protocol_Catalog holds transport-service providers (socket()-level hooks); NameSpace_Catalog holds name-resolution providers (gethostbyname-level hooks). On 64-bit Windows BOTH catalogs must be baselined — a 32-bit LSP is loaded into WoW64 processes only."
fields:
- name: provider-path
  kind: path
  location: "Protocol_Catalog9\\Catalog_Entries\\<NNNNNNNN>\\PackedCatalogItem (binary blob) — contains UTF-16LE DLL path at offset"
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Each catalog entry's PackedCatalogItem binary blob embeds the full DLL path of the service provider. Legitimate Windows LSPs point to %SystemRoot%\\System32 (rsvpsp.dll, mswsock.dll). Third-party LSPs used to be common for AV / firewall / parental-controls products — modern equivalents use WFP. A novel LSP DLL path outside System32 and not matching a known security product = network-traffic-intercept persistence."
- name: provider-name
  kind: label
  location: "Protocol_Catalog9\\Catalog_Entries\\<NNNNNNNN>\\ProtocolName"
  type: REG_SZ
  encoding: utf-16le
  note: "Human-readable name of the provider ('MSAFD Tcpip [TCP/IP]'). Stock names are well-known; an unfamiliar ProtocolName is a trivially-visible anomaly."
- name: namespace-provider
  kind: path
  location: "NameSpace_Catalog5\\Catalog_Entries\\<NNNNNNNN>\\LibraryPath"
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Name-service provider DLL (hooks name resolution APIs). Stock Windows has a couple of namespace providers (NLA, NTDS, PNRP). Extra entries = injected into every gethostbyname / GetAddrInfoEx call system-wide."
- name: chain-length
  kind: counter
  location: "Protocol_Catalog9\\Catalog_Entries\\<NNNNNNNN>\\ChainLen"
  type: REG_DWORD
  note: "LSP chain depth. 0 = base provider; 1 = 'layered' provider that sits above a base. An LSP with chain length >0 wraps an existing provider — the common hijack pattern is to insert a layered LSP above a core Winsock provider so that ALL traffic flows through the attacker's DLL."
- name: catalog-count
  kind: counter
  location: "Protocol_Catalog9\\Num_Catalog_Entries"
  type: REG_DWORD
  note: "Total number of entries. Baseline Windows 10/11 has ~30 entries. Substantially higher number = additional providers registered; compare against known-good."
- name: key-last-write
  kind: timestamp
  location: WinSock2\\Parameters key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on the Parameters key updates whenever an LSP is installed / removed. An unexpected LastWrite timestamp = install window for the injected LSP."
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'A Winsock LSP hook loads the attacker DLL into every process
    that makes a network call — browsers, svchost, PowerShell, lsass.
    This makes it one of the highest-privilege persistence mechanisms
    available: single DLL, injected into every network-connecting
    process system-wide, with the ability to read and modify every
    socket stream before it hits the wire. Because modern Windows has
    largely migrated security vendors to WFP, a present-day LSP entry
    pointing to a non-Microsoft DLL should be treated as suspicious by
    default.'
  qualifier-map:
    setting.registry-path: "Services\\WinSock2\\Parameters\\Protocol_Catalog9"
    setting.dll: field:provider-path
    time.start: field:key-last-write
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: none; PackedCatalogItem is not signed
  known-cleaners:
  - tool: netsh winsock reset
    typically-removes: resets catalog to Windows defaults (kills legit third-party LSPs too — visible disruption)
  survival-signals:
  - Provider-path outside System32 that isn't from a known security product = unauthorized LSP
  - Unknown ChainLen>0 entry ordered above core Microsoft providers = layered interception inserted
  - Catalog-count significantly higher than clean-install baseline = unexpected providers registered
provenance:
  - ms-winsock-service-provider-interface
  - mitre-t1574
---

# Winsock 2 LSP Catalog

## Forensic value
A Layered Service Provider (LSP) is a Winsock-2 DLL that hooks socket calls at the userland Winsock layer. Registered entries sit in `HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\`:

- `Protocol_Catalog9` / `Protocol_Catalog_64` — transport providers (per-architecture)
- `NameSpace_Catalog5` / `NameSpace_Catalog_64` — name-resolution providers

When a process calls any Winsock API (socket, send, recv, gethostbyname), the chain of registered LSPs is walked — the attacker-registered DLL loads into that process and sees the traffic. This is a single-config-write persistence with system-wide injection into every network app.

## Modern context
Microsoft deprecated LSPs for security-product use in Windows 8 (directed vendors to WFP — Windows Filtering Platform). Present-day Windows 10/11 installs from Microsoft ship only the core stock providers. Legitimate third-party LSPs are rare; their presence today should be investigated against a known product install rather than assumed benign.

A freshly-registered LSP DLL outside System32 on a modern Windows 11 endpoint with no justifying install event is one of the strongest persistence-hijack signals available.

## Concept reference
- ExecutablePath (one per catalog entry's provider-path and namespace-provider)

## Triage
```cmd
# List the protocol catalog (64-bit view)
netsh winsock show catalog

# Registry-direct approach
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries" /s
```

For each entry, extract the DLL path from PackedCatalogItem (blob at offset ~0x290 inside the value) and validate against known-good.

## Recovery
If an LSP is found malicious: `netsh winsock reset` rolls the catalog to Windows defaults. This also removes any legitimate third-party LSP — document and reinstall those afterward.

## Practice hint
Install Sysinternals Autoruns on a clean Windows 11 VM. The "Winsock Providers" tab lists all current LSP and NSP entries with their backing DLLs and signatures. Compare against a second clean VM to confirm the baseline. Any delta = candidate persistence.
