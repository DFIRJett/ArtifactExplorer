---
name: NLA-Signatures-Unmanaged
title-description: "Network List Manager Signatures\\Unmanaged — default-gateway MAC + SSID for every unmanaged network"
aliases:
- NLA Unmanaged
- NetworkList Signatures Unmanaged
- unmanaged network signatures
link: network
tags:
- network-history
- rogue-ap-trace
- itm:IF
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
  path: "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged"
  sibling: "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed (domain-joined)"
  addressing: hive+key-path
  note: "Network List Manager records a signature subkey for every unique network the host has connected to that is NOT a domain-joined (Managed) network. Each subkey holds the default gateway MAC address, first / last connected time, and cross-references to a Profile (NetworkList-profiles). Combined with Wireless SSID data, this gives a complete history of every WiFi access point and every home / public / hotel / venue network this host has ever connected to."
fields:
- name: default-gateway-mac
  kind: identifier
  location: "Signatures\\Unmanaged\\<signature-guid>\\DefaultGatewayMac value"
  type: REG_BINARY
  encoding: 6-byte MAC address
  note: "MAC address of the default gateway for this unmanaged network. Because gateway MACs are (practically) globally unique and because home routers / AP vendors use predictable OUI prefixes, this MAC identifies a SPECIFIC physical router. Cross-reference against macaddress.io / Wireshark OUI database to attribute the router vendor. For investigations involving rogue APs, this is the single most valuable field — the MAC doesn't change even if the SSID is spoofed."
- name: first-network-ssid
  kind: label
  location: "Signatures\\Unmanaged\\<signature-guid>\\FirstNetwork value"
  type: REG_SZ
  encoding: utf-16le
  note: "The network name (SSID for WiFi, or wired-network identifier). An attacker-set SSID is intentionally suggestive ('Verizon-ABCD', 'Starbucks', 'att-wifi') to social-engineer association — investigate patterns of SSIDs that don't match the victim's known networks."
- name: description
  kind: label
  location: "Signatures\\Unmanaged\\<signature-guid>\\Description value"
  type: REG_SZ
  note: "Human-readable description as shown in the Network-and-Sharing-Center UI. Typically matches or extends FirstNetwork with metadata like 'Wi-Fi' or 'Ethernet'."
- name: profile-guid
  kind: identifier
  location: "Signatures\\Unmanaged\\<signature-guid>\\ProfileGuid value"
  type: REG_SZ
  encoding: guid-string
  note: "Join key to NetworkList\\Profiles\\<profile-guid>. Profiles hold additional metadata (NameType, Category, ProfileName, DateCreated, DateLastConnected). Always read together with the sibling Profiles subkey for full context."
- name: source
  kind: flags
  location: "Signatures\\Unmanaged\\<signature-guid>\\Source value"
  type: REG_DWORD
  note: "6 = DHCP learned; 8 = Manual; other values per Microsoft documentation. Distinguishes auto-acquired networks (DHCP-configured home / public) from manually-configured networks (often VPN or statically-assigned test environments)."
- name: date-created
  kind: timestamp
  location: "NetworkList\\Profiles\\<profile-guid>\\DateCreated value"
  type: REG_BINARY
  encoding: 16-byte custom (year/month/dayofweek/day/hour/minute/second/milliseconds)
  clock: system
  resolution: 1ms
  note: "First time this network was connected from this host. Binary 16-byte format (not FILETIME). Parsed as: (uint16 Year)(uint16 Month)(uint16 DayOfWeek)(uint16 Day)(uint16 Hour)(uint16 Minute)(uint16 Second)(uint16 Millisecond)."
- name: date-last-connected
  kind: timestamp
  location: "NetworkList\\Profiles\\<profile-guid>\\DateLastConnected value"
  type: REG_BINARY
  encoding: 16-byte custom (same format as DateCreated)
  clock: system
  resolution: 1ms
  note: "Most recent connection to this network. Pair with DateCreated for connection-window duration. A network with DateCreated = DateLastConnected = single-use (drove past once); repeated connections indicate a familiar network (home, office, regular venue)."
- name: key-last-write
  kind: timestamp
  location: Signatures\Unmanaged\<signature-guid> subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on the signature subkey — typically close to DateLastConnected but independently-sourced. Cross-reference for tamper detection."
observations:
- proposition: COMMUNICATED
  ceiling: C4
  note: 'The Signatures\\Unmanaged key is the most complete WiFi / non-
    domain network connection history on Windows. Every previous
    connection — home WiFi, hotel, airport, coffee shop, conference,
    public venue — persists here with gateway MAC, SSID, and first /
    last connection times. Used to: trace a host''s physical movement
    across locations; identify rogue-AP connections (attacker-
    operated APs named to impersonate legitimate networks); place a
    compromised host at a specific location at a specific time. On
    investigations involving lateral movement via unmanaged networks
    (attacker device that was briefly on the target''s home network)
    this registry is the pivot that locates the attacker device.'
  qualifier-map:
    peer.address: field:default-gateway-mac
    peer.name: field:first-network-ssid
    time.start: field:date-created
    time.end: field:date-last-connected
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: none
  known-cleaners:
  - tool: netsh wlan delete profile name=<SSID>
    typically-removes: the Profile subkey (and through cascade, the Signature entry). Leaves LastWrite on the parent Signatures\\Unmanaged key as residue.
  - tool: direct registry delete of Signatures\\Unmanaged\\<guid>
    typically-removes: specific network-history entry
  survival-signals:
  - Signatures\\Unmanaged entries with DateLastConnected matching incident window and SSIDs that don't match the user's documented network list = candidate rogue-AP or travel-network exposure
  - DefaultGatewayMac with OUI prefix matching suspicious vendors (pentesting hardware — WiFi Pineapple, Alfa adapters) = strong rogue-AP indicator
  - Repeated unique Signatures entries in short time window = host was in a mobility scenario (travel, walking-by probes); normal pattern is stable set of frequent networks
provenance:
  - ms-network-list-service-and-the-signat
---

# NetworkList Signatures\Unmanaged (WiFi / non-domain connection history)

## Forensic value
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\<signature-guid>` holds one subkey per unique **unmanaged** (non-domain-joined) network the host has ever connected to. Each signature records:

- `DefaultGatewayMac` — MAC address of the network's default gateway (physical-router identifier)
- `FirstNetwork` — the SSID for WiFi, or the wired network identifier
- `ProfileGuid` — join-key to NetworkList\Profiles\<guid> for connection times + description

Companion key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\<profile-guid>` holds:
- `DateCreated` — first connection (16-byte binary timestamp)
- `DateLastConnected` — most recent connection
- `Description` — human-readable network name
- `Category` — 0=Public, 1=Private, 2=Domain-authenticated

ALWAYS parse both keys together. The existing `NetworkList-profiles` artifact covers the Profiles side; **this artifact covers the Signatures\Unmanaged side which holds the gateway MAC and SSID attribution** that Profiles alone does not surface.

## Why MAC matters more than SSID
SSIDs can be spoofed (attacker-run AP named "HomeWifi" to impersonate the victim's home network). Default gateway MACs are globally unique per physical device. If the DefaultGatewayMac on a Signatures entry does not match the expected home-router MAC, the SSID was spoofed — the user thought they were on their home network but actually connected to an attacker AP.

## Concept references
- None direct (MAC address is not a modeled concept in this graph; IPAddress-like but distinct)

## Triage
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged" /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" /s
```

Join each Signatures\\<guid>\\ProfileGuid against Profiles\\<guid> for connection times.

## Binary timestamp decode
Profiles DateCreated / DateLastConnected are 16 bytes:
```
offset 0: uint16 Year
offset 2: uint16 Month
offset 4: uint16 DayOfWeek
offset 6: uint16 Day
offset 8: uint16 Hour
offset 10: uint16 Minute
offset 12: uint16 Second
offset 14: uint16 Millisecond
```
All little-endian. NOT a FILETIME — don't try to parse as one.

## Cross-reference
- **NetworkList-profiles** artifact — sibling Profiles data
- **Microsoft-Windows-NlaSvc/Operational** EVTX channel — per-connection telemetry
- **Microsoft-Windows-WLAN-AutoConfig/Operational** — WiFi-specific association / disassociation events
- **Event ID 8001** (WLAN successful association) / **8002** (failure) — correlate SSID + time
- **Wireless MAC address randomization** registry (HKLM\SYSTEM\...Microsoft\WlanSvc\Parameters\MACRandomizationType) — enterprise settings that may affect Signatures persistence

## Practice hint
On a Windows 11 laptop, connect to a few different WiFi networks (home, phone hotspot, cafe). Open Registry Editor at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged`. Each connection produces a new GUID subkey. Cross-reference DefaultGatewayMac against your phone's hotspot MAC (from the phone's network settings) and the cafe's router MAC (arp-cached during connection) — they will match the binary values exactly.
