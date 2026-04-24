---
name: NetworkList-profiles
aliases:
- NetworkList
- WLAN profiles
- wired profiles
- known-networks
link: network
tags:
- timestamp-carrying
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: Vista
    max: '11'
location:
  hive: SOFTWARE
  path: Microsoft\Windows NT\CurrentVersion\NetworkList
  sub-paths:
    signatures: NetworkList\Signatures\Managed  +  Signatures\Unmanaged
    profiles: NetworkList\Profiles\{GUID}
  addressing: hive+key-path
fields:
- name: profile-guid
  kind: identifier
  location: '{GUID} subkey name under Profiles\'
  encoding: guid-string
- name: profile-name
  kind: identifier
  location: Profiles\{GUID}\ProfileName value
  type: REG_SZ
  encoding: utf-16le
  note: the SSID for Wi-Fi profiles; a friendly name for Ethernet
- name: description
  kind: identifier
  location: Profiles\{GUID}\Description value
  type: REG_SZ
- name: category
  kind: enum
  location: Profiles\{GUID}\Category value
  type: REG_DWORD
  note: 0=public, 1=private, 2=domain
- name: managed
  kind: flags
  location: Profiles\{GUID}\Managed value
  type: REG_DWORD
- name: date-created
  kind: timestamp
  location: Profiles\{GUID}\DateCreated value
  encoding: 16-byte SYSTEMTIME structure
  clock: system
  resolution: 1ms
- name: date-last-connected
  kind: timestamp
  location: Profiles\{GUID}\DateLastConnected value
  encoding: 16-byte SYSTEMTIME structure
  clock: system
  resolution: 1ms
- name: default-gateway-mac
  kind: identifier
  location: Signatures\Managed or Unmanaged\<signature>\DefaultGatewayMac value
  type: REG_BINARY
  encoding: 6-byte MAC address
  note: the gateway MAC — used by Windows to recognize a network; survives even after profile rename
- name: dns-suffix
  kind: identifier
  location: Signatures\...\DnsSuffix value
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: DomainName
    role: networkProfileDnsSuffix
- name: first-network
  kind: identifier
  location: Signatures\...\FirstNetwork value
  type: REG_SZ
  encoding: utf-16le
observations:
- proposition: CONNECTED
  ceiling: C3
  note: 'Every network this system has connected to (Wi-Fi SSID, Ethernet

    LAN signature, domain network) leaves a Profile entry. Captures

    date-created (first-seen) and date-last-connected per network.

    Powerful for ''where has this laptop been'' questions.

    '
  qualifier-map:
    peer.network-name: field:profile-name
    peer.gateway-mac: field:default-gateway-mac
    peer.dns-suffix: field:dns-suffix
    time.start: field:date-created
    time.end: field:date-last-connected
anti-forensic:
  write-privilege: admin
  known-cleaners:
  - tool: Settings > Network > Manage known networks > Forget
    typically-removes: full
    note: UI-level profile forget removes the subkey
  - tool: netsh wlan delete profile name=<SSID>
    typically-removes: full (Wi-Fi only)
provenance:
- ms-network-list-service-and-the-signat
- regripper-plugins
---

# NetworkList Profiles

## Forensic value
Windows' registry of every network the system has connected to. Wi-Fi SSIDs, Ethernet LAN signatures, VPN profiles. Each profile records category (public/private/domain), first-seen date, and last-connected date.

Investigative value is travel/location inference: a laptop's NetworkList tells you where it's been connected — home Wi-Fi, airport Wi-Fi, corporate LAN, etc. Combined with gateway MAC (rarely randomized for enterprise networks), identifies specific networks unambiguously.

## Concept reference
- DomainName (DnsSuffix field)

## Known quirks
- **SYSTEMTIME encoding** for the two timestamps — different from FILETIME; 16-byte structure with yyyy/mm/dd/hh/mm/ss/ms fields. Parser must handle both formats.
- **Profile GUID is opaque.** Cross-reference ProfileName + DefaultGatewayMac between Profiles\ and Signatures\ subkeys to get the full picture.
- **Date-created doesn't update on reconnect.** It's the first-ever-connected date. Date-last-connected is the reconnect tracker.

## Practice hint
On a Windows laptop that's traveled: `reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList" networks.reg`. Parse the Profiles subkeys — each SSID is one profile. Chronologically sort by date-created to reconstruct the laptop's "connection history" back to first Windows install.
