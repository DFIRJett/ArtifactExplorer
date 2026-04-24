---
name: NetworkProfile-10000
title-description: Network connection
aliases:
- network connected
- NLA profile change
link: network
tags:
- per-interface
- network-history
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-NetworkProfile/Operational
platform:
  windows:
    min: '8'
    max: '11'
location:
  channel: Microsoft-Windows-NetworkProfile/Operational
  event-id: 10000
  provider: Microsoft-Windows-NetworkProfile
fields:
- name: Name
  kind: label
  location: EventData → Name
  note: network profile name — SSID for WiFi, 'Network N' for Ethernet, domain name for domain profiles
- name: Category
  kind: flag
  location: EventData → Category
  note: 0=Public, 1=Private, 2=Domain — firewall scope driver
- name: Description
  kind: label
  location: EventData → Description
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
  references-data:
  - concept: FILETIME100ns
    role: absoluteTimestamp
observations:
- proposition: NETWORK_CONNECTED
  ceiling: C3
  note: Host joined a network (wired or wireless). Pairs with NetworkProfile-10001 (disconnected) to bound network-presence windows. Gives authoritative SSID / profile name timeline — critical for geolocation
    and when-was-host-on-which-network questions.
  qualifier-map:
    object.network.name: field:Name
    object.network.category: field:Category
    time.connected: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance:
- ms-network-list-service-and-the-signat
- regripper-plugins
---

# NetworkProfile-10000

## Forensic value
Host network-connect event. Records the SSID (or Ethernet / domain profile name) and category (Public/Private/Domain) at join time. Combined with 10001 (disconnect), reconstructs the full "when was this laptop on which network" timeline.

## Cross-references
- **NetworkList-profiles** — registry catalog of the same profiles with richer metadata (gateway MAC, first-connect)
- **DHCP-Client-log** — lease events for the same connection
- **SRUM-NetworkConnections** — SRUDB's own connection log
