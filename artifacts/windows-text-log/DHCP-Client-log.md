---
name: DHCP-Client-log
aliases: [DHCP client event log, DHCP lease history]
link: network
tags: [per-interface, network-history]
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: "Microsoft-Windows-Dhcp-Client%4Operational.evtx — cross-ref"
platform:
  windows: {min: Vista, max: '11'}
location:
  path: "Primary: Microsoft-Windows-Dhcp-Client/Operational (evtx). Legacy text log: %WINDIR%\\System32\\LogFiles\\DHCPSRVLOG* on servers"
  addressing: filesystem-path
fields:
- name: lease-event
  kind: record
  location: evtx event ID 50066 / 50067 (DHCPv4) or text-log line on servers
  note: "modern Windows records lease assign/renew/release in the evtx channel; the text-log form primarily applies to Windows DHCP SERVER role"
- name: ip-address
  kind: address
  location: event 50066 EventData → Address
  references-data:
  - {concept: IPAddress, role: resolvedIp}
- name: mac-address
  kind: identifier
  location: event 50066 EventData → HWAddress
  note: "client MAC — complements NetworkList-profiles GatewayMac for same-network attribution"
- name: lease-obtained
  kind: timestamp
  location: event 50066 System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: DHCP_ASSIGNMENT
  ceiling: C3
  note: "Records the IP address the machine held at a given time. Critical for reconciling host IP-timeline against server-side logs (firewall, proxy, IDS)."
  qualifier-map:
    object.ip.address: field:ip-address
    object.mac: field:mac-address
    time.assigned: field:lease-obtained
anti-forensic:
  write-privilege: service
provenance: []
provenance: [kape-files-repo]
---

# DHCP-Client-log

## Forensic value
Records every lease assignment the host received. Host had IP `10.0.0.47` between T1 and T2 — a fact essential when firewall logs elsewhere say "10.0.0.47 did X at T1.5" and you need to confirm the mapping.

Note: on modern Windows clients, the primary source is the Microsoft-Windows-Dhcp-Client/Operational evtx channel (event 50066 lease obtained, 50067 released). Text-format DHCP logs on `%WINDIR%\System32\LogFiles\` apply chiefly to DHCP Server role installs, not clients.

## Cross-references
- **NetworkList-profiles** — WiFi/Ethernet profile catalog with gateway MAC
- **NetworkProfile-10000** — evtx network-connected event
