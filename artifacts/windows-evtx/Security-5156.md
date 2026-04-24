---
name: Security-5156
title-description: "Windows Filtering Platform has permitted a connection"
aliases:
- WFP connection permitted
- 5156
link: network
link-secondary: application
tags:
- connection-audit
- per-connection
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  channel: Security
  event-id: 5156
  provider: "Microsoft-Windows-Security-Auditing"
  addressing: evtx-record
  note: "Fires once per connection PERMITTED by Windows Filtering Platform (underlying framework for Windows Firewall + third-party filter drivers). Extremely high-volume on hosts with 'Audit Filtering Platform Connection' enabled — tens to hundreds of thousands per day on a server. Typically enabled only on specific forensic / SOC hosts. Delivers per-connection evidence: source IP/port, destination IP/port, protocol, process ID, application path, direction, layer GUID. Combined with Firewall rule-change events, provides the 'rule was changed then this traffic matched the new rule' observability."
fields:
- name: process-id
  kind: identifier
  location: "event data → ProcessID"
  encoding: uint32 (decimal string)
  references-data:
  - concept: ProcessId
    role: actingProcess
  note: "PID of the process whose connection was permitted. Joins to Security-4688 NewProcessId / Sysmon-1 ProcessId for process attribution. Key join-field for the authentication-to-network-effect chain."
- name: application
  kind: path
  location: "event data → Application"
  encoding: utf-16le (NT kernel path, e.g., \\device\\harddiskvolume3\\...\\binary.exe)
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: "Kernel-format path of the executable initiating / receiving the connection. Requires drive-letter translation (via GetFinalPathNameByHandle or mapping against MountedDevices). Prefetch / Amcache lookup by filename provides execution-evidence context."
- name: source-address
  kind: identifier
  location: "event data → SourceAddress"
  encoding: IPv4 / IPv6 text
  references-data:
  - concept: IPAddress
    role: authSourceIp
  note: "Source IP of the connection. For outbound (direction=0) from this host, equals this host's IP. For inbound (direction=1), equals the remote peer's IP."
- name: source-port
  kind: identifier
  location: "event data → SourcePort"
  encoding: uint16 (decimal string)
  note: "Source port. Ephemeral for outbound client sockets; service port for inbound."
- name: destination-address
  kind: identifier
  location: "event data → DestAddress"
  encoding: IPv4 / IPv6 text
  references-data:
  - concept: IPAddress
    role: destinationIp
  note: "Destination IP. For outbound = remote peer; for inbound = this host."
- name: destination-port
  kind: identifier
  location: "event data → DestPort"
  encoding: uint16
  note: "Destination port."
- name: protocol
  kind: enum
  location: "event data → Protocol"
  encoding: IANA protocol number (6=TCP, 17=UDP, 1=ICMP)
  note: "Transport protocol. Combined with ports identifies the service being accessed (80=HTTP, 443=HTTPS, 445=SMB, 3389=RDP, 88=Kerberos)."
- name: direction
  kind: flags
  location: "event data → Direction"
  encoding: 0=outbound (%%14592) / 1=inbound (%%14593)
  note: "Connection direction relative to this host. Attacker connections to C2 = outbound; attacker inbound pivot = inbound."
- name: layer-name
  kind: label
  location: "event data → LayerName + LayerRTID"
  encoding: WFP layer identifier
  note: "Which WFP layer filtered the connection. Most common: 'Application Layer Enforcement IPv4 Send/Recv' (%%14611/14610). Differs for SMB / named pipes / Kerberos / other sub-layers."
- name: subject-logon-id
  kind: identifier
  location: "event data → subject LogonId (when present)"
  encoding: hex LUID
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: "Logon session the connecting process belongs to. Joins back to Security-4624 TargetLogonId — completes the user→process→connection chain."
- name: event-time
  kind: timestamp
  location: "System/TimeCreated → SystemTime"
  encoding: xs:dateTime UTC
  clock: system
  resolution: 1ms
  note: "Event record time. Per-connection precision — high-volume data supporting timeline reconstruction of every network connection."
observations:
- proposition: COMMUNICATED
  ceiling: C4
  note: 'Security-5156 is the per-connection success record from Windows
    Filtering Platform. When Audit Filtering Platform Connection is
    enabled, EVERY permitted network connection generates an event —
    complete source/destination/port/protocol/process coverage
    independent of Sysmon-3. For the authentication-to-firewall-
    tamper chain: after a rule change is detected, 5156 events post-
    dating the change that match the new rule''s scope are direct
    evidence the rule had enforcement effect. Also primary network-
    attribution source when Sysmon-3 is not deployed or has rolled.'
  qualifier-map:
    direction: bidirectional
    peer.ip: field:destination-address
    actor.process: field:process-id
    time.start: field:event-time
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: EVTX-level
  known-cleaners:
  - tool: "wevtutil cl Security + disable Audit Filtering Platform Connection"
    typically-removes: both current log + prospective logging
  survival-signals:
  - 5156 events post-dating firewall rule change that match the rule's scope = rule had enforcement effect
  - 5156 outbound to attacker-IP with process=attacker-binary = C2 traffic captured
  - Absence of expected 5156 during known-active period = 'Audit Filtering Platform Connection' disabled (likely intentional)
provenance: [ms-event-5156, mitre-t1071]
---

# Security-5156 — Filtering Platform Connection Permitted

## Forensic value
Security-5156 fires once per connection permitted by Windows Filtering Platform — the kernel-level framework behind Windows Firewall. When the "Audit Filtering Platform Connection" subcategory is enabled, EVERY network connection generates a record with:

- Source IP / port
- Destination IP / port
- Protocol
- ProcessId + Application (kernel path)
- Direction (inbound / outbound)
- LayerName (WFP sublayer)

High-volume — tens to hundreds of thousands per day on active hosts. Typically enabled only on forensic-grade hosts or specific SOC monitoring boxes.

## Use in the authentication-to-firewall-tamper chain
When a firewall rule is added (Firewall-2004 event), subsequent 5156 events whose fields match the new rule's scope (port/IP/protocol) prove the rule had network-enforcement effect. ProcessId + SubjectLogonId join back to Security-4688 and Security-4624 for full chain attribution.

## Concept references
- ProcessId, IPAddress, ExecutablePath, LogonSessionId

## Triage
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5156} -MaxEvents 1000 |
    ForEach-Object {
        $x = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time        = $_.TimeCreated
            PID         = ($x.Event.EventData.Data | ? Name -eq 'ProcessID').'#text'
            App         = ($x.Event.EventData.Data | ? Name -eq 'Application').'#text'
            Src         = ($x.Event.EventData.Data | ? Name -eq 'SourceAddress').'#text'
            SrcPort     = ($x.Event.EventData.Data | ? Name -eq 'SourcePort').'#text'
            Dst         = ($x.Event.EventData.Data | ? Name -eq 'DestAddress').'#text'
            DstPort     = ($x.Event.EventData.Data | ? Name -eq 'DestPort').'#text'
            Protocol    = ($x.Event.EventData.Data | ? Name -eq 'Protocol').'#text'
            Direction   = ($x.Event.EventData.Data | ? Name -eq 'Direction').'#text'
        }
    } | Format-Table -AutoSize
```

## Cross-reference
- **Security-4688** — ProcessId join for process-context
- **Security-4624** — LogonID join for session-context
- **Firewall-2004 / 2005 / 2006** — rule-change events preceding 5156 matching the rule
- **Sysmon-3** — alternate network-connection source
- **firewall-log** (pfirewall.log) — text-format sibling
