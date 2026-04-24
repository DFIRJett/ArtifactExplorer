---
name: SRUM-NetworkUsage
aliases:
- SRUDB NetworkUsage table
- per-process bytes transferred
link: network
tags:
- system-wide
- tamper-hard
- time-limited-retention
volatility: persistent
interaction-required: none
substrate: windows-ess
substrate-instance: SRUDB.dat
platform:
  windows:
    min: '8'
    max: '11'
location:
  path: "%WINDIR%\\System32\\sru\\SRUDB.dat"
  table-guid: "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
  addressing: ese-table-row
fields:
- name: AutoIncId
  kind: identifier
  location: table → AutoIncId
- name: TimeStamp
  kind: timestamp
  location: table → TimeStamp
  encoding: filetime-le (OLE-automation-date in some parsers)
  clock: system
  resolution: 1 hour (aggregation interval)
- name: AppId
  kind: path
  location: table → AppId (joined to SruDbIdMapTable)
  note: full executable path of the process that transferred bytes
  references-data:
  - concept: ExecutablePath
    role: actingProcess
- name: UserId
  kind: identifier
  location: table → UserId (joined to SruDbIdMapTable)
  note: SID that owned the process
  references-data:
  - concept: UserSID
    role: actingUser
- name: InterfaceLuid
  kind: identifier
  location: table → InterfaceLuid
  note: Locally-Unique-ID of the network interface — maps to the interface GUID in NetworkList-profiles
- name: L2ProfileId
  kind: identifier
  location: table → L2ProfileId
  note: joins to SRUM-NetworkConnections table by L2ProfileId — yields the SSID/profile name the traffic rode on
- name: BytesSent
  kind: counter
  location: table → BytesSent
  type: uint64
- name: BytesRecvd
  kind: counter
  location: table → BytesRecvd
  type: uint64
observations:
- proposition: NETWORK_USAGE
  ceiling: C3
  note: Per-process bytes transferred per network interface per user per hour-window. Survives process termination. Retention ~30-60 days.
  qualifier-map:
    actor.process: field:AppId
    actor.user: field:UserId
    object.network.interface: field:InterfaceLuid
    object.bytes.sent: field:BytesSent
    object.bytes.recvd: field:BytesRecvd
    time.observed: field:TimeStamp
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - tool: Diagnostic Data viewer / Clear Activity History
    typically-removes: does NOT affect SRUM
  - tool: delete %WINDIR%\System32\sru\*.* (requires SYSTEM + service stop)
    typically-removes: full
provenance:
  - libyal-libesedb
  - khatri-srum-dump
---

# SRUM-NetworkUsage

## Forensic value
The System Resource Usage Monitor records **bytes sent and received per process per user per network interface per ~1-hour time window**. Given a SRUM DB with 30 days of retention, you can answer:

- "Did process X ever exfiltrate data through this interface?" — non-zero BytesSent attributable to a specific AppId
- "What was the busiest outbound hour?" — aggregate BytesSent by TimeStamp
- "Which user launched a heavy-network process?" — join to UserId
- "Was this traffic on the corporate WiFi or the hotel network?" — join to L2ProfileId → SRUM-NetworkConnections → profile name

Distinct from firewall logs or Sysmon-3:
- **Sysmon-3** captures individual connection events (no byte totals, no aggregation)
- **firewall-log** captures allowed/denied decisions (byte counts only for some event types, often off)
- **SRUM-NetworkUsage** captures the cumulative byte totals **regardless of logging config**

## Retention
Typical SRUM retention is 30-60 days depending on disk pressure. Busy endpoints may rotate faster. Acquire early; the hour-level granularity degrades as older windows coalesce.

## Table joins
SRUM is highly normalized. Parsing requires joins:
- **AppId / UserId** → `SruDbIdMapTable` (IdType=0 is App-path, IdType=2 is SID)
- **L2ProfileId** → SRUM-NetworkConnections table → profile metadata → SSID

`srum-dump` (Mark Baggett) + the supplied Windows.edb template automates these joins to a CSV/XLSX per-table export.

## Cross-references
- **NetworkList-profiles** — registry-based WiFi profile catalog; maps L2ProfileId to SSID
- **SRUM-Process** — sibling table with CPU/focus/foreground time for the same AppId/UserId
- **SRUM-ApplicationResource** — finer per-app resource attribution
- **SRUM-NetworkConnections** — connection events (connect/disconnect, profile change)

## Practice hint
```
srum_dump.exe --SRUM_INFILE SRUDB.dat --OUT_DIR .\out --TEMPLATE SRUM_TEMPLATE.xlsx
```
Open the resulting NetworkUsage sheet. Sort by BytesSent descending; anomalies are usually obvious (a lone spike from a non-browser process, unusual dwarfing of normal usage, a short window of massive egress).
