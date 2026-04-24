---
name: SRUM-Process
aliases:
- SRUM AppResourceUsage
- System Resource Usage Monitor
- SRUDB process records
link: application
tags:
- timestamp-carrying
volatility: persistent
interaction-required: none
substrate: windows-ess
substrate-instance: SRUDB.dat
platform:
  windows:
    min: '8'
    max: '11'
  windows-server:
    min: '2012'
    max: '2022'
location:
  path: '%WINDIR%\System32\sru\SRUDB.dat'
  table-guid: '{d10ca2fe-6fcf-4f6d-848e-b2e99266fa89}'
  table-alias: AppResourceUsage
  addressing: ess-table-row
fields:
- name: app-id
  kind: path
  location: AppId column
  encoding: string — may be an executable path OR a special form like '!!<SID>!<path>' for per-user scope
  references-data:
  - concept: ExecutablePath
    role: ranProcess
- name: user-sid
  kind: identifier
  location: UserId column (resolves via SruDbIdMapTable)
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: actingUser
- name: timestamp-bucket
  kind: timestamp
  location: TimeStamp column
  encoding: filetime-le
  clock: system
  resolution: 1h
  note: SRUM aggregates in hourly buckets — each row is one (app, user, hour) triplet
- name: foreground-cycle-time
  kind: counter
  location: ForegroundCycleTime column
  encoding: int64
  note: CPU cycle count attributed to foreground activity
- name: background-cycle-time
  kind: counter
  location: BackgroundCycleTime column
  encoding: int64
- name: face-time
  kind: counter
  location: FaceTime column
  encoding: int64
  note: total time the app had visible UI focus (approximate dwell)
- name: bytes-written
  kind: counter
  location: BytesWritten column
  encoding: int64
  note: disk bytes written by this app in this hour — key exfil signal
- name: bytes-read
  kind: counter
  location: BytesRead column
  encoding: int64
- name: foreground-bytes-written
  kind: counter
  location: ForegroundBytesWritten column
  encoding: int64
  note: disk writes while the app was in foreground — distinguishes user-driven activity from background
- name: background-bytes-written
  kind: counter
  location: BackgroundBytesWritten column
  encoding: int64
observations:
- proposition: EXECUTED
  ceiling: C3
  note: 'Presence of a SRUM row for (app, user, hour) proves the process ran

    under that user during that hour, at least to some measurable extent.

    Combined with byte counters, tells you HOW MUCH the process did — a

    unique capability no other artifact provides.

    '
  qualifier-map:
    process.image-path: field:app-id
    actor.user: field:user-sid
    time.start: field:timestamp-bucket
    frequency.count: inferred from row existence; SRUM doesn't store per-run counts
- proposition: COMMUNICATED
  ceiling: C2
  note: 'Via the sibling NetworkUsage table (same SRUDB.dat but different table

    GUID), per-app network bytes sent/received are available. Without the

    join, this artifact supports EXECUTED only; with NetworkUsage joined,

    a bytes-sent-over-network claim becomes possible.

    '
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: ESE transaction logs
  known-cleaners:
  - tool: manual deletion of SRUDB.dat
    typically-removes: full
    note: Windows will recreate on next hourly flush — recreation timestamp tells
  - tool: service-stop + truncate
    typically-removes: full
  survival-signals:
  - SRUM present + Prefetch absent for same executable = selective Prefetch cleanup (rarer because SRUM is less well-known)
  - AppResourceUsage bytes-written matches size of a known exfiltrated file during a USB-connected window = strong circumstantial
    exfil signal (see topics/data-exfiltration-usb-storage-device.md §D)
provenance:
  - libyal-libesedb
  - khatri-srum-dump
---

# SRUM — AppResourceUsage (per-process resource ledger)

## Forensic value
Unique among execution artifacts: records **how much each process did**, not just that it ran. Hourly-bucket rows per (app, user, hour) with cycle time + bytes-written-to-disk + bytes-read-from-disk + foreground/background split.

For exfiltration investigations, SRUM's bytes counters are sometimes the only evidence quantifying data movement on a host without active network monitoring. A `powershell.exe` that wrote 4 GB to disk in an hour while a USB was plugged in is forensically interesting in a way no other artifact captures.

## Two concept references
- ExecutablePath (via AppId column)
- UserSID (via UserId column, resolved through SruDbIdMapTable)

## Sibling tables in the same SRUDB.dat
- **NetworkConnectivity** (`{973f5d5c-...}`) — per-interface connection state
- **NetworkUsage** (`{d10ca2fe-6fcf-4f6d-848e-b2e99266fa86}`) — per-app network bytes sent/received (COMMUNICATED evidence)
- **AppHistory** — legacy summarized usage
- **EnergyUsage** — battery consumption per app
- **PushNotification** — notification event counts

These are separate artifacts within the same substrate-instance. A full SRUM analysis joins across them.

## Known quirks
- **Hourly buckets round timestamps.** SRUM doesn't give minute-by-minute — bucket-start hour only.
- **AppId column is compound.** Sometimes a clean path, sometimes a `!!<SID>!<path>` form that encodes user scope inline. Parsers must handle both.
- **UserId is not the SID directly** — it's an ID into SruDbIdMapTable. Must join to resolve to a SID.
- **Rows can be coalesced / truncated.** SRUM has retention limits; older entries drop off.
- **ESE dirty-state issues.** See `substrates/windows-ess.md` — replay transaction logs on a copy before querying.

## Practice hint
Acquire SRUDB.dat from a test Win10 VM (service-stop + copy, or VSS). Parse with SrumECmd. Find a PowerShell-running hour — observe bytes-written totals. Correlate with Prefetch's last-run time for the same executable.
