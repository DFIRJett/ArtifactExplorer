---
name: Setupapi-Upgrade-Log
title-description: "setupapi.upgrade.log — device / driver events recorded during Windows in-place upgrades (Win10+)"
aliases:
- setupapi upgrade log
- setupapi.upgrade.log
- Windows upgrade device log
link: application
link-secondary: user
tags:
- upgrade-trail
- usb-history
- windows-update
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: Setupapi-Upgrade-Log
platform:
  windows:
    min: '10'
    max: '11'
    note: "Generated during Windows 10 / Windows 11 feature upgrade (version-to-version) operations. Not present on systems that have never been upgraded. Persists indefinitely after the upgrade unless explicitly cleaned."
  windows-server:
    min: '2016'
    max: '2022'
location:
  path: "%WINDIR%\\INF\\setupapi.upgrade.log"
  sibling-files: "setupapi.dev.log (steady-state device install), setupapi.setup.log (OS setup)"
  addressing: file-path
  note: "Plain-text UTF-16LE with BOM. Written by the PnP / SetupAPI subsystem during a Windows feature upgrade (e.g., 1909 → 2004, 21H2 → 22H2). Records every device / driver SetupAPI interaction that occurred during the upgrade window. Complements setupapi.dev.log (which captures ongoing device installs on normal running systems) — the upgrade variant is specifically the transition-period log. Often contains first-connection records for USB devices that were attached when the upgrade ran — preserving device-enumeration evidence a normal dev.log might have rolled out."
fields:
- name: device-install-records
  kind: content
  location: "log lines matching 'dvi:' or '[Device Install (DiInstallDriver)]' sections"
  encoding: utf-16le (text)
  note: "Per-device install blocks recording hardware-ID, driver-INF path, install outcome, and timestamp. Preserves device-enumeration events that occurred specifically during the upgrade window."
- name: device-hwid
  kind: identifier
  location: "log lines — 'Hardware ID:' fields"
  encoding: utf-16le (text)
  references-data:
  - concept: DeviceSerial
    role: usbDevice
  note: "Hardware ID of enumerated devices (VID/PID for USB; bus-specific format for internal). USB hardware IDs appearing here (USB\\VID_xxxx&PID_xxxx format) indicate the device was plugged in during the upgrade — a device-history breadcrumb independent of USBSTOR's steady-state record."
- name: driver-inf-path
  kind: path
  location: "log lines — 'INF path:' / 'Driver File Path:'"
  encoding: utf-16le
  note: "Driver INF package path as selected for install. For attacker-signed driver delivery during an upgrade window, this field names the specific INF — combines with driver-signing investigations."
- name: event-timestamp
  kind: timestamp
  location: "per-line log timestamp (typically '[YYYY/MM/DD HH:MM:SS.mmm]' format)"
  encoding: "yyyy/MM/dd HH:mm:ss.SSS (local time on host; check LogTimestampSource)"
  clock: system
  resolution: 1ms
  note: "Per-event timestamp — brackets the upgrade operation window. File-level mtime gives the last log-write time; individual event timestamps give the fine-grained per-device moments within the upgrade."
- name: upgrade-start-end
  kind: content
  location: "log lines — '>>>  [Setup Identifier (DiInstallDevice)]' / upgrade phase markers"
  note: "Phase markers delineating upgrade stages. Useful for correlating which devices were enumerated DURING the upgrade vs before/after."
- name: file-mtime
  kind: timestamp
  location: setupapi.upgrade.log $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime = last write. Matches the upgrade completion timestamp. File size is a rough proxy for how many devices / drivers the upgrade touched."
observations:
- proposition: EXECUTED_DURING_UPGRADE
  ceiling: C3
  note: 'setupapi.upgrade.log is the authoritative timestamped record of
    SetupAPI activity during a Windows feature upgrade. Preserves
    device-enumeration events including USB first-connection records
    that steady-state logs may have rolled out on long-lived hosts.
    Complement to setupapi.dev.log: the upgrade log captures the
    transition-specific activity, while dev.log captures ongoing
    activity. For investigations involving attacker activity during
    or bracketing a Windows upgrade, this file provides the device-
    level timeline.'
  qualifier-map:
    time.start: field:event-timestamp
    object.id: field:device-hwid
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none (plain text)
  known-cleaners:
  - tool: "delete %WINDIR%\\INF\\setupapi.upgrade.log"
    typically-removes: complete log (no rotation — single file)
  survival-signals:
  - setupapi.upgrade.log present AND recent = confirms a Windows feature upgrade occurred at that time; correlates with WindowsUpdate-log events
  - Device hardware-IDs in upgrade.log that don't appear in dev.log / USBSTOR = device connection during upgrade window only (USB inserted just for the upgrade, removed before)
  - upgrade.log missing on a host whose WindowsUpdate history shows feature upgrades = log was deleted
provenance:
  - kobzar-2021-windows-updates-anti-forensics-usb
  - forensicswiki-setup-api-logs
  - martinez-2019-unminioncurioso-setupapi-antiforensic
  - kape-files-repo
---

# setupapi.upgrade.log

## Forensic value
`%WINDIR%\INF\setupapi.upgrade.log` is the Windows-upgrade-specific variant of setupapi logging. Generated during Windows 10 / 11 feature upgrades (e.g., 1909 → 2004, 21H2 → 22H2) by the SetupAPI subsystem. Records every device / driver interaction that happened during the upgrade window.

## Three setupapi log family
- **setupapi.setup.log** — OS setup (first-install-of-Windows) events
- **setupapi.dev.log** — ongoing device install events (steady-state)
- **setupapi.upgrade.log** — device / driver events during Windows feature upgrades

All three are plain-text UTF-16LE and persist indefinitely. Acquire all three.

## Why it matters
On a long-lived host, setupapi.dev.log can rotate or be cleaned, losing early USB-first-connection records. setupapi.upgrade.log is generated only during upgrades and captures a snapshot of everything SetupAPI touched in that window — including USB devices that were plugged in at the time.

For investigations asking "when was this USB first seen on this host?" — if the device was attached during an upgrade window, setupapi.upgrade.log has the answer even when dev.log has rolled.

## Concept reference
- DeviceSerial (via embedded hardware-ID records with VID/PID and USB serial)

## Triage
```powershell
Get-Content "$env:WINDIR\INF\setupapi.upgrade.log" -Encoding Unicode |
    Select-String -Pattern 'USB\\VID_|Hardware ID:|Install|Device Install' |
    Select-Object -First 50
```

## Cross-reference
- **setupapi.dev.log** — sibling log for non-upgrade periods
- **USBSTOR / USB-Enum / MountedDevices** — registry-side USB history
- **WindowsUpdate-log** / **CBS-log** — upgrade session timeline
- **Microsoft-Windows-WindowsUpdateClient/Operational** EVTX — upgrade task history

## Practice hint
On a VM that has been feature-upgraded (you can force this by running the Windows Update assistant to install a newer feature build): locate `%WINDIR%\INF\setupapi.upgrade.log` and grep for USB-related hardware IDs. Cross-reference the timestamps against the upgrade completion time. This dual-source (upgrade.log + dev.log) approach catches device events that steady-state logs alone miss.
