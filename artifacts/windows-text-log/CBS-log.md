---
name: CBS-log
aliases: [Component-Based Servicing log, CBS.log]
link: system-state-identity
tags: [system-wide, install-history]
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: CBS.log
platform:
  windows: {min: Vista, max: '11'}
location:
  path: "%WINDIR%\\Logs\\CBS\\CBS.log"
  addressing: filesystem-path
fields:
- name: log-line
  kind: record
  location: text line
  encoding: "YYYY-MM-DD HH:MM:SS, LEVEL CBS COMPONENT: message"
- name: package-identifier
  kind: identifier
  location: embedded in lines with 'Applicable' / 'Installing' / 'Resolving'
  note: "package manifest identifier — matches entries under HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages"
- name: sfc-results
  kind: status
  location: "lines with 'Verify', 'Repair', '[SR]'"
  note: "System File Checker (sfc /scannow) output — verified integrity violations appear here exclusively"
- name: timestamp
  kind: timestamp
  location: leading timestamp of each line
  encoding: YYYY-MM-DD-HH:MM:SS-ms
  clock: system
  resolution: 1ms
observations:
- proposition: INSTALL_STATE_TRACE
  ceiling: C3
  note: "Lowest-level install/repair log on Windows. Windows Update outcomes, DISM operations, SFC results — all trace through CBS."
  qualifier-map:
    object.package.id: field:package-identifier
    time.observed: field:timestamp
anti-forensic:
  write-privilege: unknown
provenance: []
---

# CBS.log

## Forensic value
Lower-level companion to WindowsUpdate.log. Every WU operation, DISM command, SFC scan, and feature-update rollout generates CBS.log entries. Verified-integrity violations from `sfc /scannow` appear HERE (not in WindowsUpdate.log) tagged `[SR]`.

## Cross-references
- **WindowsUpdate-log** — higher-level timeline; CBS has the per-package detail
- **DISM-log** — DISM engine's own log, interleaves with CBS for image-servicing ops
- **System-19** / **System-20** (evtx WindowsUpdate) — structured equivalents
