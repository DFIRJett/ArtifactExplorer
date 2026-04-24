---
name: WindowsUpdate-log
aliases:
- Windows Update log
- WindowsUpdate.log
- WU log
link: system-state-identity
tags:
- system-wide
- tamper-easy
- update-history
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: WindowsUpdate.log
platform:
  windows:
    min: '7'
    max: '11'
    note: format split — Win7/8 had a single %WINDIR%\WindowsUpdate.log text file; Win10+ uses ETL files in %WINDIR%\Logs\WindowsUpdate, requiring Get-WindowsUpdateLog to decode to text
location:
  path-legacy: "%WINDIR%\\WindowsUpdate.log"
  path-modern: "%WINDIR%\\Logs\\WindowsUpdate\\*.etl"
  decoder-cmdlet: Get-WindowsUpdateLog
  addressing: filesystem-path
fields:
- name: log-line
  kind: record
  location: decoded text line
  note: format — "YYYY-MM-DD HH:MM:SS.mmm PID TID Component MESSAGE"
- name: update-id
  kind: identifier
  location: lines mentioning GUID update IDs (often in the MESSAGE body)
- name: package-name
  kind: identifier
  location: lines mentioning KB number or package name (KB5001649, etc.)
- name: install-outcome
  kind: status
  location: lines with 'Install', 'Success', 'Failed', 'Download', 'Reporter'
- name: timestamp
  kind: timestamp
  location: leading timestamp on each line
  encoding: ISO-8601-local
  clock: system
  resolution: 1ms
  update-rule: append-on-event
observations:
- proposition: OS_STATE_OBSERVED
  ceiling: C2
  note: Chronological WU activity — update checks, downloads, installs, rollbacks, service errors. Baseline for patch-timeline reconstruction and detecting suspended/disabled updates.
  qualifier-map:
    object.package: field:package-name
    object.outcome: field:install-outcome
    time.observed: field:timestamp
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - tool: "Settings → Windows Update → Update history → Uninstall"
    typically-removes: "does NOT clear WU log — update-history UI reads evtx, not this log"
  - tool: "direct delete of ETL files (possible with SYSTEM token; service will resume new ETLs)"
    typically-removes: past-ETL full
  detection-signals:
    - "gap in timestamp stream > several days on an online system = WU service tampering"
    - "'Reporter' events with odd SourceURL = WSUS reconfiguration"
provenance: []
provenance: [kape-files-repo]
---

# WindowsUpdate-log

## Forensic value
Chronological record of Windows Update activity. Used to answer:

- **Was this system patched at the time of the incident?** Cross-reference install timestamps against published CVE dates.
- **Was WU disabled or redirected?** Service-stop, WSUS point-of-contact changes, and scheduled-check failures show here.
- **What was installed and when?** Each KB install has a distinctive "Install : Finished" or "Installation Successful" line.
- **Did rollback occur?** WU logs uninstallation/rollback events distinctly from install events.

## Win7/8 vs Win10+ format
- **Legacy (Win7, Win8, 8.1):** a single growing text log at `%WINDIR%\WindowsUpdate.log`. Directly readable.
- **Modern (Win10+):** ETL trace files in `%WINDIR%\Logs\WindowsUpdate\`. Decoded via:
  ```powershell
  Get-WindowsUpdateLog -LogPath C:\triage\WindowsUpdate.log
  ```
  This cmdlet reads the ETL files, correlates symbols, and writes a combined plain-text log.

## Offline decoding
For offline images, copy the ETL files and the symbols subdirectory (`%WINDIR%\Logs\WindowsUpdate\`) onto a live Windows host, then run Get-WindowsUpdateLog against them. Requires matching or compatible symbols — mismatched symbols produce partial decodes.

## Correlation
- **setupapi-dev-log** — driver-install history (PnP) distinct from WU — but Windows Update often installs drivers so they cross-reference
- **CBS.log** — Component-based servicing log; the lower-level install engine WU calls into. When WU says "Install Finished", CBS.log has the per-package detail.
- **System-19 / System-43** (Windows Update events in EVTX) — complementary structured evtx-side view

## Gap detection
On a system that should be online, a multi-day gap in WindowsUpdate-log activity suggests:
- WU service disabled (check Services registry)
- wuauserv set to Manual or Disabled
- GPO push via WUfB preventing check-in
- Host offline during that window

Correlate with System-6005/6006 boot/shutdown events to distinguish offline gaps from tampering.

## Practice hint
```
Get-WindowsUpdateLog -LogPath C:\temp\wu.log
Select-String -Path C:\temp\wu.log -Pattern "Installation Successful|Install Error|Rollback"
```
Filters the decoded log to the highest-signal lines.
