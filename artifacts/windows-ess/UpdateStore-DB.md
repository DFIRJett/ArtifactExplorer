---
name: UpdateStore-DB
title-description: "Windows Update store.db — per-update install-state database (ESE/JET format)"
aliases:
- UpdateStore.db
- WU store database
- store.edb
link: application
link-secondary: system
tags:
- update-history
- patch-forensics
volatility: persistent
interaction-required: none
substrate: windows-ess
substrate-instance: UpdateStore-DB
platform:
  windows:
    min: '10'
    max: '11'
    note: "Windows Update internals restructured in Win10 1809 with the Update Session Orchestrator (USO). store.db is the per-update state database that replaced parts of the legacy SoftwareDistribution\\DataStore.edb. Still coexists with DataStore.edb on modern builds."
  windows-server:
    min: '2016'
    max: '2022'
location:
  path-usoshared: "%ProgramData%\\USOShared\\Logs\\store.db"
  path-softwaredistribution: "%WINDIR%\\SoftwareDistribution\\DataStore\\DataStore.edb (legacy / main WU datastore)"
  path-pending: "%WINDIR%\\SoftwareDistribution\\Download\\ (downloaded update packages)"
  addressing: file-path
  note: "ESE-format database tracking update session state: per-update download status, install status, timestamps, detection-ID, update-ID, category (Security / Critical / Feature / Driver), KB identifier. Complements WindowsUpdate.log (text-log artifact already covered) which logs WU events — this database holds the authoritative state. For DFIR: pivotal in patch-level attribution, identifying when specific vulnerability-fixing updates were installed / skipped / failed, and detecting attacker-manipulated update posture (suppressed critical updates that would have patched an exploit they're using)."
fields:
- name: update-id
  kind: identifier
  location: "store.db Updates / tbUpdates table — UpdateID GUID"
  encoding: guid-string
  note: "Microsoft Update unique identifier per update. Joins to Microsoft Update Catalog / WSUS for the authoritative update description (KB number, severity, affected-product list)."
- name: kb-number
  kind: identifier
  location: "store.db — KB / Title fields per update record"
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: "KB identifier (e.g., KB5021233) or title text. Joins to MSRC advisories for what CVE(s) the update addresses. For incident-timeline work: 'was this host patched against CVE-XXX when the attack happened?' — answer by finding the KB corresponding to the CVE and checking its install status in store.db."
- name: install-state
  kind: enum
  location: "store.db — InstallState / State column per update"
  encoding: integer state enum
  note: "Update state: Detected / Downloaded / Installing / Installed / Failed / Reverted / Superseded / Hidden. For security updates relevant to an exploit window: Not-Installed or Failed on a critical update near the incident window = unpatched vulnerability at attack time."
- name: detection-time
  kind: timestamp
  location: "store.db — DetectionTime / LastDeploymentChangeTime"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "When WU detected the update as applicable. Pairs with InstallTime for detect-to-install latency analysis (attacker-induced delay / gap)."
- name: install-time
  kind: timestamp
  location: "store.db — InstallationTime column"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "When the update was successfully installed. Joins to System-19 (installation successful) and 20 (installation failure) events in Microsoft-Windows-WindowsUpdateClient/Operational EVTX."
- name: failure-info
  kind: flags
  location: "store.db — FailureCount / LastFailureTime / ResultCode"
  encoding: HRESULT + count + timestamp
  note: "Per-update failure statistics. A pattern of failures on security-critical updates leading up to an intrusion = attacker environmental prep (they know the host is unpatched)."
- name: file-mtime
  kind: timestamp
  location: store.db file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime = last state-change write. Typically advances every WU session (scan / download / install)."
- name: companion-datastore
  kind: content
  location: "%WINDIR%\\SoftwareDistribution\\DataStore\\DataStore.edb"
  note: "Legacy / complementary WU database. Still written on modern builds. Similar per-update state records + expanded metadata (applicable products, severity). Acquire alongside store.db for complete WU state picture."
observations:
- proposition: CONFIGURED_PATCH_STATE
  ceiling: C4
  note: 'UpdateStore.db + SoftwareDistribution\\DataStore.edb together
    are the authoritative source of WU state on a host. Install-
    state + timestamps + failure info for every applicable update.
    For DFIR patch-attribution: direct evidence of whether a
    specific KB was installed before an exploit-triggered incident.
    For detecting attacker WU tampering: suppressed critical updates
    (Hidden state) near intrusion window + failure patterns on
    fixing-the-exploit KBs = probable attacker environmental prep
    or victim-side misconfiguration that the attacker exploited.
    Complements WindowsUpdate.log (event text log) with the state
    database view.'
  qualifier-map:
    object.id: field:kb-number
    object.state: field:install-state
    time.start: field:install-time
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: ESE page-level checksums
  known-cleaners:
  - tool: "Stop WU service + delete store.db + DataStore.edb"
    typically-removes: update-state history; WU rebuilds empty on next run — historical patch data lost
  - tool: "Stop-Service wuauserv + Remove-Item -Path 'C:\\Windows\\SoftwareDistribution\\DataStore' -Recurse"
    typically-removes: same
  survival-signals:
  - store.db showing critical security update in Hidden state near intrusion window = WU posture was tampered to prevent the patch
  - DataStore.edb / store.db missing on a host where Windows Update history shows recent installs = deliberate cleanup
  - File mtime pattern showing no WU activity during incident window on a typically-active host = WU service suppressed
provenance:
  - ms-update-session-orchestrator-uso-arc
---

# Windows Update Store DB

## Forensic value
`%ProgramData%\USOShared\Logs\store.db` is the Update Session Orchestrator's per-update state database (ESE format). Tracks download / install / failure state for every update detected as applicable to the host. Companion to `WindowsUpdate.log` (text log — covered separately) and `%WINDIR%\SoftwareDistribution\DataStore\DataStore.edb` (legacy / complementary database).

## Forensic uses
- **Patch-state attribution**: was KB5021233 (or whichever CVE-fix) installed before the incident? Direct query.
- **Missing-critical-update detection**: security-critical KB in "Hidden" / "Detected-Not-Installed" state near intrusion window.
- **Update-failure analysis**: pattern of failures on specific KBs = possible attacker environmental prep.
- **Timeline anchors**: InstallationTime fields give precise update-install moments for correlation with other evidence.

## Parsing
ESE database — parse with:
- `esedbexport` (libesedb / Joachim Metz)
- NirSoft ESEDatabaseView
- Microsoft's ESE APIs via PowerShell module

## Concept reference
- None direct — state-tracking artifact.

## Triage
```powershell
Copy-Item "$env:ProgramData\USOShared\Logs\store.db" -Destination .\evidence\store.db
Copy-Item "$env:WINDIR\SoftwareDistribution\DataStore\DataStore.edb" -Destination .\evidence\DataStore.edb

# Offline parse
esedbexport.exe -t .\export store.db
```

Inspect Updates table (or equivalent) → rows with InstallState, DetectionTime, InstallationTime, KB identifiers.

## Cross-reference
- **WindowsUpdate-log** — text-log of WU events (covered separately)
- **Microsoft-Windows-WindowsUpdateClient/Operational** EVTX — events 19 (installed), 20 (failed), 44 (download started)
- **Application-Error / MsiInstaller** EVTX — update-installer failures
- **CBS-log** — component-based servicing log (DISM / component install failures)
- **Uninstall-Keys** registry — some KB installations leave uninstall entries

## Practice hint
On a lab VM: let Windows Update run naturally. Acquire store.db. Parse with esedbexport. Inspect a specific KB's row — see Detection / Installation timestamps + InstallState. Search MSRC for that KB's CVE list — now you have direct patch-vs-vulnerability correlation for forensic attribution.
