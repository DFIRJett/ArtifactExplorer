---
name: BITS-QueueManager
title-description: "Background Intelligent Transfer Service queue database — jobs.jdb (modern) / qmgr*.dat (legacy)"
aliases:
- BITS queue manager database
- qmgr0.dat / qmgr1.dat
- jobs.jdb
- BITS job state
link: network
link-secondary: application
tags:
- exfil-channel
- living-off-the-land
- itm:IF
- itm:ME
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: BITS-QueueManager
platform:
  windows:
    min: NT5.2
    max: '11'
    note: "Format changed between Windows releases. Windows 7 / 8 / 8.1 / early Win10: qmgr0.dat + qmgr1.dat (double-buffered binary format). Windows 10 1709+ / Windows 11: jobs.jdb (single JET / ESE-backed database). Both hold the same logical content: per-job state, source URL, destination path, owner SID, state machine position."
  windows-server:
    min: '2003'
    max: '2022'
location:
  path-legacy: "%ALLUSERSPROFILE%\\Microsoft\\Network\\Downloader\\qmgr0.dat and qmgr1.dat"
  path-modern: "%ALLUSERSPROFILE%\\Microsoft\\Network\\Downloader\\jobs.jdb (Win10 1709+)"
  addressing: file-path
  note: "%ALLUSERSPROFILE% = C:\\ProgramData on modern Windows. Directory ACL restricts to SYSTEM + Administrators. Acquire the whole Downloader\\ folder including any .tmp spill files and the jobs.jdb journal files (jobs-jrnNN.log) — the journal may hold delta records not yet merged."
fields:
- name: job-url
  kind: identifier
  location: "BITS record — SourceUrl field (UTF-16LE)"
  encoding: utf-16le
  references-data:
  - concept: URL
    role: downloadedFromUrl
  note: "The URL BITS fetched from (download job) or posted to (upload job). An attacker-configured BITS job pointing to a C2 URL is one of the most durable exfil / download persistence mechanisms on Windows — BITS runs as SYSTEM, survives reboot, throttles gracefully to avoid detection, and resumes automatically across network outages."
- name: job-destination
  kind: path
  location: "BITS record — LocalName field (UTF-16LE)"
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Local destination path (download) or source path (upload). Download jobs writing to %TEMP% / user-writable paths that later match Amcache execution entries = payload delivery completed."
- name: owner-sid
  kind: identifier
  location: "BITS record — Owner SID"
  encoding: sid-binary or string
  note: "SID of the account that created the job. Jobs created by non-administrator accounts are unusual outside WSUS / Delivery Optimization contexts — worth validating owner against expected services."
- name: job-state
  kind: enum
  location: "BITS record — JobState field"
  encoding: uint32
  note: "BITS state machine position: 0=Queued, 1=Connecting, 2=Transferring, 3=Suspended, 4=ERROR, 5=Transient Error, 6=Transferred, 7=Acknowledged, 8=Cancelled. Suspended / Transferred states on a job with a C2-looking URL + lack of acknowledgment = attacker job awaiting trigger."
- name: job-priority
  kind: enum
  location: "BITS record — Priority"
  encoding: uint32
  note: "0=Foreground, 1=High, 2=Normal, 3=Low. Attackers commonly use Low priority to stay below throttling thresholds and avoid competing with user traffic — a jobs.jdb row with Priority=3 and URL to a non-Microsoft host is a classic pattern."
- name: create-time
  kind: timestamp
  location: "BITS record — CreationTime"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "Job submission time. Pair with Microsoft-Windows-Bits-Client/Operational event IDs 3 (job created), 59 (job transferred), 61 (job error) for cross-verification against EVTX."
- name: modify-time
  kind: timestamp
  location: "BITS record — ModificationTime"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "Last state-transition timestamp. For a still-active job, the delta between CreationTime and ModificationTime shows how long the job has been running — attacker persistence jobs often have days- or weeks-long active windows."
- name: notify-command
  kind: content
  location: "BITS record — CommandLine (on completion)"
  encoding: utf-16le
  note: "OPTIONAL command BITS runs when the job completes (SetNotifyCmdLine API). Attacker-set notify command turns BITS into a durable trigger: 'once download of this URL finishes, run this command' — equivalent to scheduled-task persistence but invoked on download-completion rather than time."
- name: file-mtime
  kind: timestamp
  location: jobs.jdb / qmgr*.dat file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime — updates as BITS persists state changes. Serves as the broad 'BITS was active at time X' signal at the filesystem level, useful for triage before parsing the internal records."
observations:
- proposition: COMMUNICATED
  ceiling: C4
  note: 'BITS is a Microsoft-signed, SYSTEM-privileged, reboot-persistent,
    throttle-aware network-transfer service present on every Windows
    install since XP. Attackers use it as a durable exfil / download
    channel because it: (1) runs as SYSTEM so no user logon is needed,
    (2) survives reboot automatically, (3) uses HTTP/HTTPS and blends
    with legitimate Windows Update / Delivery Optimization traffic,
    (4) supports notify-commands that fire arbitrary code on completion,
    (5) is under-monitored compared to Sysmon-3 / Sysmon-22 because
    BITS transfers are kernel-queued rather than per-process. The
    queue database is the definitive record of every BITS job past
    and present — a forensic goldmine when exfil is suspected.'
  qualifier-map:
    direction: bidirectional
    peer.url: field:job-url
    object.path: field:job-destination
    actor.user: field:owner-sid
    time.start: field:create-time
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: ESE page checksums (jobs.jdb); custom checksum (qmgr*.dat)
  known-cleaners:
  - tool: net stop BITS + delete Downloader\ contents
    typically-removes: all job state (service recreates empty jobs.jdb on next start)
  - tool: bitsadmin /reset /allusers
    typically-removes: cancels all queued jobs but leaves jobs.jdb structure intact
  survival-signals:
  - jobs.jdb SourceUrl fields pointing to external IPs / non-Microsoft domains with Owner=LOCAL SYSTEM = high-confidence SYSTEM-context persistence
  - Notify-command populated on a job = command-trigger plant (rare in legitimate Windows use outside specific enterprise apps)
  - BITS jobs in Suspended state with attacker-looking URL = dormant exfil channel awaiting trigger
  - Large number of completed-Acknowledged rows for a destination that later appears in Sysmon-1 as an attacker binary = dropper delivery chain
provenance:
  - ms-background-intelligent-transfer-ser
  - mitre-t1197
  - project-2023-windowsbitsqueuemanagerdatabas
  - anssi-fr-2018-bits-parser-jobs-jdb-qmgr-dat
  - mandiant-2021-via-runnels-bits-forensics
  - fireeye-bitsparser
---

# BITS Queue Manager Database

## Forensic value
The Background Intelligent Transfer Service (BITS) is the signed, SYSTEM-privileged, reboot-persistent network-transfer service Windows uses internally (Windows Update, Delivery Optimization, SCCM, Edge update). Any application can submit a BITS job — including attacker tooling via `bitsadmin.exe` or the `Microsoft.BackgroundIntelligentTransfer.Management` PowerShell module.

Every BITS job's state lives in the queue database:

- **Legacy (Win7 → early Win10)**: `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr0.dat` + `qmgr1.dat` (double-buffered binary)
- **Modern (Win10 1709+)**: `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\jobs.jdb` (JET ESE database)

Each record holds source URL, destination path, owner SID, job state, priority, timestamps, and optional notify-command. The database is the single richest source for reconstructing BITS activity.

## Why attackers love BITS
- Runs as **SYSTEM** → no user logon required for trigger
- **Reboot-persistent** → jobs survive across reboots automatically
- **HTTP/HTTPS only** → no exotic protocols that trigger network-IDS
- Blends into **Windows Update** and **Delivery Optimization** noise
- Supports **SetNotifyCmdLine** → arbitrary command on completion (MITRE T1197)
- **Throttle-aware** → won't compete with user network activity, stays under SOC thresholds
- Under-monitored by **Sysmon-3 / Sysmon-22** — transfers are kernel-queued, not per-process

## Concept references
- URL (per job-url)
- ExecutablePath (per job-destination)

## Triage
```powershell
# Live — list all BITS jobs across all users
bitsadmin /list /allusers /verbose
# Modern PowerShell
Get-BitsTransfer -AllUsers | Format-List *

# Offline — acquire and parse
Copy-Item "C:\ProgramData\Microsoft\Network\Downloader\*" -Destination .\evidence\bits\ -Recurse
# Then:
# python3 bits_parser.py .\evidence\bits\jobs.jdb > jobs.csv
```

## Cross-reference
- **EVTX**: `Microsoft-Windows-Bits-Client/Operational` events 3 (created), 59 (transferred), 61 (error), 3b (notify command)
- **Sysmon-3**: outbound network connection from svchost.exe hosting BITSv2 service
- **Amcache / Prefetch**: completion-triggered commands leave standard execution evidence
- **Security-4688**: bitsadmin.exe / PowerShell BITS cmdlet invocations

## Practice hint
On a test VM (elevated PowerShell):
```powershell
Start-BitsTransfer -Source "https://example.com/benign-test.txt" -Destination "C:\temp\test.txt"
```
Then stop BITS and inspect `jobs.jdb` — your job row is visible in the parser output. Complete the job, check EVTX Bits-Client/Operational for events 3 and 59. This end-to-end chain is exactly what attacker-submitted jobs produce (with malicious URLs / destinations).
