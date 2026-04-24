---
name: Defender-1116
title-description: "Microsoft Defender Antivirus detected malware or other potentially unwanted software"
aliases:
- Defender malware detected
- Microsoft Defender detection
link: security
tags:
- detection
- av-telemetry
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Windows Defender/Operational
platform:
  windows:
    min: '7'
    max: '11'
    note: Defender bundled with Windows; earlier releases used SCEP with similar event IDs
location:
  channel: Microsoft-Windows-Windows Defender/Operational
  event-id: 1116
  provider: Microsoft-Windows-Windows Defender
  log-file: "%WINDIR%\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx"
fields:
- name: ThreatName
  kind: label
  location: EventData → 'Threat Name'
  note: Defender signature name (Trojan:Win32/*, Behavior:Win32/*, HackTool:*, etc.)
- name: ThreatID
  kind: identifier
  location: EventData → 'Threat ID'
  note: numeric catalog ID for the detection signature
- name: SeverityName
  kind: flag
  location: EventData → 'Severity Name'
  note: Low / Moderate / High / Severe
- name: CategoryName
  kind: label
  location: EventData → 'Category Name'
- name: ActionName
  kind: flag
  location: EventData → 'Action Name'
  note: Allow / Block / Quarantine / Remove / UserDefined / NoAction — the intended action (actual outcome in 1117)
- name: Path
  kind: path
  location: EventData → 'Path'
  note: "filesystem path OR behavior-context identifier; format varies by detection type (file:_<path>, containerfile:_<archive>, behavior:_<ctx>, amsi:_<content>, webcontent:_<url>)"
  references-data:
  - concept: ExecutablePath
    role: scannedTarget
- name: ProcessName
  kind: path
  location: EventData → 'Process Name'
  note: process that triggered the detection (Explorer during download scan, the malicious process itself for behavior hits)
  references-data:
  - concept: ExecutablePath
    role: actingProcess
- name: DetectionUser
  kind: identifier
  location: EventData → 'Detection User'
  note: SID under which the detection fired
  references-data:
  - concept: UserSID
    role: actingUser
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: SCANNED_TARGET_HIT
  ceiling: C3
  note: Defender matched a known-bad signature or behavior. Authoritative for 'something was attempted' — compare with 1117 (action outcome) to distinguish blocked vs. user-override situations.
  qualifier-map:
    object.threat.name: field:ThreatName
    object.file.path: field:Path
    actor.user.sid: field:DetectionUser
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: service
  known-cleaners:
  - tool: wevtutil clear-log
    typically-removes: emits 104 to System
  - tool: 'Defender exclusion path'
    typically-removes: prevents FUTURE detections on the excluded path (no retroactive scrub)
detection-priorities:
  - Defender-5001 (protection disabled) preceding a 1116 by minutes — attacker disabled, dropped, re-enabled
  - Multiple 1116 events with identical ThreatName in <60s — scan caught a staged drop sequence
  - 1116 with Path containing 'behavior:' and ProcessName being a LOLBin (powershell.exe, rundll32.exe) — behavior-based detection on fileless attack
provenance:
  - ms-defender-events
---

# Defender-1116

## Forensic value
Defender's "malware detected" event. Fires every time a signature match (AV/engine detection) OR a behavior-monitor match (AMSI, behavior monitoring) happens. The richest built-in AV telemetry in Windows — structured, machine-readable, and always-on when Defender is the active AV.

## Detection type discrimination via Path
- `file:_C:\Users\u\Downloads\evil.exe` → classic file-scan signature hit
- `containerfile:_C:\Users\u\Downloads\payload.zip` → archive-scan hit
- `behavior:_process_*.exe\u\powershell.exe` → AMSI / behavior detection
- `amsi:_<content>` → direct AMSI content block
- `webcontent:_https://...` → SmartScreen URL block

The prefix before `:_` tells you the detection subsystem. Behavior/AMSI hits are the most actionable for post-compromise analysis — they indicate the attacker was actively running code that Defender intercepted mid-flight.

## Pair with Defender-1117
- **1116** = "we detected this"
- **1117** = "we took this action"

A 1116 without a matching 1117 within seconds is abnormal — indicates Defender was interrupted, terminated, or tampered with between detection and action. Cross-reference Defender-5001 (real-time protection disabled) for the tampering hypothesis.

## Defender-MPLog correlation
The Defender service also writes a detailed text log to `%ProgramData%\Microsoft\Windows Defender\Support\MPLog-*.log`. Defender-1116 gives a summary; MPLog has the scan timings, file hashes, and engine signatures. The cross-reference (artifact: Defender-MPLog) gives richer forensic detail than the evtx alone.

## Cross-references
- **Defender-1117** — action-taken outcome
- **Defender-5001** — real-time protection disabled (tampering precursor)
- **Defender-MPLog** (text log) — detailed scan diagnostics
- **Zone-Identifier-ADS** — Mark-of-the-Web on the detected file; confirms download origin
- **Chrome-Downloads / Edge-Downloads** — if the file was browser-downloaded, the hash + URL chain is here

## Practice hint
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -FilterXPath "*[System[EventID=1116]]" |
  Select-Object TimeCreated,
    @{N='Threat';E={($_.Message -split "`n" | Select-String 'Threat Name').ToString()}},
    @{N='Path';E={($_.Message -split "`n" | Select-String 'Path').ToString()}}
```
Quick triage — full decode via ThreatName + Path combinations.
