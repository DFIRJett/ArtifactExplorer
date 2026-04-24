---
name: Defender-MPLog
aliases:
- Microsoft Defender MPLog
- AV engine log
link: security
tags:
- timestamp-carrying
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: MPLog-*.log
platform:
  windows:
    min: '7'
    max: '11'
  windows-server:
    min: '2016'
    max: '2022'
location:
  path: '%ProgramData%\Microsoft\Windows Defender\Support\MPLog-<yyyymmdd-hhmmss>.log'
  rotation: one file per Defender engine session
  addressing: filesystem-path-plus-rotation-timestamp
fields:
- name: log-timestamp
  kind: timestamp
  location: per-line prefix
  encoding: '''YYYY-MM-DD HH:MM:SS.sss'' local time'
  clock: system
  resolution: 1ms
- name: scanned-path
  kind: path
  location: '''RealTimeProtection'' / ''Scan'' entries'
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: scannedTarget
  note: files scanned during real-time protection — captures every on-access scan
- name: threat-name
  kind: identifier
  location: '''Threat'' entries'
  encoding: ascii
  note: e.g., 'Trojan:Win32/Emotet', 'Behavior:Win32/SuspPowerShellExec'
- name: file-hash
  kind: hash
  location: '''SHA256:'' / ''SHA1:'' prefix lines'
  encoding: hex-string
  references-data:
  - concept: ExecutableHash
    role: detectedHash
- name: action-taken
  kind: enum
  location: '''Action:'' entries'
  encoding: ascii
  note: Allow / Block / Clean / Quarantine / Delete
- name: user-context
  kind: identifier
  location: session/process context lines
  encoding: '''DOMAIN\user'' or SID'
  note: the user context under which the scan occurred
- name: engine-version
  kind: identifier
  location: engine startup banner
  encoding: ascii
  note: MsMpEng version; useful for timeline of which detections were available
observations:
- proposition: EXISTS
  ceiling: C3
  note: 'Records every file Defender saw during real-time protection AND any

    threat detections. For suspected malware, MPLog is often the earliest

    evidence that the file touched the system.

    '
  qualifier-map:
    entity.path: field:scanned-path
    entity.hash: field:file-hash
    entity.threat-label: field:threat-name
    time.start: field:log-timestamp
  preconditions:
  - Defender real-time protection was enabled at the time
  - MPLog file not deleted (attackers sometimes clean these specifically)
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: none
  known-cleaners:
  - tool: manual delete of MPLog-*.log
    typically-removes: full for that session
  - tool: Defender tampering protection
    typically-removes: prospective via service disable; leaves System log traces
  survival-signals:
  - MPLog gap during known-active period = Defender was disabled or session logs were deleted
  - Threat entries in MPLog but no quarantine file on disk = quarantine was purged by user or cleanup tool
provenance: []
provenance: [kape-files-repo]
---

# Microsoft Defender MPLog

## Forensic value
Detailed plaintext log of Defender engine activity. Records real-time-protection scans (every executed or accessed file touched), detection events, signature updates, and engine configuration changes. One log file per engine session.

For malware investigations, MPLog is often the most granular timeline of "what Defender saw" — including scanned files that Defender *didn't* flag but that a human analyst would find suspicious in retrospect.

## Two concept references
- ExecutablePath (scanned paths)
- ExecutableHash (SHA256/SHA1 of scanned or detected files)

## Known quirks
- **File is large.** A day's worth of activity on a busy system is tens of MB. Grep or `Select-String` to find specific hashes/paths.
- **Timestamps local time.** Different rotation files may span different days; align via rotation filename date prefix.
- **Line format varies between engine versions.** Older log lines use different prefixes than newer.
- **Deletion is trivial** (plaintext under %ProgramData% — user-writable if Defender protection isn't enforced).

## Practice hint
Grep today's MPLog for any file you manually downloaded. You'll see RealTimeProtection entries for on-access scans. Compare the hash logged there to the current file — mismatch indicates the file was modified after scan.
