---
name: Sysmon-1
title-description: "Process Create"
aliases:
- Sysmon process-create
- Sysmon ProcessCreate
- Sysinternals Sysmon event 1
link: application
tags:
- timestamp-carrying
- tamper-hard
volatility: runtime
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Sysmon/Operational
platform:
  windows:
    min: '7'
    max: '11'
    note: requires Sysmon installed
  windows-server:
    min: 2008R2
    max: '2022'
    note: requires Sysmon installed
location:
  channel: Microsoft-Windows-Sysmon/Operational
  event-id: 1
  log-file: '%WINDIR%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx'
  addressing: channel+event-id
fields:
- name: rule-name
  kind: label
  location: EventData\RuleName
  encoding: utf-16le
  note: "Name of the matching config rule (populated when the Sysmon XML config uses `<ProcessCreate name='...'>`). Empty for events matched by default rules. A labeled RuleName makes SIEM grouping / hunting rules dramatically more readable than raw image-path matching."
- name: utc-time
  kind: timestamp
  location: EventData\UtcTime
  encoding: '''YYYY-MM-DD HH:MM:SS.SSS'' UTC string'
  clock: system
  resolution: 1ms
- name: process-guid
  kind: identifier
  location: EventData\ProcessGuid
  encoding: guid-string
  note: Sysmon-generated unique identifier; correlates with other Sysmon events for the same process
- name: process-id
  kind: identifier
  location: EventData\ProcessId
  encoding: uint32
  references-data:
  - concept: ProcessId
    role: createdProcess
  note: PID assigned to this newly-created process. Joins forward to all subsequent Sysmon events for this process via ProcessGuid (more durable) or PID (faster, reuse-risky).
- name: image
  kind: path
  location: EventData\Image
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: ranProcess
- name: file-version
  kind: identifier
  location: EventData\FileVersion
  encoding: utf-16le
- name: description
  kind: identifier
  location: EventData\Description
  encoding: utf-16le
- name: product
  kind: identifier
  location: EventData\Product
  encoding: utf-16le
- name: company
  kind: identifier
  location: EventData\Company
  encoding: utf-16le
- name: original-file-name
  kind: identifier
  location: EventData\OriginalFileName
  encoding: utf-16le
  note: mismatches with image's filename indicate renamed binaries — classic masquerade tell
- name: command-line
  kind: identifier
  location: EventData\CommandLine
  encoding: utf-16le
  note: always captured (unlike 4688 which requires extra GPO)
- name: current-directory
  kind: path
  location: EventData\CurrentDirectory
  encoding: utf-16le
- name: user
  kind: identifier
  location: EventData\User
  encoding: '''DOMAIN\username'' utf-16le'
  note: friendly user — the SID must be resolved via SAM/ProfileList
- name: logon-guid
  kind: identifier
  location: EventData\LogonGuid
  encoding: guid-string
- name: logon-id
  kind: identifier
  location: EventData\LogonId
  encoding: hex-uint64
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: correlates with Security 4624 TargetLogonId — joins Sysmon-1 to the Security.evtx session window
- name: terminal-session-id
  kind: counter
  location: EventData\TerminalSessionId
  encoding: uint32
- name: integrity-level
  kind: enum
  location: EventData\IntegrityLevel
  encoding: string
  note: Low / Medium / High / System
- name: hashes
  kind: hash
  location: EventData\Hashes
  encoding: compound string 'MD5=...,SHA1=...,SHA256=...,IMPHASH=...'
  references-data:
  - concept: ExecutableHash
    role: ranHash
  note: which algorithms are included depends on Sysmon config (HashAlgorithms directive)
- name: parent-process-guid
  kind: identifier
  location: EventData\ParentProcessGuid
  encoding: guid-string
- name: parent-process-id
  kind: identifier
  location: EventData\ParentProcessId
  encoding: uint32
  references-data:
  - concept: ProcessId
    role: parentProcess
  note: PID of the process that spawned this one. Recursively join each parent-process-id to a prior Sysmon-1's process-id to reconstruct the process tree.
- name: parent-image
  kind: path
  location: EventData\ParentImage
  encoding: utf-16le
- name: parent-command-line
  kind: identifier
  location: EventData\ParentCommandLine
  encoding: utf-16le
- name: parent-user
  kind: identifier
  location: EventData\ParentUser
  encoding: utf-16le
observations:
- proposition: EXECUTED
  ceiling: C4
  note: 'The most detailed native execution event when Sysmon is deployed.

    Captures hashes + command line + parent lineage + integrity level

    in a single record — superset of Security-4688''s coverage and

    without the CLI-auditing GPO requirement.

    '
  qualifier-map:
    process.image: field:image
    process.image-hash: field:hashes
    process.command-line: field:command-line
    process.parent-image: field:parent-image
    process.parent-command-line: field:parent-command-line
    actor.user: field:user
    process.session: field:logon-id
    time.start: field:utc-time
  preconditions:
  - Sysmon installed and config capturing event 1
  - Sysmon channel retained across investigation window
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX checksums; Sysmon driver is signed
  known-cleaners:
  - tool: Sysmon uninstall
    typically-removes: prospective
    note: stops new events but doesn't delete past ones; service uninstall is itself logged by Windows
  - tool: config-change hiding rules
    typically-removes: selective
    note: sophisticated attackers push a Sysmon config that excludes their activity; detectable via Sysmon event 16 (config
      change)
  survival-signals:
  - Sysmon channel has gap = service was stopped during window; check Windows System log for service-control events
  - Sysmon event 16 (config change) right before suspicious activity = possible rule-tampering for evasion
provenance: [ms-sysmon-system-monitor, hartong-2024-sysmon-modular-a-repository-of, uws-event-90001]
---

# Sysmon Event 1 — Process Create

## Forensic value
Gold-standard process-creation telemetry on Windows — when Sysmon is deployed. Captures what Security-4688 captures plus: executable hashes (up to four algorithms), parent command line, parent user, process GUIDs (stable identifiers across Sysmon event types), integrity level, terminal session. With good Sysmon config, a single event has nearly everything an execution investigation needs.

## Three concept references
- ExecutablePath (Image)
- ExecutableHash (Hashes — compound, multi-algorithm)
- (UserSID — indirect through LogonId ↔ 4624)

## Known quirks
- **Sysmon must be installed.** Not native — requires `Sysmon.exe -i <config.xml>`. Absence of Sysmon channel ≠ process didn't run; only means no Sysmon visibility.
- **Hashes compound string.** Parsers must split `MD5=...,SHA1=...,SHA256=...` into separate hash values. Which hashes appear depends on config (`HashAlgorithms` setting).
- **Process GUID is Sysmon-internal, not Windows.** Stable for cross-Sysmon-event correlation (ProcessGuid in event 1 matches same value in events 3, 5, etc.) but meaningless outside Sysmon.
- **Config-hiding attacks.** Sophisticated actors deploy Sysmon config that excludes their tooling. Detect via Sysmon event 16 (config change).

## Practice hint
Install Sysmon with Olaf Hartong or SwiftOnSecurity config on a Win10 VM. Run a PowerShell command with arguments — observe the full event 1 payload including hashes and parent lineage. Compare coverage vs. Security-4688 for the same launch.
