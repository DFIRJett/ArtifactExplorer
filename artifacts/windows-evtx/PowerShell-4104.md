---
name: PowerShell-4104
title-description: "PowerShell Script Block Logging"
aliases:
- PowerShell script block logging
- PS 4104
- ScriptBlockText event
link: application
tags:
- timestamp-carrying
- tamper-hard
volatility: runtime
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-PowerShell/Operational
platform:
  windows:
    min: '7'
    max: '11'
    note: PowerShell 5.0+ required for script-block logging
location:
  channel: Microsoft-Windows-PowerShell/Operational
  event-id: 4104
  log-file: '%WINDIR%\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx'
fields:
- name: time-created
  kind: timestamp
  location: System\TimeCreated SystemTime
  encoding: iso8601-utc
  clock: system
  resolution: 1us
- name: script-block-text
  kind: identifier
  location: EventData\ScriptBlockText
  encoding: utf-16le
  note: FULL PowerShell script block source — decoded even if the original invocation was base64-encoded
- name: script-block-id
  kind: identifier
  location: EventData\ScriptBlockId
  encoding: guid-string
- name: path
  kind: path
  location: EventData\Path
  encoding: utf-16le
  note: source file path when available (script file); blank for ad-hoc commands
- name: message-number
  kind: counter
  location: EventData\MessageNumber
  encoding: uint32
  note: large script blocks split across multiple 4104 events; reassemble by ScriptBlockId
- name: message-total
  kind: counter
  location: EventData\MessageTotal
  encoding: uint32
- name: user-id
  kind: identifier
  location: System\Security\UserID
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: actingUser
observations:
- proposition: EXECUTED
  ceiling: C4
  note: 'Script-block logging captures the DECODED content of PowerShell

    script execution. Defeats base64 / encoded-command / compressed

    payload obfuscation — 4104 logs see the post-decode script body.

    Single most powerful native artifact against PowerShell-based attacks.

    '
  qualifier-map:
    process.image: powershell.exe or pwsh.exe
    process.script-content: field:script-block-text
    actor.user: field:user-id
    time.start: field:time-created
  preconditions:
  - 'ScriptBlockLogging enabled via GPO: Computer Config > Admin Templates > Windows Components > Windows PowerShell > Turn
    on Script Block Logging = Enabled'
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX checksums
  known-cleaners:
  - tool: disable ScriptBlockLogging via registry or GPO
    typically-removes: prospective
    note: attackers often disable this FIRST via Set-ItemProperty to the registry key controlling it
  - tool: wevtutil clear-log
    typically-removes: full
  survival-signals:
  - PowerShell invocations evident from process-creation events (Security-4688 / Sysmon-1) but no 4104 events = ScriptBlockLogging
    was disabled
provenance:
  - mitre-t1059
  - mitre-t1059-001
  - ms-powershell-operational
---

# PowerShell Event 4104 — Script Block Logging

## Forensic value
The strongest single artifact for investigating PowerShell-based attacks. Whatever the attacker passes to PowerShell — encoded commands, compressed payloads, obfuscated scripts — gets **decoded by PowerShell at execution time and logged verbatim** in event 4104's ScriptBlockText field.

If you see `powershell.exe -EncodedCommand <huge-base64>` in a 4688 process-creation event, the matching 4104 event has the decoded source that would have run. This is why attackers actively target ScriptBlockLogging for disablement — it's that effective.

## Concept reference
- UserSID (UserID)

## Known quirks
- **Requires explicit enabling.** Not on by default. GPO or registry. Absence in the channel ≠ no PowerShell ran; most likely ScriptBlockLogging was off.
- **Large scripts split across events.** MessageNumber + MessageTotal fields let you reassemble; script-block-id groups them.
- **Per-scope events.** Each module imported or scriptblock parsed generates an event. A single malicious payload can produce many events.

## Practice hint
Enable ScriptBlockLogging on a test VM. Run `powershell -EncodedCommand <base64 of simple script>`. Look at Microsoft-Windows-PowerShell/Operational event 4104 — verify the decoded script appears.
