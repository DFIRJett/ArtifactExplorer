---
name: System-1074
title-description: "The process has initiated the restart / shutdown of the computer"
aliases:
- 1074
- USER32 1074
- Clean shutdown / restart
link: system-state-identity
link-secondary: user
tags:
- power-event
- clean-shutdown
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: System
platform:
  windows:
    min: XP
    max: '11'
  windows-server:
    min: '2003'
    max: '2022'
location:
  channel: System
  event-id: 1074
  provider: USER32
  addressing: evtx-record
  note: "Emitted when a process initiates a clean shutdown or restart (via ExitWindowsEx, InitiateSystemShutdown, shutdown.exe, Stop-Computer, Restart-Computer, or GUI Start-menu power-off). Captures who initiated, what process initiated, and why. Does NOT fire on crashes, power loss, or forced hard-offs — those leave System-41 as the only marker."
fields:
- name: initiating-process
  kind: path
  location: "EventData → param1"
  encoding: utf-16le
  note: "Full path of the process that issued the shutdown API call. Common values: C:\\Windows\\System32\\shutdown.exe (command-line / GUI shutdown), C:\\Windows\\System32\\winlogon.exe (Start-menu shutdown), C:\\Windows\\System32\\wbem\\wmiprvse.exe (WMI Win32_OperatingSystem.Shutdown), powershell.exe (Stop-Computer / Restart-Computer). Attacker-initiated forced reboots typically show shutdown.exe or powershell.exe in this field."
- name: reason-text
  kind: label
  location: "EventData → param2"
  encoding: utf-16le
  note: "Human-readable reason string. 'No title for this reason could be found' when unspecified; otherwise text like 'Operating System: Service pack (Planned)'."
- name: reason-code
  kind: flags
  location: "EventData → param3"
  encoding: shutdown reason code
  note: "Hex shutdown reason code (Major.Minor pair). Useful for distinguishing planned (major 0x8) vs. user-initiated (major 0x0) vs. application-initiated (major 0x4) shutdowns."
- name: shutdown-type
  kind: enum
  location: "EventData → param4"
  encoding: utf-16le
  note: "'shutdown' | 'restart' | 'power off' — distinguishes restart from full power-off. Forced reboots by attackers often use 'restart' (shutdown /r) to bring the host back up quickly."
- name: initiating-user
  kind: label
  location: "EventData → param6"
  encoding: utf-16le (DOMAIN\\user format)
  note: "User account under which the shutdown was initiated. Cross-reference against Security-4624 / 4634 around the event time to verify that user's session was active. A 1074 with a SYSTEM user and a scripted initiating-process suggests scheduled / service / remote-triggered shutdown rather than interactive."
- name: computer-name
  kind: label
  location: "System → Computer"
  encoding: NetBIOS hostname
  references-data:
  - concept: MachineNetBIOS
    role: trackerMachineId
  note: "Host that recorded the event. Useful in multi-host investigations."
- name: event-time
  kind: timestamp
  location: "System → TimeCreated"
  encoding: xs:dateTime UTC
  clock: system
  resolution: 1ms
  note: "Moment the shutdown was INITIATED — not when power actually cut. Delta to the next-boot System-6005 / System-41 bounds the shutdown-and-boot duration."
observations:
- proposition: CLEAN_SHUTDOWN_INITIATED
  ceiling: C3
  note: "Definitive marker that a shutdown or restart was initiated through a normal OS path (API call / command-line tool / GUI). Absence of 1074 preceding a System-41 in the same boot-before-boot gap = forced / dirty shutdown (the OS didn't get a chance to log it)."
  qualifier-map:
    actor.user: field:initiating-user
    actor.process: field:initiating-process
    object.machine: field:computer-name
    time.start: field:event-time
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX-level
  survival-signals:
  - 1074 by shutdown.exe initiated by a non-interactive-session user (cross-check Security-4624 LogonType) = remote or scripted shutdown. Attacker-forced reboot following a log clear typically shows up here UNLESS the attacker skipped the clean path and used hard-off / WMI soft-kill / Stop-Computer -Force.
  - No 1074 preceding a System-41 = forced / dirty shutdown. A 1074 WITH a following System-41 = the reboot happened normally and the 41 is a false positive or separate later dirty-off.
  - 1074 by wininit.exe / winlogon.exe with SYSTEM user = automatic system-initiated (Windows Update, critical-process-died recovery, scheduled task issuing shutdown /r) — not necessarily suspicious.
provenance: [ms-user32-event-1074-shutdown-initiate]
---

# System-1074 — Clean Shutdown Initiated

## Forensic value
The single clearest "someone (or some process) told Windows to shut down cleanly" marker. Captures WHO (user), WHAT (process that called the shutdown API), WHEN (time), and HOW (reason code + restart-vs-shutdown-vs-poweroff).

For anti-forensic investigations: 1074 is the paired opposite of System-41. Together they describe every shutdown path:

| 1074 present? | 41 present on next boot? | Interpretation                                    |
|---------------|--------------------------|---------------------------------------------------|
| yes           | no                       | Normal clean shutdown and orderly reboot          |
| yes           | yes                      | Clean shutdown was initiated but the system dirty-rebooted anyway (crash during shutdown, power cut mid-shutdown) |
| no            | yes                      | No clean shutdown; dirty reboot (forced, crash, power loss) |
| no            | no                       | System didn't shut down — if boot time advanced, something's wrong with the logging subsystem (or the event gap is in a different boot) |

## Attacker-forced reboot detection
A scripted reboot via `shutdown /r /f /t 0` or `Restart-Computer -Force` still produces a 1074 (it went through the shutdown API). That's useful — the `initiating-process` field records the exact binary, and `initiating-user` ties to the logon session that ran it. Combined with `Security-4688` (process creation) around the same time, you can identify which process spawned shutdown.exe / powershell.exe and chain back to the user action.

An attacker wanting to suppress 1074 would have to bypass the shutdown API entirely — hard-off via IPMI, VM host kill, ACPI power button simulation, or crash injection. Any of those paths leave ONLY System-41 (no paired 1074) which is itself the IOC.

## Concept references
- MachineNetBIOS (Computer field)

## Cross-reference
- **System-41** — paired unexpected-shutdown marker. Presence of both bounds the shutdown-and-restart cycle.
- **System-6005** — Event Log service started (marks new boot).
- **System-6006** — Event Log service stopped (marks clean shutdown completion — usually adjacent to 1074).
- **Security-4608** / **Security-4609** — (Windows 7-era) system startup / shutdown markers in Security.evtx.
- **ShutdownTime** — registry value recording the last clean shutdown. Updated when 1074's shutdown completes successfully; NOT updated on dirty shutdowns.
- **Security-4688** — process-creation trace of shutdown.exe / powershell.exe when the shutdown was script-initiated. Joins on ProcessId within the boot.

## Practice hint
Run `shutdown /r /t 0` from an elevated PowerShell, let the reboot happen, then check System.evtx for 1074. Observe: `initiating-process=C:\Windows\System32\shutdown.exe`, `initiating-user=DOMAIN\yourname`, `shutdown-type=restart`. This is the exact signature a scripted attacker reboot produces — the artifact alone doesn't flag attacker intent; the pattern (timestamp adjacency to Security-1102 or to VSS deletion events) is what earns the suspicion.
