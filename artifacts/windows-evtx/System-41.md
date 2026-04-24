---
name: System-41
title-description: "The system rebooted without cleanly shutting down first"
aliases:
- Kernel-Power 41
- Unexpected shutdown
- Dirty reboot
link: system-state-identity
link-secondary: evasion
tags:
- power-event
- anti-forensic-signal
- always-emitted
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: System
platform:
  windows:
    min: '7'
    max: '11'
  windows-server:
    min: '2008R2'
    max: '2022'
location:
  channel: System
  event-id: 41
  provider: Microsoft-Windows-Kernel-Power
  addressing: evtx-record
  note: "Logged by the NEXT boot after a dirty shutdown — Windows notices on wake-up that the previous session didn't record a clean power-off (System-1074) or sleep-transition, and emits 41 as the post-mortem marker. TimeCreated is the boot-time of the surviving session, NOT the moment of the unexpected shutdown. The unexpected shutdown moment is inferred from the last event before boot + the PowerButtonTimestamp field when available."
fields:
- name: bugcheck-code
  kind: flags
  location: "EventData → BugcheckCode"
  encoding: uint32
  note: "Nonzero = BSOD crash occurred. Zero = power loss / forced hard-off with no crash. Common crash codes: 0x9F (DRIVER_POWER_STATE_FAILURE), 0xEF (CRITICAL_PROCESS_DIED), 0xA (IRQL_NOT_LESS_OR_EQUAL). Attacker-forced reboots (Stop-Computer -Force, holding the power button, PSU kill) typically produce 0x0."
- name: bugcheck-parameters
  kind: flags
  location: "EventData → BugcheckParameter1 / 2 / 3 / 4"
  encoding: hex uint64 ×4
  note: "BSOD-specific parameters. Useful only when BugcheckCode is nonzero. Zero in all four is the normal dirty-power-off pattern."
- name: sleep-in-progress
  kind: flags
  location: "EventData → SleepInProgress"
  encoding: boolean
  note: "True if the system was transitioning to sleep when the shutdown happened. False is the more-common attacker-forced pattern."
- name: power-button-timestamp
  kind: timestamp
  location: "EventData → PowerButtonTimestamp"
  encoding: FILETIME (0 if not recorded)
  clock: system
  resolution: 100ns
  note: "Exact moment the power button was registered (when the firmware/kernel captured it). Nonzero = user held the power button. Zero = not a power-button event (crash / PSU loss / remote forced reboot / VM host kill). For attacker-forced reboot via `shutdown /r /f /t 0` or `Stop-Computer -Force`, this field is usually zero — the OS issued the shutdown before the kernel could record a button press."
- name: computer-name
  kind: label
  location: "System → Computer"
  encoding: NetBIOS hostname
  references-data:
  - concept: MachineNetBIOS
    role: trackerMachineId
  note: "Host that recorded the event. Useful in multi-host investigations where evtx bundles land together and need sorting."
- name: event-time
  kind: timestamp
  location: "System → TimeCreated"
  encoding: xs:dateTime UTC
  clock: system
  resolution: 1ms
  note: "Boot time of the session that NOTICED the dirty shutdown — i.e., the first boot after the crash / power loss. Subtract from the last surviving event in the PREVIOUS boot to bound when the unexpected shutdown occurred."
observations:
- proposition: UNCLEAN_SHUTDOWN
  ceiling: C3
  note: 'Definitive marker that the previous boot ended without a System-1074 clean-shutdown event or sleep transition. Present on every dirty shutdown — crash, power loss, forced hard-off, VM host kill, battery run-down. Absence on a known-crashed system indicates evtx tampering (41 is in System.evtx which is separate from Security.evtx — a Security-only wipe does NOT touch this signal).'
  qualifier-map:
    object.machine: field:computer-name
    time.start: field:event-time
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX-level
  survival-signals:
  - System-41 followed within seconds by System-6005 (Event Log service started) and System-6009 (OS version banner) = normal dirty-reboot → boot sequence. Pattern is forensically benign by itself, but its TIMING matters when placed on a threat timeline.
  - System-41 minutes after a Security-1102 or an evtx-size-drop on Security = suspicious. Attacker wiped logs then forced reboot to flush RAM before forensic imaging.
  - Multiple System-41 events in rapid succession (hours apart) = unstable hardware OR deliberate repeat-reboot pattern (attacker cycling power to burn down journals).
  - System-41 with BugcheckCode=0 AND PowerButtonTimestamp=0 AND SleepInProgress=false = classic "forced soft shutdown via command" signature. Not conclusive on its own but fits attacker-forced-reboot IOC.
provenance: [ms-event-id-41-the-system-has-rebooted, mitre-t1070]
---

# System-41 — Kernel-Power Unexpected Shutdown

## Forensic value
Marks every boot whose predecessor session did not record a clean shutdown (System-1074) or sleep transition. The event is emitted by the CURRENT boot as a post-mortem — Windows compares the last-known power state from the previous session against the new boot and, when the previous session's shutdown wasn't recorded cleanly, logs 41.

For anti-forensic timelines: System-41 lives in `System.evtx`, not `Security.evtx`. An attacker clearing `Security.evtx` (Security-1102) does NOT clear 41 — and a forced reboot to flush RAM after a Security-clear leaves this telltale in the surviving System channel.

## Interpretation by field pattern

| BugcheckCode | PowerButtonTimestamp | SleepInProgress | Typical cause                           |
|--------------|----------------------|-----------------|-----------------------------------------|
| nonzero      | 0                    | false           | BSOD crash (check Minidump)             |
| 0            | nonzero              | false           | User held power button                  |
| 0            | 0                    | true            | Failed sleep transition                 |
| 0            | 0                    | false           | Power loss, VM host kill, OR forced soft shutdown via command |

The last row is the attacker-forced-reboot pattern (`shutdown /r /f /t 0`, `Stop-Computer -Force`, remote WMI reboot). No crash, no button, no sleep — just "next boot noticed the previous session didn't say goodbye."

## Concept references
- MachineNetBIOS (Computer field)

## Cross-reference
- **System-1074** — clean shutdown initiated. Paired opposite of 41. Presence of 1074 with matching timestamp = normal. Absence next to 41 = dirty shutdown.
- **System-6005** — Event Log service started (next-boot marker). Fires right after 41.
- **System-6006** — Event Log service stopped cleanly. Present on clean shutdown, missing on dirty.
- **System-6008** — "The previous system shutdown at \<time\> was unexpected." Parallel marker to 41 on older Windows (Vista / 7 era); 41 superseded it on Windows 8+.
- **Security-1102** — Security log cleared. 41 minutes after 1102 = forced-reboot-after-wipe IOC.
- **ShutdownTime** — registry value under `HKLM\SYSTEM\CurrentControlSet\Control\Windows\ShutdownTime` carries the last CLEAN shutdown. Delta between ShutdownTime and 41's TimeCreated bounds the unexpected-shutdown window.
- **WER-Report** — if BugcheckCode was nonzero, the memory dump + WER report may have been written.

## Practice hint
Force a dirty reboot in a lab VM (pull the VM host "Power Off" — NOT "Shutdown"). Boot and check System.evtx for 41. Observe: BugcheckCode=0, PowerButtonTimestamp=0, SleepInProgress=false. This is the exact signature an attacker-forced soft reboot produces, which is the point — the event doesn't distinguish "VM yanked" from "attacker ran shutdown /f".
