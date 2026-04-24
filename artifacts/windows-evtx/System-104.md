---
name: System-104
title-description: "The System log file was cleared"
aliases:
- 104
- System log cleared
- Eventlog 104
link: security
link-secondary: evasion
tags:
- timestamp-carrying
- tamper-hard
- anti-forensic-signal
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: System
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  channel: System
  event-id: 104
  provider: Microsoft-Windows-Eventlog
  addressing: evtx-record
  note: |
    System-channel equivalent of Security-1102. Written BY the act of clearing the System log — after `wevtutil cl System` or MMC Event Viewer "Clear Log" on System, the now-empty System.evtx starts fresh with event 104 as its first entry, naming who cleared it and when. Attackers targeting System.evtx specifically (to hide System-104, System-41, System-1074, System-7045 service-install, or other power/service evidence) leave this 104 as their tombstone unless they bypass wevtutil entirely (service-stop + file-delete avoids writing a fresh 104 but creates its own gap signature).
fields:
- name: event-time
  kind: timestamp
  location: "System → TimeCreated"
  encoding: xs:dateTime UTC
  clock: system
  resolution: 1us
  note: "The moment the System log was cleared — this is the very first timestamp in the post-clear System.evtx."
- name: channel-cleared
  kind: label
  location: "UserData → LogFileCleared → Channel"
  encoding: utf-16le
  note: "The channel whose log was cleared — usually 'System' (matching the container) but 104 is emitted to the System log when OTHER non-Security channels are cleared too (Application, Setup, custom admin channels). The Channel field disambiguates which log the clear actually targeted."
- name: subject-user-sid
  kind: identifier
  location: "UserData → LogFileCleared → SubjectUserSid"
  encoding: SID
  references-data:
  - concept: UserSID
    role: actingUser
  note: "SID of the account that cleared the log — requires membership in Administrators / Backup Operators / Event Log Readers group OR equivalent 'Manage auditing and security log' right."
- name: subject-user-name
  kind: label
  location: "UserData → LogFileCleared → SubjectUserName"
  encoding: utf-16le
- name: subject-domain-name
  kind: label
  location: "UserData → LogFileCleared → SubjectDomainName"
  encoding: utf-16le
- name: subject-logon-id
  kind: identifier
  location: "UserData → LogFileCleared → SubjectLogonId"
  encoding: hex LUID
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: "LUID of the session that initiated the clear. Joins to Security-4624 / 4634 around the event to identify how the clearing session was established (interactive / remote / scheduled / etc)."
- name: computer-name
  kind: label
  location: "System → Computer"
  encoding: NetBIOS hostname
  references-data:
  - concept: MachineNetBIOS
    role: trackerMachineId
observations:
- proposition: DELETED
  ceiling: C4
  note: |
    "System / Application log cleared" — the System-channel tamper tombstone.
    An investigator finding a 104 in the first-few-events position of System.evtx knows the log was cleared by the named user at the named time. For anti-forensic chains, pairs with Security-1102 when both Security and System are wiped in sequence — the PAIR is the strongest evidence of deliberate log manipulation (both channels cleared in the same session).
  qualifier-map:
    object.resource: field:channel-cleared
    actor.user: field:subject-user-sid
    actor.session: field:subject-logon-id
    time.start: field:event-time
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: EVTX-level; channel-wide retention policy applies after 104 as normal
  survival-signals:
  - System-104 by a non-privileged account (not Administrators / SYSTEM) = investigate privilege-escalation path that granted clear rights.
  - System-104 with Channel != 'System' = the System log captured a clear event for a DIFFERENT channel (e.g., Application). Cross-check whichever channel was named; the attacker targeted something specific.
  - System-104 timestamp within minutes of Security-1102 = coordinated dual-channel wipe. Strongest anti-forensic IOC for this combo — a casual clean-up job wouldn't bother with System.
  - System-104 with NO subsequent System-6005 (Event Log service started) = unusual; normally Event Log service restarts after a clear. Absence may indicate manual file-replacement instead of a clean wevtutil clear.
provenance:
  - mitre-t1070-001
---

# System-104 — System Log Cleared

## Forensic value
The tamper tombstone for non-Security channels. When an attacker runs `wevtutil cl System` (or clears Application / Setup / custom admin channels), the cleared log starts fresh with event 104 as its first record — naming SubjectUserSid, SubjectLogonId, and the exact moment.

Security-1102 covers the Security log. System-104 covers everything else. Sophisticated anti-forensic operations clear BOTH because a Security-only clear leaves System.evtx with full service-lifecycle (7045 installs, 41 unexpected shutdowns, 1074 clean shutdowns, 219 driver loads, 7036 state changes) — a rich attacker-evidence surface.

## Detection of coordinated wipes
The strongest IOC for deliberate log tampering is a **Security-1102 + System-104 pair** within the same session. Queries:

```powershell
# Security-1102 clears
Get-WinEvent -LogName Security -FilterHashtable @{Id=1102} -MaxEvents 20

# System-104 clears
Get-WinEvent -LogName System   -FilterHashtable @{Id=104}  -MaxEvents 20

# Both together — cross-correlate by SubjectLogonId + TimeCreated proximity
```

If the same SubjectLogonId appears in both within a short window, the attacker walked through both channels in one session.

## Concept references
- UserSID (SubjectUserSid), LogonSessionId (SubjectLogonId), MachineNetBIOS (Computer)

## Cross-reference
- **Security-1102** — paired tombstone for Security channel. The pair is forensically stronger than either alone.
- **System-6005** — Event Log service started. Usually appears right after a 104 because wevtutil restarts the service.
- **System-1074** / **System-41** — power-event records. 104 can be used to remove these, but the registry ShutdownTime value and WER-Report files survive outside evtx.
- **System-7045** — service installed (persistence). A common target of System-channel clears.

## Practice hint
In a lab VM: `wevtutil cl System` as admin, then check the post-clear System.evtx — event 104 is the ONLY pre-clear record preserved (everything else is gone). Observe the SubjectUserSid + SubjectLogonId in the record; this is the evidence the attacker couldn't avoid leaving.
