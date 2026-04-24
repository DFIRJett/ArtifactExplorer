---
name: Security-4688
title-description: "A new process has been created"
aliases:
- process-creation audit event
- new-process event
link: application
tags:
- timestamp-carrying
- tamper-hard
volatility: runtime
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows:
    min: '7'
    max: '11'
  windows-server:
    min: '2008'
    max: '2025'
location:
  channel: Security
  event-id: 4688
  log-file: '%WINDIR%\System32\winevt\Logs\Security.evtx'
  addressing: channel+event-id
fields:
- name: time-created
  kind: timestamp
  location: System\TimeCreated SystemTime
  encoding: iso8601-utc
  clock: system
  resolution: 1us
- name: subject-user-sid
  kind: identifier
  location: EventData\SubjectUserSid
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: actingUser
  note: the account under which the new process was created
- name: subject-user-name
  kind: identifier
  location: EventData\SubjectUserName
  encoding: utf-16le
- name: subject-domain-name
  kind: identifier
  location: EventData\SubjectDomainName
  encoding: utf-16le
  note: domain / workgroup / computer name of the subject
- name: subject-logon-id
  kind: identifier
  location: EventData\SubjectLogonId
  encoding: hex-uint64
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: "Session identifier — correlates with 4624 TargetLogonId for session context. Every process this session spawns carries this LUID as its SubjectLogonId, allowing backward chain 4688→4624 for full user-attribution."
- name: new-process-id
  kind: identifier
  location: EventData\NewProcessId
  encoding: hex-uint32
  references-data:
  - concept: ProcessId
    role: createdProcess
  note: "PID assigned to the newly-created process. Appears in subsequent 4663/4657/4658 events as ProcessId — the primary join key for reconstructing what this process did after creation."
- name: new-process-name
  kind: path
  location: EventData\NewProcessName
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: ranProcess
- name: token-elevation-type
  kind: enum
  location: EventData\TokenElevationType
  encoding: enum-string
  note: '%%1936=default, %%1937=elevated, %%1938=limited — UAC split-token indicator'
- name: mandatory-label
  kind: identifier
  location: EventData\MandatoryLabel (Win8+)
  encoding: sid-string
  note: integrity level — S-1-16-4096=low, 8192=medium, 12288=high, 16384=system
- name: parent-process-id
  kind: identifier
  location: EventData\ProcessId
  encoding: hex-uint32
  references-data:
  - concept: ProcessId
    role: parentProcess
  note: "PID of the process that spawned this one. Walk parent-child recursively by joining each parent-process-id to a preceding 4688's new-process-id to reconstruct the full process tree."
- name: parent-process-name
  kind: path
  location: EventData\ParentProcessName (Win10+)
  encoding: utf-16le
  note: added in Win10 — earlier versions only have parent PID, requiring cross-reference
- name: command-line
  kind: identifier
  location: EventData\CommandLine
  encoding: utf-16le
  note: ONLY populated if 'Include command line in process creation events' policy is enabled — often absent by default
- name: target-user-sid
  kind: identifier
  location: EventData\TargetUserSid (when process created in different user context)
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: targetUser
  note: populated for runas / CreateProcessAsUser scenarios where the creator and target identity differ. v2 / Win10+.
- name: target-user-name
  kind: identifier
  location: EventData\TargetUserName
  encoding: utf-16le
  note: target account name when the process is spawned in a different user context. v2 / Win10+.
- name: target-domain-name
  kind: identifier
  location: EventData\TargetDomainName
  encoding: utf-16le
  note: domain of the target account. v2 / Win10+.
- name: target-logon-id
  kind: identifier
  location: EventData\TargetLogonId
  encoding: hex-uint64
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: "LUID of the session the NEW process runs in (as opposed to SubjectLogonId which is the session that CREATED the process). Differs from SubjectLogonId only when runas / CreateProcessAsUser shifts identity. v2 / Win10+."
observations:
- proposition: EXECUTED
  ceiling: C4
  note: 'Kernel-logged process-creation event with SID, full path, parent PID,

    and (optionally) command line. Strongest native execution evidence on

    Windows when command-line auditing is enabled — often superior to

    Amcache/Prefetch because it captures parent/child relationships and

    command-line arguments.

    '
  qualifier-map:
    process.image-path: field:new-process-name
    process.command-line: field:command-line
    process.parent-image: field:parent-process-name
    actor.user: field:subject-user-sid
    process.session: field:subject-logon-id
    time.start: field:time-created
  preconditions:
  - Audit policy 'Process Creation' enabled (off by default on many SKUs)
  - 'For command-line: also enable ''Include command line in process creation events'' GPO'
  - Security.evtx retained across target window
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX record/chunk checksums
  known-cleaners:
  - tool: wevtutil clear-log Security
    typically-removes: full
    note: emits 1102 counter-signal
  - tool: audit-policy disable
    typically-removes: prospective
    note: silently stops NEW 4688 events — look for recent 4719 (audit policy changed)
  survival-signals:
  - 4688 events for recent sessions absent + 4624 logons present = targeted 4688 suppression via policy change
  - Event 4719 immediately before suspicious activity window = audit policy was just altered
provenance:
  - ms-event-4688
  - ms-include-command-line-in-process-cre
  - uws-event-4688
  - jpcert-2017-lateral-movement-detection-v2
---

# Security Event 4688 — Process Creation

## Forensic value
The authoritative process-creation audit event. Each 4688 records: executing user, full image path, parent process, and (if policy allows) command-line arguments. With command-line auditing on, 4688 is the single most detailed execution record Windows produces natively — captures arguments that Prefetch, Amcache, and BAM don't.

## Concept references
- ExecutablePath (NewProcessName)
- UserSID (SubjectUserSid)

## Known quirks
- **Command line absent by default.** Enabling requires both `Audit Process Creation = Success` and the GPO `Include command line in process creation events = Enabled`. Absence of CommandLine in an organization's 4688s reveals policy gaps.
- **Integrity label decoding.** `S-1-16-<level>` maps: 4096=Low, 8192=Medium, 12288=High, 16384=System. UAC-sensitive investigations need this.
- **ParentProcessName is Win10+.** Pre-Win10 gives only ParentProcessId — you must correlate across 4688 events to find the parent's 4688 and reconstruct the tree.
- **Token elevation type** distinguishes UAC-elevated from default tokens in the same user session.

## Anti-forensic caveats
Disabling 4688 via policy is the most common evasion. Check for **Event 4719** (audit policy changed) around the investigation window — attackers who disable 4688 often leave this trace.

## Practice hint
On a Win10 VM with process-creation + command-line auditing enabled, open PowerShell and run `Start-Process calc.exe`. Parse the resulting 4688 — confirm CommandLine, ParentProcessName (powershell.exe), and SubjectUserSid (your user). Then disable CLI auditing, re-run, observe missing CommandLine field.
