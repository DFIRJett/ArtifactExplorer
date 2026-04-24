---
name: Scheduled-Tasks
aliases:
- Task Scheduler
- schtasks
- at-jobs
link: persistence
tags:
- timestamp-carrying
- tamper-easy
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  hive: SOFTWARE
  path: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{task-GUID}
  also: parallel XML files at %WINDIR%\System32\Tasks\<folder>\<taskname>
  addressing: hive+key-path-plus-xml-sibling
fields:
- name: task-guid
  kind: identifier
  location: '{task-GUID} subkey name'
  encoding: guid-string
- name: task-path
  kind: path
  location: Path value
  type: REG_SZ
  note: namespace path like '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan'
  references-data:
  - concept: TaskName
    role: identitySubject
- name: action-executable
  kind: path
  location: Actions value (binary blob) — parsed action command
  type: REG_BINARY
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
- name: principal-sid
  kind: identifier
  location: Actions blob — running-as principal
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: actingUser
  note: task runs under this account; may be SYSTEM, LOCAL SERVICE, NETWORK SERVICE, or a real user
- name: hash
  kind: identifier
  location: Hash value
  type: REG_BINARY
  encoding: SHA256 of the task definition XML (Win8+)
  note: integrity check — tasks whose XML was modified out-of-band fail to load
- name: dynamic-info
  kind: identifier
  location: DynamicInfo value
  type: REG_BINARY
  note: last-run + last-result + next-run time blob; requires version-specific parsing
- name: last-run-time
  kind: timestamp
  location: DynamicInfo blob offset
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: next-run-time
  kind: timestamp
  location: DynamicInfo blob offset
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: last-result
  kind: enum
  location: DynamicInfo blob offset
  encoding: uint32
  note: Win32 error code of last task run; 0 = success
- name: xml-file-reference
  kind: path
  location: paired %WINDIR%\System32\Tasks\<path> file
  encoding: filesystem-path
  note: full task XML lives here — triggers, settings, actions in human-readable XML
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'Persistent scheduled task — runs on trigger (time, event, logon, boot,

    etc.) under the specified principal. Second most common persistence

    mechanism after Run keys, and preferred by modern malware because it

    can target SYSTEM context.

    '
  qualifier-map:
    setting.task-guid: field:task-guid
    setting.task-path: field:task-path
    setting.executable: field:action-executable
    actor.user: field:principal-sid
    time.start: field:last-run-time
anti-forensic:
  write-privilege: admin
  integrity-mechanism: task XML hash validated against registry Hash value
  known-cleaners:
  - tool: schtasks /delete
    typically-removes: partial
    note: removes registry + XML; audit-log entries in TaskScheduler/Operational may persist
  - tool: direct registry + XML file delete
    typically-removes: full
  survival-signals:
  - Registry Tasks subkey present but paired XML file absent = partial cleanup (XML deleted, registry missed)
  - Task principal-sid == SYSTEM + action path in %TEMP% or user AppData = high-suspicion pattern
  - Hash mismatch between registry and XML = XML was modified without updating the hash; forensic tampering
provenance:
  - ms-task-scheduler-1-0-legacy-format-re
  - ms-task-scheduler-2-0-xml-schema-refer
  - mitre-t1053-005
exit-node:
  is-terminus: true
  primary-source: mitre-t1053-005
  attribution-sentence: 'Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code (MITRE ATT&CK, n.d.).'
  terminates:
    - PERSISTED
  sources:
    - ms-task-scheduler-2-0-xml-schema-refer
    - mitre-t1053-005
  reasoning: >-
    The Scheduled Tasks registry cache (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree and ...\Tasks) plus the XML files under %WINDIR%\System32\Tasks are the authoritative definition of every scheduled task — TaskName, Trigger, Action (executable + arguments), RunAs principal, conditions. For 'what task is configured here and what does it run,' this is the terminus.
  implications: >-
    Defensible attribution for task-based persistence. When TaskScheduler-106 (task created) / -140 (updated) / -141 (deleted) events are missing, the current TaskCache + XML state still proves the task definition and first-created-time via the XML file's NTFS $FN creation timestamp. Commodity-malware favorites (MS17-010 backdoor task / Ryuk task-persistence / schtasks /ru SYSTEM from compromised admin) all terminate their persistence chain at this artifact.
  preconditions: 'TaskCache subkey AND %WINDIR%\System32\Tasks both available; attacker did not run "schtasks /delete" + XML file cleanup (leaves USN-journal rename trail)'
  identifier-terminals-referenced:
    - TaskName
    - ExecutablePath
    - UserSID
---

# Windows Scheduled Tasks

## Forensic value
Persistence mechanism that runs programs on triggers (time, boot, logon, session start, event log match, etc.). Malware uses scheduled tasks because:
- Can run as SYSTEM even from user-context creation
- Can evade event-log auditing with specific trigger types
- Legitimate tasks provide camouflage (1000+ Microsoft-built-in tasks exist)

## Concept references
- ExecutablePath (action path)
- UserSID (principal)

## Two-location format is a parsing gotcha
Every scheduled task exists in TWO places simultaneously:
1. **Registry** (SOFTWARE hive, TaskCache\Tasks\{GUID}) — binary-encoded action + integrity hash
2. **Filesystem** (%WINDIR%\System32\Tasks\...) — human-readable XML with triggers, settings, author

Some parsers use only one or the other. Always acquire both; cross-check hash integrity.

## Investigative starting points
- Principal SYSTEM + non-Microsoft-signed action = high suspicion
- Recent task creation timestamps = recent persistence establishment
- Tasks whose XML references paths in user temp directories
- Tasks with triggers on specific event-log events (evasion via legitimate-looking trigger)

## Practice hint
List all tasks with `schtasks /query /fo LIST /v`. Grep output for `Author:` and `Run As User:` — the surprising patterns surface quickly. Match against Microsoft-signed baseline to narrow to non-default entries.
