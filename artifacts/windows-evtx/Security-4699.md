---
name: Security-4699
title-description: "A scheduled task was deleted"
aliases:
- 4699
- Task deleted
link: persistence
link-secondary: user
tags:
- task-lifecycle
- tamper-signal
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows:
    min: '7'
    max: '11'
  windows-server:
    min: '2008R2'
    max: '2022'
location:
  channel: Security
  event-id: 4699
  provider: "Microsoft-Windows-Security-Auditing"
  addressing: evtx-record
  note: "Paired with Security-4698 (task registered) and Security-4702 (task updated) to form the full Scheduled Task lifecycle in the Security channel. 4699 fires when a task is deleted — via schtasks /Delete, Unregister-ScheduledTask, or Task Scheduler MMC. Subcategory: 'Other Object Access Events' (not on by default — must be enabled via auditpol)."
fields:
- name: subject-user-sid
  kind: identifier
  location: "EventData → SubjectUserSid"
  encoding: SID
  references-data:
  - concept: UserSID
    role: actingUser
  note: "SID of the user that deleted the task. For cleanup-trail investigations this identifies the removing actor."
- name: subject-logon-id
  kind: identifier
  location: "EventData → SubjectLogonId"
  encoding: hex LUID
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: "Logon session that made the change. Joins back to Security-4624."
- name: task-name
  kind: identifier
  location: "EventData → TaskName"
  encoding: utf-16le
  references-data:
  - concept: TaskName
    role: scheduledTask
  note: "Full task path (e.g., \\Microsoft\\Windows\\CustomTask\\<task>). Joins to Security-4698 of the SAME TaskName in the earlier lifecycle event pair."
- name: task-content
  kind: content
  location: "EventData → TaskContent"
  encoding: utf-16le XML
  note: "Snapshot of the task XML at deletion time. Preserves the Actions / Triggers / Principal that would otherwise be lost with the task itself — especially important when 4698 rolled."
- name: event-time
  kind: timestamp
  location: "System/TimeCreated"
  encoding: xs:dateTime UTC
  clock: system
  resolution: 1ms
  note: "Delete timestamp. Pair with preceding 4698 (task create) for lifecycle window."
observations:
- proposition: PERSISTENCE_REMOVED
  ceiling: C4
  note: 'Security-4699 is the cleanup-action-evidence event for scheduled
    tasks. Post-compromise cleanup often deletes persistence tasks the
    attacker installed. The TaskContent field preserves the XML of the
    deleted task — recovering what the persistence DID even though the
    task is gone. Cross-reference TaskName with surviving file-level
    artifacts (ScheduledTask-XML surviving on disk; Amcache for the
    executable the task ran).'
  qualifier-map:
    actor.user: field:subject-user-sid
    actor.session: field:subject-logon-id
    object.task: field:task-name
    time.start: field:event-time
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX-level
  survival-signals:
  - 4699 without prior 4698 in log = create happened before log rolled; combined with AMcache-inventory of task-referenced executable recovers most context
  - 4699 timestamp within hours of a 4698 for the same TaskName = short-lived task (classic attacker installation + cleanup pattern)
provenance: [ms-event-4699]
---

# Security-4699 — Scheduled Task Deleted

## Forensic value
Pairs with Security-4698 (task registered) to bracket a scheduled-task lifecycle. Critical for anti-forensic investigation: when an attacker deletes their persistence task, 4699 preserves the TaskContent XML — meaning the Actions / Triggers / RunAs / CommandLine of the deleted task are recoverable even though the task itself is gone.

## Concept references
- UserSID (SubjectUserSid), LogonSessionId (SubjectLogonId), TaskName

## Cross-reference
- **Security-4698** — task creation (partner event)
- **Security-4702** — task modification
- **ScheduledTask-XML** — surviving file-level XML in %WINDIR%\System32\Tasks\
- **TaskScheduler-141** — task-deleted event on Microsoft-Windows-TaskScheduler/Operational channel
