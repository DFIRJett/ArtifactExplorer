---
name: TaskScheduler-141
title-description: "Task deleted"
aliases: [task deleted]
link: persistence
tags: [cleanup-indicator]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-TaskScheduler/Operational
platform:
  windows: {min: Vista, max: '11'}
location:
  channel: Microsoft-Windows-TaskScheduler/Operational
  event-id: 141
  provider: Microsoft-Windows-TaskScheduler
fields:
- name: TaskName
  kind: identifier
  location: EventData → TaskName
  references-data:
  - {concept: TaskName, role: registeredTask}
- name: UserName
  kind: label
  location: EventData → UserName
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: TASK_DELETED
  ceiling: C3
  note: "Scheduled task removed. Pair with 106 (register) and 140 (update) to rebuild the full task lifecycle. A 106 → ... → 141 sequence on the same TaskName within an incident window is a classic cleanup pattern."
  qualifier-map:
    actor.user: field:UserName
    object.task.name: field:TaskName
    time.deleted: field:TimeCreated
anti-forensic:
  write-privilege: service
  bypass: "direct TaskCache registry deletion bypasses 141; also bypassed by Tarrask SD-value-deletion (task persists but is hidden from enumeration)"
provenance:
  - ms-task-scheduler-2-0-xml-schema-refer
  - mitre-t1070
---

# TaskScheduler-141

## Forensic value
Delete event for scheduled tasks. Companion to 106 (registered) and 140 (updated). Critical cleanup-phase indicator: attackers who create, execute, and delete a task leave the 106 → 200/201 → 141 sequence as the only surviving trace.

## Cross-references
- **TaskScheduler-106** — registration
- **TaskScheduler-140** — modifications
- **TaskScheduler-200/201** — execution
- **Security-4699** — audited counterpart (requires Object Access audit)
- **Scheduled-Tasks** — if the registry TaskCache still has an orphan, it's a cleanup gap
