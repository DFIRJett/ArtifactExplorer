---
name: TaskScheduler-106
title-description: "Task registered"
aliases:
- Task registered
link: persistence
tags:
- persistence-primary
- always-emitted
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-TaskScheduler/Operational
platform:
  windows:
    min: Vista
    max: '11'
location:
  channel: Microsoft-Windows-TaskScheduler/Operational
  event-id: 106
  provider: Microsoft-Windows-TaskScheduler
fields:
- name: TaskName
  kind: identifier
  location: EventData → TaskName
  references-data:
  - concept: TaskName
    role: registeredTask
- name: UserContext
  kind: label
  location: EventData → UserContext
  note: "account that registered the task (domain\\user or SID)"
  references-data:
  - concept: UserSID
    role: actingUser
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: TASK_REGISTERED
  ceiling: C3
  note: "Scheduled task registered (created). Pair with Scheduled-Tasks registry artifact: evtx gives install timestamp + registering user, registry gives current configuration."
  qualifier-map:
    actor.user: field:UserContext
    object.task.name: field:TaskName
    time.created: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance:
  - ms-task-scheduler-2-0-xml-schema-refer
  - mitre-t1053-005
---

# TaskScheduler-106

## Forensic value
Emitted when a new task is registered with the Task Scheduler. Unlike Security-4698 (which requires the File System audit policy to be on), TaskScheduler-106 fires unconditionally. Pair with:
- **Scheduled-Tasks** (registry): current configuration of the task
- **TaskScheduler-140**: subsequent updates to the task definition
- **TaskScheduler-200 / 201**: actual execution history

## Join-key use
TaskName joins across all four sources. Registering user (UserSID) joins back into the broader per-user activity chain.
