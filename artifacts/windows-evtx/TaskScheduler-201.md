---
name: TaskScheduler-201
title-description: "Action completed"
aliases:
- Task action completed
link: persistence
tags:
- execution
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
  event-id: 201
  provider: Microsoft-Windows-TaskScheduler
fields:
- name: TaskName
  kind: identifier
  location: EventData → TaskName
  references-data:
  - concept: TaskName
    role: executedTask
- name: ActionName
  kind: path
  location: EventData → ActionName
  references-data:
  - concept: ExecutablePath
    role: ranProcess
- name: TaskInstanceId
  kind: identifier
  location: EventData → TaskInstanceId
  note: GUID matching the paired 200 event
- name: ResultCode
  kind: status
  location: EventData → ResultCode
  note: "process exit code (hex). 0 = success; non-zero values reveal task failure — especially useful when attacker cleanup destroys the action binary after one run"
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: TASK_ACTION_COMPLETED
  ceiling: C3
  note: "Task action completed. Pair with 200 to compute duration; non-zero ResultCode = run failed or action missing."
  qualifier-map:
    object.task.name: field:TaskName
    object.task.instance: field:TaskInstanceId
    object.task.exit: field:ResultCode
    time.end: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance:
  - ms-task-scheduler-2-0-xml-schema-refer
  - mitre-t1053-005
---

# TaskScheduler-201

## Forensic value
Completion event for each task-action run. Pair with the matching 200 via TaskInstanceId for per-run duration. ResultCode is the action's process exit — non-zero values reveal failed launches (missing binary, permissions, errors) that would be invisible in the registry.

## Join-key use
TaskInstanceId is the intra-evtx join with 200. TaskName + ActionName cross-reference into Scheduled-Tasks registry configuration and into Prefetch / Amcache for actual binary execution evidence.
