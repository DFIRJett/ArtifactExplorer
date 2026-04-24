---
name: TaskScheduler-200
title-description: "Action started"
aliases:
- Task action started
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
  event-id: 200
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
  note: "full path of the action binary — the ImagePath TaskScheduler will launch"
  references-data:
  - concept: ExecutablePath
    role: ranProcess
- name: TaskInstanceId
  kind: identifier
  location: EventData → TaskInstanceId
  note: GUID per launch — joins 200 (started) with 201 (completed)
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: TASK_ACTION_EXECUTED
  ceiling: C4
  exit-node: false
  note: "Task action launched. Shows TaskName + actual executable path. Strongest per-launch evidence of scheduled-task-driven execution."
  qualifier-map:
    object.task.name: field:TaskName
    object.task.executable: field:ActionName
    object.task.instance: field:TaskInstanceId
    time.start: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance:
  - ms-task-scheduler-2-0-xml-schema-refer
  - mitre-t1053-005
---

# TaskScheduler-200

## Forensic value
Every scheduled-task launch. Carries the actual ActionName (binary that ran) at run-time — critical because the registry may hold one version of the task definition while the EVTX captures what ACTUALLY ran at a specific moment. Discrepancies between registry ActionName and evtx ActionName indicate the task was modified between install and the recorded run.

## Join-key use
TaskName + TaskInstanceId together. TaskInstanceId is a GUID shared by the matching 201 (completed) — pair them to compute run duration and detect hangs / failures.
