---
name: TaskScheduler-140
title-description: "Task updated"
aliases:
- Task updated
link: persistence
tags:
- persistence-primary
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
  event-id: 140
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
- proposition: TASK_UPDATED
  ceiling: C3
  note: "Scheduled task definition updated (actions / triggers / principals changed). The classic post-install persistence modification."
  qualifier-map:
    actor.user: field:UserContext
    object.task.name: field:TaskName
    time.modified: field:TimeCreated
anti-forensic:
  write-privilege: service
detection-priorities:
  - "106 (register) + 140 (update) sequence on the same TaskName within minutes — tamper-after-create pattern"
provenance:
  - ms-task-scheduler-2-0-xml-schema-refer
  - mitre-t1053-005
---

# TaskScheduler-140

## Forensic value
Task definition modification. Attackers commonly register a benign-looking task, then update the Actions node to add a malicious payload after the initial audit noise settles. A 106→140 sequence on the same TaskName within a short window is a signature pattern.

## Join-key use
TaskName + UserContext together reconstruct the modification timeline. Cross-reference Scheduled-Tasks registry artifact for the CURRENT (post-modification) configuration; compare against the action blob at time of 106 if preserved elsewhere.
