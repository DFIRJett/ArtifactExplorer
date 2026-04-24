---
name: TaskName
kind: identifier
lifetime: persistent
link-affinity: persistence
description: |
  Windows Scheduled Task name/path — the forward-slash-delimited path
  that uniquely identifies a task (e.g., "\Microsoft\Windows\Defrag\ScheduledDefrag",
  "\MyEvilTask"). Both the Task Registry TaskCache\Tree\<path> key and the
  TaskScheduler/Operational evtx events carry this value.
canonical-format: "string path beginning with backslash, forward-slash-separated folders"
aliases: [scheduled-task-name, task-path]
roles:
  - id: identitySubject
    description: "Task's canonical path under \\Root — registry subkey path and evtx TaskName field match"
  - id: executedTask
    description: "Task name on run events (TaskScheduler-200, 201)"
  - id: registeredTask
    description: "Task name on register/update events (TaskScheduler-106, 140)"
  - id: scheduledTask
    description: "Task name mentioned as a scheduled-execution object (pre-execution, config-only) — task-XML config reference, GPP scheduled-task preference, Security-4699 deletion — distinct from execution / registration events"

known-containers:
  - Scheduled-Tasks
  - TaskScheduler-106
  - TaskScheduler-140
  - TaskScheduler-200
  - TaskScheduler-201
---

# Task Name

## What it is
The Windows Scheduled Task identifier — a backslash-rooted, forward-slash-delimited path matching the layout under `\Root\` in the Task Scheduler. Stored as a subkey path in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<path>` and as the `TaskName` field in every TaskScheduler/Operational event.

## Forensic join key
Registry carries the CURRENT configuration (Actions node with binary action blob, Triggers node with schedule, etc.). EVTX carries the HISTORICAL timeline (when registered, updated, ran, deleted). Join on TaskName to compare: registry says "task points at X"; evtx says "task ran N times between T1 and T2." Discrepancy = modification after creation.

## Detection pattern
A task with TaskScheduler-106 (registered), several 200/201 (ran), then 141 (deleted) — but still present in registry TaskCache — suggests a process created a task, ran it, deleted the tree node but left TaskCache\Tasks\<GUID> orphaned. A common cleanup gap.
