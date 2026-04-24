---
name: Security-4698
title-description: "A scheduled task was created"
aliases: [scheduled task created audit]
link: persistence
tags: [persistence-primary, audit-policy-dependent]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: {min: '7', max: '11'}
location:
  channel: Security
  event-id: 4698
  provider: Microsoft-Windows-Security-Auditing
  requirement: "auditpol /set /subcategory:\"Other Object Access Events\" /success:enable — OFF by default"
fields:
- name: SubjectUserSid
  kind: identifier
  location: EventData → SubjectUserSid
  references-data:
  - {concept: UserSID, role: actingUser}
- name: SubjectUserName
  kind: label
  location: EventData → SubjectUserName
- name: SubjectDomainName
  kind: label
  location: EventData → SubjectDomainName
- name: SubjectLogonId
  kind: identifier
  location: EventData → SubjectLogonId
  references-data:
  - {concept: LogonSessionId, role: sessionContext}
- name: TaskName
  kind: identifier
  location: EventData → TaskName
  references-data:
  - {concept: TaskName, role: registeredTask}
- name: TaskContent
  kind: content
  location: EventData → TaskContent
  note: "FULL XML definition of the task at creation time — every Action, Trigger, Principal, Settings element. Priceless for post-facto analysis of tasks that have since been modified or deleted. Pair with TaskScheduler-106 (no audit policy requirement) for always-on coverage."
- name: ClientProcessStartKey
  kind: identifier
  location: EventData → ClientProcessStartKey
  encoding: uint64
  note: "Client-process start key — Win10 1903+. Opaque per-process identifier used by the task-scheduler service; pair with ClientProcessId for full invoker attribution."
- name: ClientProcessId
  kind: identifier
  location: EventData → ClientProcessId
  encoding: uint32
  references-data:
  - concept: ProcessId
    role: actingProcess
  note: "PID of the process that RPC-called schtasks. Win10 1903+. Hunt-gold field — reveals the actual invoker when schtasks is abused remotely."
- name: ParentProcessId
  kind: identifier
  location: EventData → ParentProcessId
  encoding: uint32
  references-data:
  - concept: ProcessId
    role: parentProcess
  note: "Parent PID of the invoking client process. Win10 1903+. Joins to 4688 to reconstruct the parent-child chain behind task creation."
- name: RpcCallClientLocality
  kind: enum
  location: EventData → RpcCallClientLocality
  encoding: uint32
  note: "RPC call locality (0 = unknown, 1 = local-same-host, 2 = remote). Non-local values indicate cross-host task creation via RPC — strong lateral-movement signal. Win10 1903+."
- name: FQDN
  kind: identifier
  location: EventData → FQDN
  note: "Fully-qualified domain name of the client host creating the task. Populated for remote (non-local) task creation. Win10 1903+."
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: TASK_CREATED_WITH_XML
  ceiling: C4
  note: "Audited task-creation event. Higher-fidelity than TaskScheduler-106 because it captures the full TaskContent XML (every trigger / action / principal). Caveat: bypassed entirely if the attacker writes directly to the TaskCache registry (Tarrask-style) without going through ITaskService RPC — confirmed by Qualys, WithSecure, Binary Defense."
  qualifier-map:
    actor.user.sid: field:SubjectUserSid
    object.task.name: field:TaskName
    object.task.xml: field:TaskContent
    time.created: field:TimeCreated
anti-forensic:
  write-privilege: service
  bypass: "direct TaskCache registry write bypasses both 4698 AND TaskScheduler-106"
provenance: [ms-event-4698, uws-event-4698, ms-tarrask-malware-uses-scheduled-task]
---

# Security-4698

## Forensic value
The authoritative audited task-creation event. Captures the FULL TaskContent XML — complete task definition as it existed at creation. Later modification events (4702) give TaskContentNew; together they reconstruct the modification history.

## Bypass path — Tarrask
Direct writes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*\Tasks\{Plain|Logon}\{GUID}` — registry-only registration — bypasses the ITaskService RPC path and produces NEITHER 4698 NOR TaskScheduler-106. Detect via direct registry hunting (yarp / RECmd against the live TaskCache).

## Cross-references
- **TaskScheduler-106** — always-on equivalent (no audit requirement)
- **Scheduled-Tasks** (registry) — current state
- **Security-4697** — sibling audited service-install event
