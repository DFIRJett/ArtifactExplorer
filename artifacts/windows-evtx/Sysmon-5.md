---
name: Sysmon-5
title-description: "Process terminated"
aliases: [Sysmon ProcessTerminate]
link: application
tags: [process-lifecycle]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Sysmon-Operational
platform: {windows: {min: '7', max: '11'}, windows-server: {min: '2008R2', max: '2022'}}
location: {channel: "Microsoft-Windows-Sysmon/Operational", event-id: 5, provider: Microsoft-Windows-Sysmon, addressing: evtx-record}
fields:
- {name: process-id, kind: identifier, location: "EventData → ProcessId", encoding: uint32, references-data: [{concept: ProcessId, role: actingProcess}]}
- {name: image, kind: path, location: "EventData → Image", encoding: utf-16le, references-data: [{concept: ExecutablePath, role: ranProcess}]}
- {name: process-guid, kind: identifier, location: "EventData → ProcessGuid", encoding: guid-string, note: "Sysmon-assigned unique process instance ID — joins reliably to Sysmon-1 (create) across PID reuse."}
- {name: utc-time, kind: timestamp, location: "EventData → UtcTime", encoding: ISO-8601 UTC, clock: system, resolution: 1ms}
observations:
- {proposition: PROCESS_TERMINATED, ceiling: C3, note: 'Pairs with Sysmon-1 (ProcessCreate) via ProcessGuid for exact-process lifecycle bracketing. Critical when PID reuse makes PID-only joins unreliable. Attacker-cleanup TerminateProcess calls against rival AV / EDR surface here.', qualifier-map: {actor.process: field:process-id, object.path: field:image, time.end: field:utc-time}}
provenance: [ms-sysmon-system-monitor]
---

# Sysmon-5 — ProcessTerminate
Process exit event. ProcessGuid joins reliably to Sysmon-1 across PID reuse. Kill-rival-AV patterns surface here.
