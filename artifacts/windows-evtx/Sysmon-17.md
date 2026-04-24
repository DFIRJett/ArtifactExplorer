---
name: Sysmon-17
title-description: "Named pipe created (PipeEvent Created)"
aliases: [Sysmon PipeEvent, Sysmon 17]
link: network
tags: [named-pipe, c2-detection, lateral-movement]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Sysmon-Operational
platform: {windows: {min: '7', max: '11'}, windows-server: {min: '2008R2', max: '2022'}}
location: {channel: "Microsoft-Windows-Sysmon/Operational", event-id: 17, provider: Microsoft-Windows-Sysmon, addressing: evtx-record}
fields:
- {name: pipe-name, kind: identifier, location: "EventData → PipeName", encoding: "utf-16le — \\\\\\\\.\\\\pipe\\\\<name> (single-leading-backslash in XML)", note: "Pipe name. Cobalt Strike default pipes (msagent_*, postex_*, status_*, mypipe-*) are famous IOC patterns. PsExec pipes (PSEXESVC). Named-pipe impersonation tools. Attacker C2 / lateral-movement fingerprint."}
- {name: image, kind: path, location: "EventData → Image", encoding: utf-16le, references-data: [{concept: ExecutablePath, role: ranProcess}]}
- {name: process-id, kind: identifier, location: "EventData → ProcessId", encoding: uint32, references-data: [{concept: ProcessId, role: actingProcess}]}
- {name: utc-time, kind: timestamp, location: "EventData → UtcTime", encoding: ISO-8601 UTC, clock: system, resolution: 1ms}
observations:
- {proposition: PIPE_CREATED, ceiling: C4, note: 'Pipe-name + creator-process detection surface for Cobalt Strike / Meterpreter / PsExec / custom-C2-frameworks. Strong fingerprinting opportunity — attacker pipe names are often unchanged across campaigns.', qualifier-map: {actor.process: field:process-id, peer.name: field:pipe-name, time.start: field:utc-time}}
provenance: [ms-sysmon-system-monitor]
---

# Sysmon-17 — Named Pipe Created
Cobalt Strike / Meterpreter / PsExec signature surface. Pipe name + creator process = strong fingerprint.
