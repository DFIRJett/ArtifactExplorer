---
name: Sysmon-18
title-description: "Named pipe connected (client → server)"
aliases: [Sysmon PipeEvent Connected, Sysmon 18]
link: network
tags: [named-pipe, c2-detection, lateral-movement]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Sysmon-Operational
platform: {windows: {min: '7', max: '11'}, windows-server: {min: '2008R2', max: '2022'}}
location: {channel: "Microsoft-Windows-Sysmon/Operational", event-id: 18, provider: Microsoft-Windows-Sysmon, addressing: evtx-record}
fields:
- {name: pipe-name, kind: identifier, location: "EventData → PipeName", encoding: utf-16le}
- {name: image, kind: path, location: "EventData → Image", encoding: utf-16le, references-data: [{concept: ExecutablePath, role: ranProcess}], note: "Process connecting TO the pipe. Pairs with Sysmon-17 (creation) to capture the full pipe-client-server handshake — detecting both the framework's server side and the lateral-movement client side."}
- {name: process-id, kind: identifier, location: "EventData → ProcessId", encoding: uint32, references-data: [{concept: ProcessId, role: actingProcess}]}
- {name: utc-time, kind: timestamp, location: "EventData → UtcTime", encoding: ISO-8601 UTC, clock: system, resolution: 1ms}
observations:
- {proposition: PIPE_CONNECTED, ceiling: C3, note: 'Client-side pipe connect event. Captures the lateral-movement process connecting to attacker-server pipes. Pair with Sysmon-17 for complete C2 / PsExec visibility.', qualifier-map: {actor.process: field:process-id, peer.name: field:pipe-name, time.start: field:utc-time}}
provenance: [ms-sysmon-system-monitor]
---

# Sysmon-18 — Named Pipe Connected
Client-side pipe connect. Pairs with 17 for full handshake capture.
