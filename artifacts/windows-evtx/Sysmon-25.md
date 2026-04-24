---
name: Sysmon-25
title-description: "Process tampering (image hollowing / process herpaderping / doppelgänging detected)"
aliases: [Sysmon ProcessTampering, Sysmon 25, image hollowing]
link: application
tags: [process-tampering, injection-detection, rootkit-detection]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Sysmon-Operational
platform: {windows: {min: '10', max: '11'}, windows-server: {min: '2019', max: '2022'}}
location: {channel: "Microsoft-Windows-Sysmon/Operational", event-id: 25, provider: Microsoft-Windows-Sysmon, addressing: evtx-record}
fields:
- {name: process-id, kind: identifier, location: "EventData → ProcessId", encoding: uint32, references-data: [{concept: ProcessId, role: actingProcess}]}
- {name: image, kind: path, location: "EventData → Image", encoding: utf-16le, references-data: [{concept: ExecutablePath, role: ranProcess}]}
- {name: tamper-type, kind: enum, location: "EventData → Type", encoding: "'Image is replaced' / 'Image is replaced by other process'", note: "Distinguishes self-hollowing from remote-hollowing. Image replacement = the PE on disk doesn't match the in-memory image = classic injection / hollowing."}
- {name: utc-time, kind: timestamp, location: "EventData → UtcTime", encoding: ISO-8601 UTC, clock: system, resolution: 1ms}
observations:
- {proposition: PROCESS_INJECTED, ceiling: C4, note: 'Sysmon-25 (v13+) detects process-hollowing and related process-tampering techniques. Type field distinguishes self-vs-remote tampering. High-signal — Sysmon-25 with non-MS Image is a strong injection indicator.', qualifier-map: {actor.process: field:process-id, object.path: field:image, time.start: field:utc-time}}
provenance: [ms-sysmon-system-monitor, mitre-t1055-012]
---

# Sysmon-25 — ProcessTampering
Image-hollowing / process-herpaderping / doppelgänging detection. Pair with Sysmon-10 (ProcessAccess) for injection-attempt telemetry.
