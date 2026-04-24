---
name: Sysmon-2
title-description: "File creation time changed (timestomping indicator)"
aliases: [Sysmon FileCreateTime, timestomp]
link: file
tags: [timestomp, tamper-signal, itm:AF]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Sysmon-Operational
platform: {windows: {min: '7', max: '11'}, windows-server: {min: '2008R2', max: '2022'}}
location: {channel: "Microsoft-Windows-Sysmon/Operational", event-id: 2, provider: Microsoft-Windows-Sysmon, addressing: evtx-record}
fields:
- {name: target-filename, kind: path, location: "EventData → TargetFilename", encoding: utf-16le, references-data: [{concept: ExecutablePath, role: ranProcess}]}
- {name: previous-creation-time, kind: timestamp, location: "EventData → PreviousCreationUtcTime", encoding: ISO-8601 UTC, clock: system, resolution: 1ms, note: "Creation time BEFORE the set. Delta vs CreationUtcTime reveals direction of timestomp (backdate)."}
- {name: creation-time, kind: timestamp, location: "EventData → CreationUtcTime", encoding: ISO-8601 UTC, clock: system, resolution: 1ms}
- {name: process-id, kind: identifier, location: "EventData → ProcessId", encoding: uint32, references-data: [{concept: ProcessId, role: actingProcess}]}
- {name: image, kind: path, location: "EventData → Image", encoding: utf-16le, references-data: [{concept: ExecutablePath, role: ranProcess}]}
observations:
- {proposition: TIMESTAMP_MODIFIED, ceiling: C4, note: 'Sysmon-2 is THE timestomping detection event. Fires only when SetFileTime or equivalent API changes the creation time of an existing file — not on new-file creation. Classic attacker indicator: backdate newly-dropped binaries to blend with existing files.', qualifier-map: {actor.process: field:process-id, object.path: field:target-filename, time.start: field:creation-time}}
provenance: [ms-sysmon-system-monitor, mitre-t1070-006]
---

# Sysmon Event 2 — FileCreateTime
Timestomping detection. PreviousCreationUtcTime vs CreationUtcTime delta reveals the backdate direction. Pair with MFT $SI vs $FN comparison for multi-source confirmation.
