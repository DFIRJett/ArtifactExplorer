---
name: Sysmon-14
title-description: "Registry key or value renamed"
aliases: [Sysmon RegistryEvent Rename, Sysmon 14]
link: persistence
tags: [registry-rename, evasion-signal]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Sysmon-Operational
platform: {windows: {min: '7', max: '11'}, windows-server: {min: '2008R2', max: '2022'}}
location: {channel: "Microsoft-Windows-Sysmon/Operational", event-id: 14, provider: Microsoft-Windows-Sysmon, addressing: evtx-record}
fields:
- {name: event-type, kind: enum, location: "EventData → EventType", encoding: "'RenameKey'"}
- {name: target-object, kind: path, location: "EventData → TargetObject", encoding: utf-16le, references-data: [{concept: RegistryKeyPath, role: subjectKey}]}
- {name: new-name, kind: label, location: "EventData → NewName", encoding: utf-16le, note: "Destination name after rename."}
- {name: process-id, kind: identifier, location: "EventData → ProcessId", encoding: uint32, references-data: [{concept: ProcessId, role: actingProcess}]}
- {name: utc-time, kind: timestamp, location: "EventData → UtcTime", encoding: ISO-8601 UTC, clock: system, resolution: 1ms}
observations:
- {proposition: REGISTRY_KEY_RENAMED, ceiling: C3, note: 'Registry rename — less common than create/delete/set. Attacker use: rename security-related subkeys to disable while keeping content (obscures vs delete); rename malicious subkey to blend with stock Microsoft naming.', qualifier-map: {actor.process: field:process-id, setting.registry-path: field:target-object, time.start: field:utc-time}}
provenance: [ms-sysmon-system-monitor]
---

# Sysmon-14 — RegistryEvent (RenameKey)
Registry rename. Distinctive enough to warrant its own event — attacker evasion pattern: rename-rather-than-delete for plausible-deniability.
