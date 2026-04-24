---
name: Sysmon-12
title-description: "Registry object added or deleted (CreateKey / DeleteKey)"
aliases: [Sysmon RegistryEvent CreateKey DeleteKey, Sysmon 12]
link: persistence
link-secondary: system
tags: [registry-create, persistence-primary]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Sysmon-Operational
platform: {windows: {min: '7', max: '11'}, windows-server: {min: '2008R2', max: '2022'}}
location: {channel: "Microsoft-Windows-Sysmon/Operational", event-id: 12, provider: Microsoft-Windows-Sysmon, addressing: evtx-record}
fields:
- {name: event-type, kind: enum, location: "EventData → EventType", encoding: "'CreateKey' / 'DeleteKey'"}
- {name: target-object, kind: path, location: "EventData → TargetObject", encoding: utf-16le (registry path), references-data: [{concept: RegistryKeyPath, role: subjectKey}]}
- {name: process-id, kind: identifier, location: "EventData → ProcessId", encoding: uint32, references-data: [{concept: ProcessId, role: actingProcess}]}
- {name: image, kind: path, location: "EventData → Image", encoding: utf-16le, references-data: [{concept: ExecutablePath, role: ranProcess}]}
- {name: utc-time, kind: timestamp, location: "EventData → UtcTime", encoding: ISO-8601 UTC, clock: system, resolution: 1ms}
observations:
- {proposition: REGISTRY_KEY_CREATED, ceiling: C3, note: 'Sysmon-12 captures CreateKey + DeleteKey — DIFFERENT from Sysmon-13 (value write). Required for detecting persistence that creates new subkeys (Run-key plants, service-key adds, COM-CLSID subkey creation). Pair with 13 for complete registry change visibility.', qualifier-map: {actor.process: field:process-id, setting.registry-path: field:target-object, time.start: field:utc-time}}
provenance: [ms-sysmon-system-monitor]
---

# Sysmon-12 — RegistryEvent (CreateKey / DeleteKey)
Structure-level registry changes (create + delete subkey). Pairs with Sysmon-13 (value set) and 14 (rename) for complete registry change coverage.
