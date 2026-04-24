---
name: Sysmon-15
title-description: "FileCreateStreamHash — Alternate Data Stream created with hashed content"
aliases: [Sysmon ADS, Sysmon 15, FileCreateStreamHash]
link: file
tags: [ads-tracking, zone-identifier, exec-from-ads]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Sysmon-Operational
platform: {windows: {min: '7', max: '11'}, windows-server: {min: '2008R2', max: '2022'}}
location: {channel: "Microsoft-Windows-Sysmon/Operational", event-id: 15, provider: Microsoft-Windows-Sysmon, addressing: evtx-record}
fields:
- {name: target-filename, kind: path, location: "EventData → TargetFilename", encoding: "utf-16le (path:streamname format)", references-data: [{concept: ExecutablePath, role: ranProcess}]}
- {name: hash, kind: hash, location: "EventData → Hash", encoding: "SHA256 / MD5 / SHA1 per config", references-data: [{concept: ExecutableHash, role: contentHash}]}
- {name: creation-utc-time, kind: timestamp, location: "EventData → CreationUtcTime", encoding: ISO-8601 UTC, clock: system, resolution: 1ms}
- {name: process-id, kind: identifier, location: "EventData → ProcessId", encoding: uint32, references-data: [{concept: ProcessId, role: actingProcess}]}
- {name: image, kind: path, location: "EventData → Image", encoding: utf-16le}
observations:
- {proposition: ADS_CREATED, ceiling: C4, note: 'Sysmon-15 fires on ANY NTFS Alternate Data Stream creation with content hash — including Zone.Identifier (MOTW: downloaded files) and attacker-hidden payload streams (`calc.exe:hidden.exe`). The HASH field is unique among Sysmon events — lets you fingerprint the hidden stream without reading it. Essential for execution-from-ADS detection.', qualifier-map: {actor.process: field:process-id, object.path: field:target-filename, object.hash: field:hash, time.start: field:creation-utc-time}}
provenance: [ms-sysmon-system-monitor, mitre-t1564-004]
---

# Sysmon-15 — FileCreateStreamHash (ADS with content hash)
Zone.Identifier MOTW records here; so do attacker-hidden-in-ADS payloads. Hash field is unique — fingerprint hidden streams without reading.
