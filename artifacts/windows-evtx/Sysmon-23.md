---
name: Sysmon-23
title-description: "File delete archived (FileDelete logged — preserves deleted content)"
aliases: [Sysmon FileDelete archived, Sysmon 23]
link: file
tags: [file-delete-preservation, anti-forensics-counter]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Sysmon-Operational
platform: {windows: {min: '10', max: '11'}, windows-server: {min: '2019', max: '2022'}}
location: {channel: "Microsoft-Windows-Sysmon/Operational", event-id: 23, provider: Microsoft-Windows-Sysmon, addressing: evtx-record}
fields:
- {name: target-filename, kind: path, location: "EventData → TargetFilename", encoding: utf-16le, references-data: [{concept: ExecutablePath, role: ranProcess}]}
- {name: hashes, kind: hash, location: "EventData → Hashes", encoding: "MD5 / SHA256 per config", references-data: [{concept: ExecutableHash, role: contentHash}]}
- {name: archived, kind: flags, location: "EventData → Archived", encoding: "true/false", note: "When true, Sysmon preserved the deleted file's bytes in its archive directory (configurable). Analyst can recover the deleted file from Sysmon's cache even after true deletion."}
- {name: process-id, kind: identifier, location: "EventData → ProcessId", encoding: uint32, references-data: [{concept: ProcessId, role: actingProcess}]}
- {name: image, kind: path, location: "EventData → Image", encoding: utf-16le}
- {name: utc-time, kind: timestamp, location: "EventData → UtcTime", encoding: ISO-8601 UTC, clock: system, resolution: 1ms}
observations:
- {proposition: FILE_DELETED, ceiling: C4, note: 'Sysmon-23 (added Sysmon v13+) with Archived=true PRESERVES the deleted file''s bytes in Sysmon''s archive directory — defeats attacker cleanup. Configure via Sysmon config XML <FileDelete onmatch="include">. Enterprise-grade anti-anti-forensic countermeasure.', qualifier-map: {actor.process: field:process-id, object.path: field:target-filename, object.hash: field:hashes, time.end: field:utc-time}}
provenance: [ms-sysmon-system-monitor]
---

# Sysmon-23 — FileDelete Archived
Sysmon v13+ feature. Archived=true → deleted file bytes preserved in Sysmon archive directory. Counter-anti-forensic primitive.
