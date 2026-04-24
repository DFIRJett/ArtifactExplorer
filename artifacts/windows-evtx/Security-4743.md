---
name: Security-4743
title-description: "A computer account was deleted"
aliases: [4743, computer account deleted]
link: system
tags: [ad-audit, account-lifecycle]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform: {windows: {min: '7', max: '11'}, windows-server: {min: '2008', max: '2022'}}
location: {channel: Security, event-id: 4743, provider: Microsoft-Windows-Security-Auditing, addressing: evtx-record}
fields:
- {name: target-computer-sid, kind: identifier, location: "EventData → TargetSid", encoding: SID, references-data: [{concept: UserSID, role: identitySubject}]}
- {name: target-computer-name, kind: label, location: "EventData → TargetUserName", encoding: utf-16le, references-data: [{concept: MachineNetBIOS, role: trackerMachineId}]}
- {name: subject-user-sid, kind: identifier, location: "EventData → SubjectUserSid", encoding: SID, references-data: [{concept: UserSID, role: actingUser}]}
- {name: event-time, kind: timestamp, location: "System/TimeCreated", encoding: xs:dateTime UTC, clock: system, resolution: 1ms}
observations:
- {proposition: ACCOUNT_DELETED, ceiling: C3, qualifier-map: {actor.user: field:subject-user-sid, object.user: field:target-computer-sid, time.start: field:event-time}}
provenance: [ms-event-4743, ms-audit-computer-account-management, ms-kb5008102-samr-hardening-cve-2021-42278]
---

# Security-4743 — Computer Account Deleted
Companion to 4741 (created) / 4742 (changed). Attacker-initiated computer-account delete may be persistence-cleanup.
