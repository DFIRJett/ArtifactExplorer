---
name: Security-4742
title-description: "A computer account was changed"
aliases: [4742, computer account changed]
link: system
tags: [ad-audit, account-lifecycle]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform: {windows: {min: '7', max: '11'}, windows-server: {min: '2008', max: '2022'}}
location: {channel: Security, event-id: 4742, provider: Microsoft-Windows-Security-Auditing, addressing: evtx-record}
fields:
- {name: target-computer-sid, kind: identifier, location: "EventData → TargetSid", encoding: SID, references-data: [{concept: UserSID, role: identitySubject}]}
- {name: target-computer-name, kind: label, location: "EventData → TargetUserName", encoding: utf-16le, references-data: [{concept: MachineNetBIOS, role: trackerMachineId}]}
- {name: subject-user-sid, kind: identifier, location: "EventData → SubjectUserSid", encoding: SID, references-data: [{concept: UserSID, role: actingUser}]}
- {name: user-account-control, kind: flags, location: "EventData → NewUacValue / OldUacValue", note: "Encoding caveat (2026-04-23): OldUacValue/NewUacValue carry MS-SAMR USER_ACCOUNT codes (MS-SAMR §2.2.1.12), NOT AD userAccountControl schema values. Bit layouts differ — e.g., TRUSTED_FOR_DELEGATION = 0x00002000 (SAM) vs 0x80000 (AD). See ms-samr-user-account-codes for the authoritative bitmask and ms-kb-useraccountcontrol for AD-side cross-reference. Cited values below reflect legacy AD-derived annotations and MUST be re-verified against MS-SAMR before SIEM rule-building. Attacker-high-signal: TRUSTED_FOR_DELEGATION / TRUSTED_TO_AUTH_FOR_DELEGATION set on a computer account = unconstrained or constrained delegation grant (Kerberos privilege escalation path)."}
- {name: event-time, kind: timestamp, location: "System/TimeCreated", encoding: xs:dateTime UTC, clock: system, resolution: 1ms}
observations:
- {proposition: ACCOUNT_MODIFIED, ceiling: C3, note: 'Delegation-flag changes on computer accounts = escalation path. Watch for Unconstrained Delegation grants.', qualifier-map: {actor.user: field:subject-user-sid, object.user: field:target-computer-sid, time.start: field:event-time}}
provenance: [ms-event-4742, ms-audit-computer-account-management, ms-kb5008102-samr-hardening-cve-2021-42278, ms-samr-user-account-codes, ms-kb-useraccountcontrol, eladshamir-spn-jacking, splunk-security-4742]
---

# Security-4742 — Computer Account Changed
Delegation flag changes are the primary attacker concern. TRUSTED_FOR_DELEGATION set = Kerberos unconstrained delegation abuse path.
