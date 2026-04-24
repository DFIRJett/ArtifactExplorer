---
name: Defender-1117
title-description: "Microsoft Defender Antivirus performed an action to protect from malware"
aliases: [Defender action taken]
link: security
tags: [detection, action-taken]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Windows Defender/Operational
platform:
  windows: {min: '7', max: '11'}
location:
  channel: Microsoft-Windows-Windows Defender/Operational
  event-id: 1117
  provider: Microsoft-Windows-Windows Defender
fields:
- name: ThreatName
  kind: label
  location: EventData → 'Threat Name'
- name: ActionName
  kind: flag
  location: EventData → 'Action Name'
  note: "Quarantine | Remove | Clean | Allow | UserDefined | Block"
- name: Path
  kind: path
  location: EventData → 'Path'
  references-data:
  - {concept: ExecutablePath, role: scannedTarget}
- name: DetectionUser
  kind: identifier
  location: EventData → 'Detection User'
  references-data:
  - {concept: UserSID, role: actingUser}
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: DEFENDER_ACTION_TAKEN
  ceiling: C4
  note: "Defender took action on detected threat. Pair with 1116 (detection). ActionName=Allow = user override — critical for case-building."
  qualifier-map:
    object.threat.name: field:ThreatName
    object.action: field:ActionName
    object.file.path: field:Path
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance:
  - ms-defender-events
---

# Defender-1117

## Forensic value
Counterpart to 1116 (detection). 1117 records what Defender DID — quarantined, removed, or was overridden by user choice. A 1117 with ActionName=Allow or UserDefined indicates the user ignored the warning, a key point in negligence/intent cases.

## Cross-references
- **Defender-1116** — the triggering detection event
- **Defender-5001** — "real-time protection disabled" — check if this preceded the sequence (tampering)
- **Defender-MPLog** — richer text detail
