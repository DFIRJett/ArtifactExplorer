---
name: Defender-5001
title-description: "Microsoft Defender Antivirus Real-Time Protection is disabled"
aliases: [Defender real-time protection disabled]
link: security
tags: [tamper-indicator]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Windows Defender/Operational
platform:
  windows: {min: '7', max: '11'}
location:
  channel: Microsoft-Windows-Windows Defender/Operational
  event-id: 5001
  provider: Microsoft-Windows-Windows Defender
fields:
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
  references-data:
  - concept: FILETIME100ns
    role: absoluteTimestamp
observations:
- proposition: DEFENDER_TAMPERED
  ceiling: C4
  note: "Real-time protection disabled. On corporate / default-config systems this should NEVER fire in normal operation. Near-certain tamper indicator."
  qualifier-map:
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: service
detection-priorities:
  - "any 5001 on a managed endpoint — investigate immediately"
  - "5001 followed within minutes by 1116 (detection) or 1117 (action) — attacker dropped binary during the disable window"
provenance:
  - ms-protect-security-settings-with-tamp
  - mitre-t1562-001
  - ms-defender-events
---

# Defender-5001

## Forensic value
Real-time protection was disabled. On modern Windows, this requires local admin + tamper-protection off + explicit policy change. Sequence of 5001 → attacker activity → 5001 (re-enabled) is a classic "quiet window" attacker pattern.

## Cross-references
- **Defender-1116** / **1117** — if any fire AFTER the 5001, the disable was mid-attack
- **Defender-MPLog** — richer context; 5001-adjacent log lines show what triggered
- **Sysmon-1** — what process invoked the disable (Set-MpPreference, Set-MpPreference -DisableRealtimeMonitoring $true)
