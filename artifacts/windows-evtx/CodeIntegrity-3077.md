---
name: CodeIntegrity-3077
title-description: "Code Integrity determined that a process attempted to load a module that did not meet the signing-level requirements"
aliases: [WDAC image blocked, HVCI integrity violation]
link: security
tags: [detection, kernel]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-CodeIntegrity/Operational
platform:
  windows: {min: '8.1', max: '11'}
location:
  channel: Microsoft-Windows-CodeIntegrity/Operational
  event-id: 3077
  provider: Microsoft-Windows-CodeIntegrity
fields:
- name: File
  kind: path
  location: EventData → File
  references-data:
  - {concept: ExecutablePath, role: scannedTarget}
- name: Hash
  kind: hash
  location: EventData → Hash
  references-data:
  - {concept: ExecutableHash, role: detectedHash}
- name: PolicyGuid
  kind: identifier
  location: EventData → PolicyGuid
  note: "WDAC policy that produced the block"
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: CODE_INTEGRITY_BLOCK
  ceiling: C4
  note: "WDAC / HVCI / driver-signing policy blocked loading this image. Kernel-enforced — stronger than AppLocker. Non-zero count on a default-policy system is high-signal (attacker driver / BYOVD attempt)."
  qualifier-map:
    object.file.path: field:File
    object.file.hash: field:Hash
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance:
  - ms-wdac-policy-file-format-and-enforce
---

# CodeIntegrity-3077

## Forensic value
Kernel-level image-block event. WDAC / HVCI / driver-signing policy prevented a binary or driver from loading. Stronger signal than AppLocker because CI is kernel-enforced — attackers who bypass user-mode AV can still trip this.

## Cross-references
- **Sysmon-6** (Driver loaded) — the load attempt that CI blocked
- **AppLocker-8004** — user-mode equivalent for binaries
- **Amcache-InventoryDriverBinary** — driver catalog cross-reference
