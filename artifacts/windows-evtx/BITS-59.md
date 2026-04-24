---
name: BITS-59
title-description: "BITS Client started transferring"
aliases: [BITS job started]
link: network
tags: [lolbin, execution]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Bits-Client/Operational
platform:
  windows: {min: Vista, max: '11'}
location:
  channel: Microsoft-Windows-Bits-Client/Operational
  event-id: 59
  provider: Microsoft-Windows-Bits-Client
fields:
- name: Url
  kind: url
  location: EventData → Url
  references-data:
  - {concept: URL, role: downloadedFromUrl}
- name: jobId
  kind: identifier
  location: EventData → jobId
- name: jobTitle
  kind: label
  location: EventData → jobTitle
- name: User
  kind: identifier
  location: EventData → User (SID)
  references-data:
  - {concept: UserSID, role: actingUser}
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: BITS_TRANSFER_STARTED
  ceiling: C3
  note: "BITS job initiated a download. Classic LOLBIN technique: bitsadmin / Start-BitsTransfer bypasses simple proxy policies and persists across reboots."
  qualifier-map:
    actor.user.sid: field:User
    object.url: field:Url
    object.job.id: field:jobId
    time.start: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance:
  - ms-background-intelligent-transfer-ser
  - mitre-t1197
---

# BITS-59

## Forensic value
Background Intelligent Transfer Service job creation. Every `bitsadmin /transfer` or `Start-BitsTransfer` invocation emits one 59. Attackers favor BITS for download because it survives reboots, retries automatically, and uses Windows Update-legitimate network patterns.

## Cross-references
- **BITS-60** — job transferred (completion counterpart to 59)
- **Sysmon-1** — parent process creation (the process that called bitsadmin)
- **Sysmon-3** — actual network connection(s) BITS makes
