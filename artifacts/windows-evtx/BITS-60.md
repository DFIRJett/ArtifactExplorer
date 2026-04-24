---
name: BITS-60
title-description: "BITS Client stopped transferring"
aliases: [BITS job transferred]
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
  event-id: 60
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
- name: bytesTransferred
  kind: size
  location: EventData → bytesTransferred
- name: fileCount
  kind: counter
  location: EventData → fileCount
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: BITS_TRANSFER_COMPLETED
  ceiling: C3
  note: "BITS job finished transferring bytes. Pair with BITS-59 (job created) via jobId — shows the full create-to-complete download cycle with URL + byte count."
  qualifier-map:
    object.url: field:Url
    object.bytes.transferred: field:bytesTransferred
    time.end: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance:
  - ms-background-intelligent-transfer-ser
  - mitre-t1197
---

# BITS-60

## Forensic value
Completion event for BITS transfers. Combined with BITS-59 via jobId gives the full lifecycle: when the transfer started, what URL it pulled from, how many bytes moved, when it completed.

## Cross-references
- **BITS-59** — the matching job-start event
- **firewall-log** / **Sysmon-3** — actual network flows the transfer generated
- **Zone-Identifier-ADS** — mark-of-the-web stamped on the downloaded file (if BITS opts in)
