---
name: Security-5038
title-description: "Code integrity determined that the image hash of a file is not valid"
aliases: [5038, code integrity failure, hash mismatch]
link: system
link-secondary: persistence
tags: [code-integrity, tamper-signal, rootkit-detection]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: {min: '7', max: '11'}
  windows-server: {min: '2008R2', max: '2022'}
location:
  channel: Security
  event-id: 5038
  provider: Microsoft-Windows-Security-Auditing
  addressing: evtx-record
  note: "Fires when Windows Code Integrity detects an image whose on-disk hash does not match its expected value (cached catalog / Authenticode signature). Paired with 6281 (invalid page hash — runtime-loaded module mismatch). Subcategory: 'Audit System Integrity'. Rootkit/patched-binary signal."
fields:
- name: image-path
  kind: path
  location: "EventData → (image path in event message)"
  encoding: utf-16le
  references-data: [{concept: ExecutablePath, role: ranProcess}]
  note: "Path of the image whose hash didn't match. Attacker tamper with signed system binaries (e.g., overwriting a System32 DLL with a patched version) surfaces here. Cross-reference against Amcache SHA-1 to see WHICH hash was observed."
- name: event-time
  kind: timestamp
  location: "System/TimeCreated"
  encoding: xs:dateTime UTC
  clock: system
  resolution: 1ms
observations:
- proposition: INTEGRITY_FAILURE
  ceiling: C4
  note: '5038 is a high-signal event — Code Integrity rarely produces false positives at the file-hash level. Pair with CodeIntegrity-3077 (driver-level failure) for full kernel+user integrity coverage.'
  qualifier-map:
    object.path: field:image-path
    time.start: field:event-time
provenance: [ms-event-5038]
---

# Security-5038 — Code Integrity Hash Mismatch
Image-file-level CI failure. Overwritten system binary / rootkit-patched DLL / corrupted binary all surface here. Pair with CodeIntegrity-3077 and Sysmon-6 for driver tier.
