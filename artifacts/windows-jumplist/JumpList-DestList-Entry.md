---
name: JumpList-DestList-Entry
aliases: [DestList stream entry, per-entry jump-list metadata]
link: file
tags: [per-user, timestamp-carrying]
volatility: persistent
interaction-required: user-action
substrate: windows-jumplist
substrate-instance: AutomaticDestinations-DestList
substrate-hub: User scope
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\<AppID>.automaticDestinations-ms → DestList stream"
  addressing: OLE2-CFB-stream
fields:
- name: entry-number
  kind: counter
  location: DestList entry → EntryNumber
  note: "monotonically increasing per-AppID; corresponds to the embedded-LNK stream name (hex of entry-number)"
- name: last-access-time
  kind: timestamp
  location: DestList entry → LastAccessTime
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: pin-status
  kind: flag
  location: DestList entry → PinStatus
  note: "-1 (0xFFFFFFFF) if pinned; 0 if not. Pinned = user-deliberate retention"
- name: access-count
  kind: counter
  location: DestList entry → AccessCount
- name: entry-string
  kind: label
  location: DestList entry → EntryStringData
  note: "the user-visible display label for the jump-list entry — filename, URL, or custom string"
observations:
- proposition: USER_OPENED_VIA_APP
  ceiling: C3
  note: "Per-entry metadata for auto-populated jump-list entries. Carries per-entry LastAccessTime (NOT just file-level MAC), PinStatus (pinned vs auto), and AccessCount. Pinned entries are user-deliberate — stronger intent signal than auto-tracked."
  qualifier-map:
    actor.user: profile owner
    object.target: field:entry-string
    object.pin.status: field:pin-status
    time.last_access: field:last-access-time
anti-forensic:
  write-privilege: user
provenance: [libyal-libolecf, ms-cfb]
---

# JumpList-DestList-Entry

## Forensic value
Per-entry metadata within AutomaticDestinations files. The DestList stream is where jump-list magic lives — each entry carries:
- LastAccessTime (per-entry, not file-level)
- PinStatus (pinned vs MRU-tracked)
- AccessCount (how many times opened)
- EntryString (display label)

## Cross-references
- **JumpList-Embedded-LNK** — each DestList entry has a corresponding embedded LNK stream
- **JumpList-PinnedItem** — the pin-flagged subset
- **Recent-LNK** — overlapping file-open record (survives "Clear Recent")
