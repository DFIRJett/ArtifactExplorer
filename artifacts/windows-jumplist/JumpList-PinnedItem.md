---
name: JumpList-PinnedItem
aliases: [pinned jump-list entry, pinned jumplist target]
link: user
tags: [per-user, user-intent]
volatility: persistent
interaction-required: user-action
substrate: windows-jumplist
substrate-instance: AutomaticDestinations-pinned
substrate-hub: User scope
platform:
  windows: {min: '7', max: '11'}
location:
  path: "AutomaticDestinations-ms OR CustomDestinations-ms → entries with PinStatus ≠ 0"
  addressing: OLE2-CFB-stream (DestList entries)
fields:
- name: pinned-target
  kind: path
  location: embedded LNK within the pinned entry
  references-data:
  - {concept: ExecutablePath, role: shellReference}
- name: pin-timestamp
  kind: timestamp
  location: DestList LastAccessTime for the pinned entry
  encoding: filetime-le
  note: "LastAccessTime on a pinned entry freezes at last OPEN, not at pin time — pin date itself is not directly recorded"
observations:
- proposition: USER_PINNED_DELIBERATELY
  ceiling: C4
  note: "Pinning is a deliberate user action — right-click → 'Pin to this list'. Unlike auto-MRU entries (passive), pinned entries represent deliberate long-term retention. Survives Explorer 'Clear Recent' because it's inside jump-list files, not in Recent\\*.lnk."
  qualifier-map:
    actor.user: profile owner
    object.target: field:pinned-target
anti-forensic:
  write-privilege: user
  known-cleaners:
  - {tool: right-click → Unpin, typically-removes: pin flag but entry may remain as MRU}
provenance:
  - libyal-libolecf
---

# JumpList-PinnedItem

## Forensic value
Jump-list entries with PinStatus ≠ 0 are DELIBERATELY pinned by the user (right-click → "Pin to this list"). Distinct forensic signal from auto-tracked MRU entries — pinned = user wanted long-term access to this specific target.

For incident response: pinned items reveal the user's recurring work targets — file shares, documents, internal web pages — stronger attribution signal than single-access MRU entries.

## Cross-references
- **JumpList-DestList-Entry** — source of the PinStatus flag
- **TaskbarLayout** — pinned-app companion (apps not items)
