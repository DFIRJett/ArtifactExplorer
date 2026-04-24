---
name: CustomDestinations
aliases:
- custom-jumplist
- customDestinations-ms
- pinned-items-jumplist
link: file
tags:
- timestamp-carrying
- tamper-easy
- per-user
volatility: persistent
interaction-required: user-action
substrate: windows-jumplist
substrate-instance: CustomDestinations
substrate-hub: User scope
platform:
  windows:
    min: '7'
    max: '11'
  windows-server:
    min: 2008R2
    max: '2022'
location:
  path: '%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\<AppID>.customDestinations-ms'
  addressing: filesystem-path
  filename-format: <16-hex AppID>.customDestinations-ms
fields:
- name: app-id
  kind: identifier
  location: filename prefix (before .customDestinations-ms)
  encoding: 16 uppercase hex chars
  references-data:
  - concept: AppID
    role: jumplistApp
- name: header-version
  kind: enum
  location: file bytes 0-3
  encoding: uint32-le
  note: 2 on most observed files
- name: header-total-entries
  kind: counter
  location: file bytes 4-7
  encoding: uint32-le
- name: category-count
  kind: counter
  location: header area (post-entries count)
  encoding: uint32-le
  note: number of named pin-categories (e.g., 'Tasks', 'Recent', 'Pinned')
- name: category-name
  kind: identifier
  location: per-category block header
  encoding: utf-16le
  note: category labels seen in the taskbar jump-list UI
- name: entry-separator-magic
  kind: identifier
  location: between LNK blobs
  encoding: fixed byte sequence (AB FB BF BA ...) separating items
  note: the magic separator is how parsers know where one LNK blob ends and the next begins
- name: embedded-lnk-blob
  kind: path
  location: raw LNK-format blob between magic separators
  encoding: shell-link-binary
  note: full Shell Link per entry — MAC times, target path, tracker-block, volume info all present
  references-data:
  - concept: VolumeGUID
    role: accessedVolume
  - concept: VolumeLabel
    role: accessedAtLabel
  - concept: FilesystemVolumeSerial
    role: accessedAtSerial
  - concept: MachineNetBIOS
    role: trackerMachineId
  - concept: MFTEntryReference
    role: referencedFile
- name: footer-magic
  kind: identifier
  location: file tail
  encoding: AB FB BF BA + reserved bytes
  note: distinguishes 'clean end of file' from 'truncated/corrupted' — carvers use this
observations:
- proposition: ACCESSED
  ceiling: C3
  note: 'Application-declared pinned and recent entries. Populated via the Taskbar

    API by the application itself rather than auto-tracked by Windows —

    indicates deliberate user action (pinning) or application-specific MRU.

    Most Microsoft apps (Explorer, Notepad, Office, Edge) populate these.

    '
  qualifier-map:
    object.path: embedded LNK local-base-path
    actor.user: derived from %APPDATA% owner
    actor.application: field:app-id
    object.mft-reference: embedded LNK shell-item extension block
    object.volume-guid: embedded LNK shell-item volume entry
    time.start: embedded LNK target-access-time
  preconditions:
  - File not held open by the originating app
  - AppID resolves to a known application
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: Explorer "Clear recent items" UI
    typically-removes: false
  - tool: per-entry right-click "Remove from list"
    typically-removes: partial
  - tool: manual file delete
    typically-removes: full
  survival-signals:
  - Same survival pattern as AutomaticDestinations — Recent\*.lnk cleaners miss this directory
  - AppID matches a CustomDestinations file without a corresponding AutomaticDestinations = app uses only custom jump-list
    API (less common; Microsoft Store apps sometimes)
provenance: []
---

# Custom Destinations Jump List

## Forensic value
Application-populated jump list entries — distinct from AutomaticDestinations in two ways:
1. **Format is raw sequential LNK blobs** (not OLE2 CFB) separated by fixed magic bytes. Simpler to carve, no OLE stream navigation.
2. **Application decides what goes in** (via Taskbar API). CustomDestinations typically contains *pinned* items and category-organized "Tasks" or "Recent Files" groups that the app exposes through its own UI. Less often populated than AutomaticDestinations, but richer when present.

## Same six concept references as AutomaticDestinations
AppID, FilesystemVolumeSerial, MachineNetBIOS, MFTEntryReference, VolumeGUID, VolumeLabel — all via embedded LNK blobs.

## Key differences from AutomaticDestinations

| Aspect | AutomaticDestinations | CustomDestinations |
|---|---|---|
| Format | OLE2 Compound File Binary | raw LNK-blob concatenation |
| Populated by | Windows auto-tracking | application Taskbar API |
| Contains | recent items (DestList) + LNK streams | pinned items + tasks, as LNK blobs |
| Per-entry metadata | rich (DestList record with pin, times, machine-id) | just the LNK blob |
| Parser approach | OLE stream enumeration + DestList parse | magic-delimited blob split |

## Known quirks
- **Not all apps populate CustomDestinations.** Presence alone is a signal — the app wrote it deliberately.
- **Orphaned blobs** can exist after pinned-item removal; magic separator is the delimiter, blobs between separators survive until the file is rewritten.
- **Category metadata** (e.g., "Frequent," "Tasks," "Pinned") lives in the file header structure. Some parsers expose these; many don't.
- **File can have multiple LNK blobs for the same target** if the target is pinned in multiple categories.

## Practice hint
- Pin a file via Notepad's right-click-on-taskbar menu. Observe the resulting `<AppID>.customDestinations-ms`.
- Parse with JLECmd. Confirm the pinned item appears with full LNK structure.
- Unpin it via UI. Re-parse. Note whether the blob persists (likely — leftover data between separators).
- Compare a populated AutomaticDestinations vs. CustomDestinations for the same application — different content, different perspective.
