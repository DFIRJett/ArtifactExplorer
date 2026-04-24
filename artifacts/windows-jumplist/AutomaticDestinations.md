---
name: AutomaticDestinations
aliases:
- automatic-jumplist
- auto-jumplist
- automaticDestinations-ms
link: file
tags:
- timestamp-carrying
- tamper-easy
- per-user
volatility: persistent
interaction-required: user-action
substrate: windows-jumplist
substrate-instance: AutomaticDestinations
substrate-hub: User scope
platform:
  windows:
    min: '7'
    max: '11'
  windows-server:
    min: 2008R2
    max: '2022'
location:
  path: '%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms'
  addressing: filesystem-path
  filename-format: <16-hex AppID>.automaticDestinations-ms
fields:
- name: app-id
  kind: identifier
  location: filename prefix (before .automaticDestinations-ms)
  encoding: 16 uppercase hex chars
  references-data:
  - concept: AppID
    role: jumplistApp
- name: destlist-version
  kind: enum
  location: DestList stream bytes 0-3
  encoding: uint32-le
  note: 1 = Win7, 3 = Win8.1/10, 4 = Win10+
- name: destlist-entry-count
  kind: counter
  location: DestList stream bytes 4-7
  encoding: uint32-le
- name: destlist-pinned-count
  kind: counter
  location: DestList stream bytes 8-11
  encoding: uint32-le
- name: entry-volume-birth-droid
  kind: identifier
  location: DestList per-entry — VolumeBirthDroid field
  encoding: guid-le
  note: DLT volume identifier at the target's creation — partially decodable as FilesystemVolumeSerial
  references-data:
  - concept: FilesystemVolumeSerial
    role: accessedAtSerial
- name: entry-file-birth-droid
  kind: identifier
  location: DestList per-entry — FileBirthDroid field
  encoding: guid-le
  note: DLT file identifier at creation; pair with machine-id for cross-host attribution
- name: entry-machine-id
  kind: identifier
  location: DestList per-entry — NetBIOS machine name field
  encoding: ascii (16 chars, NUL-padded)
  references-data:
  - concept: MachineNetBIOS
    role: trackerMachineId
- name: entry-mft-entry-ref
  kind: identifier
  location: DestList per-entry — MFT segment reference (6-byte entry + 2-byte sequence)
  encoding: entry:sequence
  references-data:
  - concept: MFTEntryReference
    role: referencedFile
- name: entry-modified-time
  kind: timestamp
  location: DestList per-entry — modification timestamp
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: target file's modification time at the moment of jump-list write
- name: entry-access-time
  kind: timestamp
  location: DestList per-entry — last-access timestamp captured
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: entry-last-access-time
  kind: timestamp
  location: DestList per-entry — last time the user selected this entry in Explorer
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: the 'last opened via jump list' signal — distinct from the target's own MAC times
- name: entry-pin-status
  kind: flags
  location: DestList per-entry — PinStatus field
  encoding: uint32-le
  note: 0 = auto-tracked, -1 (0xFFFFFFFF) = pinned by user
- name: entry-path
  kind: path
  location: DestList per-entry — filename/path field
  encoding: utf-16le
- name: entry-stream-id
  kind: identifier
  location: DestList per-entry — Entry ID linking to an embedded LNK stream
  encoding: hex string matching an OLE substream name
- name: embedded-lnk-stream
  kind: path
  location: OLE substream named by entry-stream-id
  encoding: shell-link-binary
  note: full Shell Link structure per entry — shell-item list with volume-GUID / volume-label / MFT refs
  references-data:
  - concept: VolumeGUID
    role: accessedVolume
  - concept: VolumeLabel
    role: accessedAtLabel
  - concept: MFTEntryReference
    role: referencedFile
  - concept: PIDL
    role: linkedItem
observations:
- proposition: ACCESSED
  ceiling: C3
  note: 'Per-app, per-user file-open history with richer metadata than Recent\

    LNK files. entry-last-access-time captures when the user most recently

    selected the entry via the jump-list UI, which survives clearing Recent\.

    '
  qualifier-map:
    object.path: field:entry-path
    object.mft-reference: field:entry-mft-entry-ref
    object.volume-serial: field:entry-volume-birth-droid
    actor.user: derived from %APPDATA% owner (NTUSER profile)
    actor.application: field:app-id
    time.start: field:entry-last-access-time
    time.end: field:entry-modified-time
  preconditions:
  - File not held open by Explorer — copy from VSS for live acquisition
  - AppID resolves to known app (JLECmd AppID table) OR resolved from live Get-StartApps
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: Explorer "Clear recent items" UI
    typically-removes: false
    note: clears %APPDATA%\Microsoft\Windows\Recent\*.lnk only
  - tool: per-entry jump-list right-click > "Remove from list"
    typically-removes: partial
    note: removes ONE DestList entry; other entries survive
  - tool: manual file delete
    typically-removes: full
    note: removes ALL app history for that AppID
  - tool: CCleaner
    typically-removes: partial
  survival-signals:
  - Recent\ cleared + AutomaticDestinations populated = naive cleanup. Common and diagnostic.
  - Entry's machine-id ≠ current host's NetBIOS = entry created on another machine, profile-roamed or copied
provenance:
  - libyal-libolecf
  - ms-cfb
  - jones-2020-dfirpub-win10-jumplist-link-file
  - libyal-liblnk
  - ms-shllink
---

# Automatic Destinations Jump List

## Forensic value
Per-app recent-item history, stored as OLE2 Compound File Binary. More forensically rich than ordinary LNK files in several ways:
- **Persists across Explorer "Clear Recent"** — the common cleanup action misses this directory entirely.
- **Carries a distinct "last-selected via jump list" timestamp** (entry-last-access-time) in addition to the target's own MAC times. This is the user's jump-list interaction event.
- **Segregated by application** (via AppID filename) — tells you which app a file was opened with, not just that it was opened.
- **Carries TrackerDataBlock machine IDs on every embedded LNK** — each entry preserves source-host provenance.

## Six concept references (richest artifact yet)
- AppID (filename prefix — application identity)
- FilesystemVolumeSerial (from volume-birth-droid)
- MachineNetBIOS (from entry machine-id + embedded LNK TrackerBlocks)
- MFTEntryReference (from entry MFT refs + embedded shell items)
- VolumeGUID (from embedded LNK shell items)
- VolumeLabel (from embedded LNK LinkInfo)

## Known quirks
- **DestList version differs by OS version.** Pre-Win8.1 has v1; Win10+ has v3 or v4. Parsers that assume one version mis-decode.
- **Pin flag is unsigned -1, not a boolean.** 0xFFFFFFFF = pinned. Some parsers interpret as signed and show -1; others show MAX_UINT32. Either way, any non-zero value in PinStatus = pinned.
- **Embedded LNK streams are full LNK files.** Parse each one as a Shell Link — all ShellLNK properties apply.
- **Orphan streams can exist.** Pinning/removing can leave LNK streams in the OLE container without matching DestList entries. Parsers that only follow DestList miss them; carvers recover them.
- **Streams named by hex EntryID** — not by filename. Don't expect meaningful stream names.

## Anti-forensic caveats
Trivially deletable as a whole file, harder to surgically redact. Per-entry removal via the UI is uneven — it updates the DestList but doesn't always remove the corresponding LNK stream (orphan signal). The combination "Recent\ cleared + AutomaticDestinations full" is a reliable indicator of naive cleanup.

## Practice hint
- On a clean Win10 VM, open several files with different applications (Notepad, Chrome, Explorer). Inspect `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\`. Identify one file per AppID.
- Run JLECmd in CSV mode. Cross-reference AppIDs to known apps.
- Right-click an entry in the jump list and "Remove from list." Re-parse. Confirm DestList updated but embedded LNK stream possibly retained.
- Clear Recent via Explorer UI. Verify `AutomaticDestinations\*` is untouched.
