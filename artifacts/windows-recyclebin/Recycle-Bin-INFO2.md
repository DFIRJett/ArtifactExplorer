---
name: Recycle-Bin-INFO2
title-description: "Legacy Recycle Bin INFO2 index (Windows 95 / 98 / Me / XP) — deleted-file metadata predating $I/$R format"
aliases:
- INFO2
- legacy Recycle Bin
- RECYCLED / Recycler INFO2
link: file
tags:
- legacy-system
- deleted-file-recovery
volatility: persistent
interaction-required: user-action
substrate: windows-recyclebin
substrate-instance: Legacy-INFO2
substrate-hub: System scope
platform:
  windows:
    min: '95'
    max: XP
    note: "Replaced by the $I / $R format starting Vista. Legacy INFO2 files still surface on forensic work against old disk images, upgraded-from-XP systems that preserved old Recycler directories, and cold-case evidence."
  windows-server:
    min: '2000'
    max: '2003'
location:
  path-win95-98-me: "%SystemDrive%\\RECYCLED\\INFO2 (per-drive; shared across all users)"
  path-win2000-xp: "%SystemDrive%\\Recycler\\<USER-SID>\\INFO2 (per-user, keyed by SID)"
  addressing: file-path
  note: "Binary index file holding one record per deleted file currently in the Recycle Bin. Each record has fixed size (280 bytes Win9x, 800 bytes NT+). Fields: original full file path, record index (matching the DCn filename in the same directory), deletion timestamp, original file size, and a drive-number byte. Deleted records (emptied Recycle Bin entries) are sometimes recoverable from slack within INFO2 before the file is reused."
fields:
- name: original-path
  kind: path
  location: "per-record at offset 20 (Win9x) / 24 (NT+)"
  encoding: ASCII (Win9x) or UTF-16LE (NT+); null-terminated
  references-data:
  - concept: UserSID
    role: profileOwner
  note: "Full original path of the deleted file (C:\\Users\\...\\document.doc). Recovers the pre-delete filename AND the pre-delete directory. For cold-case investigations this is the direct evidence of what the user had in a location before deletion."
- name: record-index
  kind: identifier
  location: "per-record at offset 4 — numeric record index"
  encoding: uint32 le
  note: "Integer N that maps to the companion 'DCn' file in the same directory holding the actual deleted bytes. INFO2 record N ↔ DCn file — identical to the $I/$R relationship in modern format. Pair the INFO2 metadata to the DCn content for full recovery."
- name: deletion-time
  kind: timestamp
  location: "per-record timestamp field"
  encoding: filetime-le (NT+) / FAT-time (Win9x)
  clock: system
  resolution: 100ns (NT+) / 2s (Win9x)
  note: "When the file was sent to the Recycle Bin (not original creation). The single-most-important pivot for incident timeline on legacy systems."
- name: original-size
  kind: counter
  location: "per-record file-size field"
  encoding: uint64 le (NT+); uint32 (Win9x)
  note: "File size at deletion time. Joins to the DCn file size as consistency check."
- name: drive-byte
  kind: flags
  location: "per-record drive-number byte"
  encoding: uint8
  note: "Drive letter index (0=A, 1=B, 2=C...). Preserved even if the partition later changed drive-letter assignment — historical state."
observations:
- proposition: HAD_FILE
  ceiling: C3
  note: 'Legacy INFO2 is the XP-era predecessor of the modern $I/$R
    recycle-bin metadata. Continues to surface on very old disk
    images, systems upgraded-from-XP, and cold-case investigations.
    For any pre-Vista evidence, INFO2 is the primary deleted-file
    metadata source.'
  qualifier-map:
    object.path: field:original-path
    time.end: field:deletion-time
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: empty Recycle Bin
    typically-removes: DCn files; INFO2 records may survive in slack
  survival-signals:
  - INFO2 present on XP-era images or upgraded systems = recoverable deleted-file history
  - Recycler\<SID>\ directory containing DCn files without matching INFO2 records = partial-cleanup pattern
provenance:
  - ms-how-the-recycle-bin-stores-files-in
  - carvey-2010-rifiuti-rifiuti2-info2-parser
  - jones-2003-rifiuti-foundstone
---

# Legacy Recycle Bin (INFO2)

## Forensic value
Before the Vista-introduced `$I/$R` format, Windows' Recycle Bin used a single binary index file called `INFO2` with paired `DCn` (deleted-content) files. Each `INFO2` record holds the pre-deletion path, size, and timestamp for one deleted file.

- **Windows 95/98/Me**: `%SystemDrive%\RECYCLED\INFO2` — machine-wide, no per-user scope
- **Windows 2000/XP**: `%SystemDrive%\Recycler\<USER-SID>\INFO2` — per-user (keyed by SID)

Modern forensic work rarely touches this artifact — except on:
- XP-era disk images
- Upgraded-from-XP hosts that preserved legacy Recycler directories
- Cold-case investigations on preserved evidence volumes

## Concept reference
- None direct (path + timestamp artifact).

## Parsing
`rifiuti2` is the canonical tool:
```bash
rifiuti-vista INFO2  # handles INFO2 across all NT versions
```

## Cross-reference
- Companion `DCn` files in same directory = actual deleted bytes
- `$MFT` for deletion-time of the `INFO2` entry itself (different from the record's deletion-time)

## Practice hint
Obtain an XP-era image (archive.org has preserved Windows XP VMs). Navigate to `C:\RECYCLER\<SID>\INFO2`, run `rifiuti2` — deleted-file history for that user is recoverable including paths and sizes.
