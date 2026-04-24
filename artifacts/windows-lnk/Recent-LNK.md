---
name: Recent-LNK
aliases:
- Recent items LNK
- Recent folder shortcut
- "%APPDATA%\\Microsoft\\Windows\\Recent"
link: file
tags:
- per-user
- tamper-easy
volatility: persistent
interaction-required: user-action
substrate: windows-lnk
substrate-instance: Recent-folder
substrate-hub: User scope
platform:
  windows:
    min: '7'
    max: '11'
location:
  path: "%APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk"
  addressing: filesystem-path
fields:
- name: target-path
  kind: path
  location: LNK LinkTargetIDList + LinkInfo LocalBasePath
  note: full path to the file the user opened
- name: target-file-reference
  kind: identifier
  location: LNK TrackerDataBlock → DroidFileIdentifier
  references-data:
  - concept: MFTEntryReference
    role: referencedFile
- name: tracker-machine-id
  kind: identifier
  location: LNK TrackerDataBlock → MachineID
  note: NetBIOS name of the host that created the LNK — survives copy, shows cross-host provenance
  references-data:
  - concept: MachineNetBIOS
    role: trackerMachineId
- name: tracker-volume-id
  kind: identifier
  location: LNK TrackerDataBlock → VolumeID
  references-data:
  - concept: VolumeGUID
    role: accessedVolume
- name: volume-serial
  kind: identifier
  location: LNK LinkInfo → VolumeID.VolumeSerialNumber
  references-data:
  - concept: FilesystemVolumeSerial
    role: accessedAtSerial
- name: volume-label
  kind: label
  location: LNK LinkInfo → VolumeID.VolumeLabel
  references-data:
  - concept: VolumeLabel
    role: accessedAtLabel
- name: lnk-file-mac
  kind: timestamps
  location: $MFT of the Recent-LNK file itself
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: LNK file is created on first target open, rewritten on subsequent opens (MAC reset)
- name: target-file-mac
  kind: timestamps
  location: LNK header FileAttributes + Target's $SI captured in LNK
  encoding: filetime-le
  note: snapshot of target's MAC times at the moment the LNK was created/rewritten
observations:
- proposition: ACCESSED
  ceiling: C3
  note: User opened the target file from Explorer (or via a registered app). Per-user-profile scoped. Survives target deletion.
  qualifier-map:
    actor.user: "%APPDATA% owner"
    object.file.path: field:target-path
    time.last_open: field:lnk-file-mac (Modified)
anti-forensic:
  write-privilege: user
  known-cleaners:
  - tool: Explorer 'Clear Recent Items'
    typically-removes: full (but jump lists often retain same entries — cleanup gap)
  - tool: CCleaner
    typically-removes: full
provenance:
  - matrix-dt026-windows-lnk-files
  - carvey-2019-windowsir-lnk-files
  - frazer-2020-mandiant-missing-lnk-user-search
  - jones-2020-dfirpub-win10-jumplist-link-file
  - zimmerman-lecmd
  - artefacts-help-repo
  - kape-files-repo
---

# Recent-LNK

## Forensic value
The canonical "files the user opened" artifact. Windows auto-creates a LNK file in `%APPDATA%\Microsoft\Windows\Recent\` every time a file is opened from Explorer OR from any application that calls `SHAddToRecentDocs` (which is most file-dialog-using apps).

Because each LNK file is the LNK format, every entry carries:
- Full target path
- Volume GUID + filesystem serial + volume label
- MachineID (NetBIOS) of the creating host
- MFT reference of the target
- Target file's $SI timestamps at time of open

## Survival
The LNK file survives:
- **Target deletion** — LNK remains after the original file is gone
- **Removable media removal** — entries for files on unmounted USB drives persist
- **Network share unmount** — UNC-target LNKs persist

Result: a historical record of file accesses that outlives the files themselves.

## Cross-references
- **RecentDocs** (registry) — per-extension MRU; corroborating per-extension list
- **JumpList-DestList-Entry** — embedded LNK streams inside jump lists often mirror Recent-LNK entries but survive `Clear Recent items`
- **ShellLNK** — the parent format definition; Recent-LNK is one location where ShellLNK instances live

## Anti-forensic gap
Clearing Recent via the Explorer "Clear Recent Items" menu item deletes the `.lnk` files in this folder but does NOT touch jump lists. Forensic investigators should compare `Recent\*.lnk` against the entry lists in `Recent\AutomaticDestinations\*.automaticDestinations-ms` — a mismatch (jump list entries present, Recent empty) is a classic partial-cleanup signal.

## Practice hint
LECmd (Eric Zimmerman) bulk-parses `Recent\` into CSV:
```
LECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent" --csv . --csvf recent.csv
```
Then correlate `TargetCreated`, `TargetModified`, `TargetAccessed` against the `SourceCreated`/`SourceModified` of the LNK file itself.
