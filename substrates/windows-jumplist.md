---
name: windows-jumplist
kind: binary-structured-file
substrate-class: Filesystem/Artifact
aliases: [Jump List, per-app recent/pinned item tracking]

format:
  variants:
    - name: AutomaticDestinations
      format: "OLE2 Compound File Binary (CFB)"
      extension: .automaticDestinations-ms
      contents: "DestList stream + N embedded LNK streams"
    - name: CustomDestinations
      format: "raw sequential concatenation of LNK blobs with fixed magic markers"
      extension: .customDestinations-ms
      contents: "category groupings + pinned items as full LNK-format blobs"
  authoritative-spec:
    - title: "Jump lists format"
      author: Jonathan Tomczak / Harlan Carvey / Mari DeGrazia (DFIR community)
      note: no single Microsoft public spec; reverse-engineered

persistence:
  live-system-locations:
    auto: "%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\<AppID>.automaticDestinations-ms"
    custom: "%APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations\\<AppID>.customDestinations-ms"
  filename-prefix: AppID (16-char uppercase hex CRC64 of AppUserModelID)
  retention: until Explorer UI "Clear recent" OR per-app "remove from list" OR manual delete
  locked-on-live-system: partial — active app's jump list is held by Explorer

parsers:
  - name: JLECmd (Eric Zimmerman)
    strengths: [bulk CSV export, both variants, AppID resolution, pin-status decoding]
  - name: Jump List Explorer (Zimmerman GUI)
    strengths: [tree-view per entry, embedded-LNK drill-down]
  - name: lib-jumplist (various community implementations)
    strengths: [programmatic access]
  - name: Oleid / 7-zip
    strengths: [extracting DestList + LNK streams from AutomaticDestinations CFB]
    weaknesses: [no CustomDestinations support — that's not CFB]

forensic-relevance:
  - cross-host-attribution: |
      Embedded LNK streams carry TrackerDataBlock with MachineID — same
      cross-host provenance as ShellLNK. Jump lists frequently preserve
      entries from machines a user no longer uses.
  - pin-status: |
      DestList entries carry a pin flag. Pinned items are user-deliberate,
      not auto-tracked — a different forensic signal than recent-access.
  - app-level-scope: |
      Unlike Recent\, jump lists segregate by AppID — user's recent Chrome
      downloads, recent Notepad files, recent Explorer folders are all in
      separate files. Lets the examiner reconstruct per-application activity.

integrity:
  signing: none
  tamper-vectors:
    - direct file deletion (cleaners that hit Recent\ often miss these subdirs)
    - per-entry unpin/remove via jump-list right-click UI
    - in-place hex edit (no integrity check to defeat)
  survival:
    - "AutomaticDestinations survives `Clear Recent items` UI action which only empties %APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk"
    - "CustomDestinations similarly independent"

anti-forensic-concerns:
  - '"Clear Recent" Explorer UI is the most common user action — does NOT clean jump lists. Mismatch between cleared Recent\ and populated jump lists is diagnostic of naive cleanup.'
  - AppID correlation can re-identify apps even when executable names are renamed — AppID derives from AppUserModelID, not filename.

known-artifacts:
  # Jump list artifacts are per-variant (Automatic vs Custom) with embedded
  # LNK streams inside each. Pinned items and DestList entries are distinct
  # forensic signals within the same file.
  authored:
    - AutomaticDestinations    # OLE2 CFB-wrapped DestList + embedded LNK streams
    - CustomDestinations       # raw concatenated LNK blobs, app-controlled
  unwritten:
    - name: JumpList-DestList-Entry
      location: AutomaticDestinations → DestList stream
      value: per-entry metadata (last-access time, pin flag, access count, entry-number) distinct from the embedded LNK's own timestamps
    - name: JumpList-PinnedItem
      location: AutomaticDestinations/CustomDestinations → entries with pin flag set
      value: user-deliberate pin action (different forensic signal than auto-tracked MRU)
    - name: JumpList-AppID-Mapping
      location: "registry: HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache + hardcoded Microsoft list"
      value: AppID → human-readable application name resolution (otherwise jump lists are anonymous 16-char hex)
    - name: JumpList-Embedded-LNK
      location: each DestList entry contains a full LNK blob (cross-reference to windows-lnk)
      value: full ShellLNK field set per entry — TrackerDataBlock MachineID, VolumeID, target-path, network info
provenance:
  - libyal-libfwsi
  - libyal-liblnk
  - libyal-libolecf
  - ms-cfb
  - ms-shllink
---

# Windows Jump List

## Forensic value
Per-application recent-and-pinned item tracking. Each taskbar-pinned or MRU-listed application gets its own jump list file, named by AppID. Each file preserves the application's most-recently-used items with embedded LNK-format structures that carry full volume/machine/target information.

Two variants, different internal formats:
- **AutomaticDestinations** (`.automaticDestinations-ms`) — auto-populated by the system for apps that participate. OLE2 Compound File Binary wrapping a DestList index + per-entry LNK streams.
- **CustomDestinations** (`.customDestinations-ms`) — populated by the application itself via the Taskbar API. Raw sequential LNK blobs.

Both are per-user (under `%APPDATA%\Microsoft\Windows\Recent\`). Both usually survive Explorer's "Clear Recent" action — that cleanup hits only the top-level `Recent\*.lnk` files.

## Forensic cross-references
Jump list entries share most of the LNK concept references (VolumeGUID, VolumeLabel, FilesystemVolumeSerial, MachineNetBIOS, MFTEntryReference) plus AppID as the application-identity pivot.

## Collection notes
On a live system, the currently-active application's jump list may be held open by Explorer. Copy from VSS or acquire offline for complete integrity. Both variants are small (kilobytes typically), so acquisition cost is negligible — acquire every `.automaticDestinations-ms` and `.customDestinations-ms` under Recent\ for every user profile.
