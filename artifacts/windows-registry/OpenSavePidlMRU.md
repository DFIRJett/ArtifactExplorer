---
name: OpenSavePidlMRU
aliases:
- Common Open/Save dialog MRU
- OpenSaveMRU
- dialog history
link: file
tags:
- per-user
- tamper-easy
- recency-ordered
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: Vista
    max: '11'
location:
  hive: NTUSER.DAT
  path: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
  sub-paths: OpenSavePidlMRU\<ext> — per-extension
  addressing: hive+key-path
fields:
- name: recent-files
  kind: path
  location: numbered values holding shell-item data
  type: REG_BINARY
  encoding: shell-item-binary
  references-data:
  - concept: PIDL
    role: dialogItem
  note: serialized ITEMIDLIST captured from a standard Open/Save file dialog; byte-for-byte comparable (on decoded fields) with the same item appearing in ShellBags, LastVisitedPidlMRU, LNK LinkTargetIDList, and jump list entries
- name: mru-list-ex
  kind: counter
  location: MRUListEx value
  type: REG_BINARY
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: ACCESSED
  ceiling: C2
  note: 'Files chosen via the common Open / Save / Browse dialogs across

    ALL applications. Distinct from RecentDocs (Explorer-specific) —

    OpenSavePidlMRU captures what the user selected through the

    standard Windows file-picker regardless of which app opened it.

    '
  qualifier-map:
    object.path: shell-item parsed path
    actor.user: NTUSER.DAT owner
    time.start: field:key-last-write
anti-forensic:
  write-privilege: user
provenance:
  - libyal-libfwsi
---

# Common Open/Save Dialog PidlMRU

## Forensic value
Per-user recent-files list for the standard Windows file-picker dialog. Any application using the common Open/Save dialog (notepad.exe, word, irfanview, ...) populates this. Complementary to RecentDocs (which tracks Explorer-opened files).

## Known quirks
- **Shell-item format** — same as RecentDocs and ShellBags.
- **Per-extension separation** works like RecentDocs.
- **Modern UWP apps use newer dialog (Win8+ style)** that does NOT populate this key — limits coverage for Store apps. Legacy Win32 app coverage is complete.
