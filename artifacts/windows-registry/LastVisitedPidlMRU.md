---
name: LastVisitedPidlMRU
aliases:
- per-app last-visited dialog location
- ComDlg32 per-app history
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
  path: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
  addressing: hive+key-path
fields:
- name: app-binary-name
  kind: path
  location: embedded in each value's binary structure
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: shellReference
  note: the executable that opened this dialog
- name: last-folder-path
  kind: path
  location: shell-item within each value
  encoding: shell-item-binary
  references-data:
  - concept: PIDL
    role: dialogItem
  note: the last folder this app's dialog was pointed at — serialized ITEMIDLIST comparable to ShellBags / OpenSavePidlMRU / LNK LinkTargetIDList captures of the same location
- name: mru-list-ex
  kind: counter
  location: MRUListEx value
  type: REG_BINARY
- name: key-last-write
  kind: timestamp
  location: key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: ACCESSED
  ceiling: C2
  note: 'Per-application last-folder-visited-in-dialog cache. Different from

    OpenSavePidlMRU (which is per-extension); this is per-app.

    Captures ''the last place application X opened its dialog to'' —

    useful for reconstructing WHERE the user was browsing when using

    a specific tool.

    '
  qualifier-map:
    object.path: field:last-folder-path
    actor.app: field:app-binary-name
    actor.user: NTUSER.DAT owner
    time.start: field:key-last-write
anti-forensic:
  write-privilege: user
provenance:
  - libyal-libfwsi
---

# LastVisitedPidlMRU

## Forensic value
Per-application "last folder visited in Open/Save dialog" cache. Each value binds an application executable to the last folder its dialog was pointed to. Different from OpenSavePidlMRU (per-extension, across all apps) — this is per-application-binary.

## Concept references
- ExecutablePath (the app name)

## Triple-artifact reconstruction
For a given investigative question like "what was the user looking at when running `cmd.exe`":
1. LastVisitedPidlMRU → which folder cmd.exe's dialog was last at
2. OpenSavePidlMRU → which files were selected in dialogs (by extension)
3. ShellBags → browsing history into folders via Explorer

Together: a full per-user file-navigation picture.
