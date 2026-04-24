---
name: RecentDocs
aliases:
- Recent Docs
- per-extension MRU
- Explorer-recent
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
    min: XP
    max: '11'
location:
  hive: NTUSER.DAT
  path: Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
  sub-paths: RecentDocs\.<ext> — per-extension subkeys
  addressing: hive+key-path
fields:
- name: recent-file-list
  kind: path
  location: numbered values (0, 1, 2, ...) containing shell-item data
  type: REG_BINARY
  encoding: shell-item-binary
  note: each value is a shell-item with full path + filename of a recent file of the given extension
- name: mru-list-ex
  kind: counter
  location: MRUListEx value
  type: REG_BINARY
  encoding: array of uint32-le
  note: most-recent-first order of the numbered values
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: updated when a new file of this extension is opened
observations:
- proposition: ACCESSED
  ceiling: C2
  note: 'Per-extension MRU — every file the user opened from Explorer (or via

    any app registered for the extension) gets a RecentDocs entry.

    Per-user-profile scoped.

    '
  qualifier-map:
    object.path: parsed shell-item path
    actor.user: NTUSER.DAT owner
    time.start: field:key-last-write
anti-forensic:
  write-privilege: user
  known-cleaners:
  - tool: Explorer 'Clear recent items'
    typically-removes: full
  - tool: CCleaner
    typically-removes: full
provenance:
  - libyal-libfwsi
---

# RecentDocs

## Forensic value
Per-user, per-extension recently-opened file list. Organized as `RecentDocs\.docx` for Word files, `RecentDocs\.jpg` for images, etc. Each subkey holds up to 10-20 shell-item values.

Complementary to ShellLNK — RecentDocs captures the file reference; LNK captures the full metadata with tracker-block. Cross-reference both for a complete recent-file picture.

## Known quirks
- **Shell-item encoding.** Values are binary shell-item lists, same format as ShellBags. Parse via shell-item parser.
- **Per-extension scope.** Check every extension of interest (`.pdf`, `.xlsx`, `.exe`, `.ps1`, etc.) — parsers usually enumerate all.
- **MRUListEx ordering** tracks most-recent-first order.
- **"RecentDocs" also has a root-level list** (not under any extension subkey) for the general recent list.
