---
name: TaskbarLayout
aliases:
- Taskbar pinned items
- Taskband
- Start-menu pinned
link: application
tags:
- per-user
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: '7'
    max: '11'
location:
  hive: NTUSER.DAT
  path: Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband
  also: Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\Favorites
  addressing: hive+key-path
fields:
- name: favorites-list
  kind: identifier
  location: Favorites value
  type: REG_BINARY
  encoding: shell-item list (similar to LNK LinkTargetIDList)
  note: pinned apps as shell-items; parsers must decode shell-item chains to extract AppIDs
  references-data:
  - concept: AppID
    role: pinnedApp
- name: favorites-resolve
  kind: identifier
  location: FavoritesResolve value
  type: REG_BINARY
  note: resolution cache; parsers often skip, but contains target paths
- name: favorites-changes-count
  kind: counter
  location: FavoritesChangesCount value
  type: REG_DWORD
- name: key-last-write
  kind: timestamp
  location: Taskband key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: EXISTS
  ceiling: C2
  note: records which apps the user pinned to the taskbar — per-user app preference indicator
  qualifier-map:
    entity.app-id: field:favorites-list
    actor.user: NTUSER.DAT owner
    time.start: field:key-last-write
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
provenance: []
---

# Taskbar Layout

## Forensic value
Per-user record of taskbar-pinned apps, encoded as a shell-item list in the Taskband\Favorites binary value. Of limited standalone forensic value but **corroborates other AppID evidence** — the AppIDs found here match those used for jump list filenames and taskbar-launch audit events.

## Concept reference
- AppID (extracted from shell-item decoding)

## Known quirks
- **Binary shell-item encoding.** Requires the same shell-item parser used for ShellBags and LNK LinkTargetIDList. Don't expect a simple text list.
- **Changes infrequently.** Users rarely change taskbar pins; this artifact's forensic value is "proves the user historically used this app" more than "proves recent activity."
