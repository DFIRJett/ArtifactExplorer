---
name: MUICache
aliases:
- Multilingual User Interface Cache
- shell muicache
- exe-display-name cache
link: application
tags:
- per-user
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: UsrClass.dat
platform:
  windows:
    min: Vista
    max: '11'
location:
  hive: UsrClass.dat
  path: Local Settings\Software\Microsoft\Windows\Shell\MuiCache
  also-legacy: NTUSER.DAT\Software\Microsoft\Windows\ShellNoRoam\MUICache (pre-Win7)
  addressing: hive+key-path
fields:
- name: executable-path
  kind: path
  location: value name — full path
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: shellReference
  note: value name IS the path to an executable the shell has seen
- name: app-id
  kind: identifier
  location: value name suffix or separate value
  encoding: 16-hex uppercase
  references-data:
  - concept: AppID
    role: muiCachedApp
  note: some MUICache entries carry AppID-suffixed value names for per-AppID display config
- name: friendly-app-name
  kind: identifier
  location: value data
  type: REG_SZ
  encoding: utf-16le
  note: display name the shell caches for this executable
observations:
- proposition: EXISTS
  ceiling: C2
  note: 'MUICache records every executable the shell has been asked to display

    a name for — typically as a result of Explorer listing or launching

    the file. Presence indicates the shell encountered the executable;

    not authoritative as "executed" but useful corroborator.

    '
  qualifier-map:
    entity.path: field:executable-path
    actor.user: UsrClass.dat owner
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
provenance: []
---

# MUICache (Shell Display-Name Cache)

## Forensic value
Per-user cache of executable display names the shell has resolved. Every time Explorer displays an .exe in a folder view or processes a shell-launch, MUICache gets an entry. Not a strong execution signal on its own (Explorer can display a file without the user executing it) but useful corroborator.

Value is in the **path visibility** — MUICache preserves paths of executables that may no longer exist on disk, providing historical path evidence when other artifacts were cleared.

## Concept references
- ExecutablePath (value name)
- AppID (when present as suffix or separate value)

## Known quirks
- **Path is the value name.** Not the data — parsers that only read value DATA miss everything.
- **Legacy and modern locations differ.** Pre-Win7 used NTUSER.DAT\Software\Microsoft\Windows\ShellNoRoam\MUICache. Win7+ moved to UsrClass.dat. Parse both for cross-version coverage.
- **Not cleared by "clear Recent"** or similar user cleanup.
