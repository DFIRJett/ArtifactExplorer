---
name: TypedPaths
aliases:
- Explorer address bar history
- URL bar (local)
link: user
tags:
- per-user
- tamper-easy
- user-intent
- recency-ordered
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: 7
    max: '11'
location:
  hive: NTUSER.DAT
  path: Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
  addressing: hive+key-path
fields:
- name: url-slot
  kind: path
  location: values named 'url1', 'url2', ..., 'url25'
  type: REG_SZ
  note: "each slot holds one user-typed Explorer address-bar entry (local path, UNC, file:// URL, or shell:: path)"
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: on each address-bar navigation (new or reused)
observations:
- proposition: ACCESSED
  ceiling: C3
  note: "User typed these paths into Explorer's address bar. Captures UNC access (\\\\server\\share), file:// URIs, shell:: namespaces — artifact of deliberate navigation."
  qualifier-map:
    actor.user: NTUSER.DAT owner
    object.path: field:url-slot
    time.last: field:key-last-write (most-recent only)
anti-forensic:
  write-privilege: user
  known-cleaners:
  - tool: Explorer 'Clear address bar history'
    typically-removes: full
  - tool: CCleaner
    typically-removes: full
provenance:
  - matrix-dt084-typedpaths
  - winreg-kb-typed-paths
  - cowen-2018-hecfblog-daily-483-typed-paths-amnesia
  - windowsir-2013-file-access-typedpaths
  - artefacts-help-repo
  - regripper-plugins
---

# TypedPaths

## Forensic value
Explorer's address-bar history. Unlike RunMRU (Win+R), TypedPaths captures navigations made within Explorer's file-manager window — the path the user typed to jump directly to a location.

Common entries:
- **UNC paths** (`\\fileserver\share\subdir`) — strongest lateral-movement indicator in user scope
- **Local paths** (`C:\temp`, `C:\Users\X\Downloads`)
- **shell: namespaces** (`shell:startup`, `shell:ProgramFiles`) — power-user knowledge; unusual for casual users
- **file:// URIs** — rare but valid
- **ftp://** / **http://** — Explorer will hand off to default browser but TypedPaths still records

## Per-slot rotation
Values are `url1`, `url2`, …, `url25` — not letters like RunMRU. Newest goes to `url1` and pushes older entries down. Timestamp is per-key; dates the most-recent entry only.

## Cross-references
- **ShellBags** records the actual folder view state after navigation — a TypedPaths entry without a corresponding ShellBags subkey indicates navigation that never produced a detailed-view state (quick jump-and-close)
- **UNC TypedPaths** cross-reference with **Security-5140** share-access events on the target server
- **TerminalServerClient-Default** for RDP targets is a different substrate — TypedPaths is Explorer-specific

## Practice hint
A user who "never uses UNC paths" with UNC entries in TypedPaths is worth investigating. Same for shell:: entries — these appear in ~5% of normal user history.
