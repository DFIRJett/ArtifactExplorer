---
name: OneDrive-SafeDelete
title-description: "OneDrive SafeDelete.db — per-user SQLite journal of files sent to Recycle Bin via OneDrive"
aliases:
- OneDrive delete journal
- SafeDelete database
- items_sent_to_recycle_bin
link: file
link-secondary: application
tags:
- per-user
- evidence-destruction
- cloud-sync
- itm:AF
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: OneDrive-SafeDelete
platform:
  windows:
    min: '10'
    max: '11'
  windows-server:
    min: '2019'
    max: '2022'
location:
  path: "%LOCALAPPDATA%\\Microsoft\\OneDrive\\settings\\Personal\\SafeDelete.db and \\Business1\\SafeDelete.db"
  addressing: sqlite-table-row
  note: "One SafeDelete.db per configured OneDrive account (Personal, Business1, Business2 ...). Same directory that holds the OneDrive sync-engine state files. Database holds the items_sent_to_recycle_bin table whose rows persist independently of the Windows Recycle Bin itself — so the record survives emptying the Recycle Bin."
fields:
- name: local-path
  kind: path
  location: SafeDelete.db items_sent_to_recycle_bin table → filePath column
  note: "Full local path of the OneDrive-synced file that was deleted. For a user hiding exfil traces, this is the 'what did they try to hide' evidence."
- name: resource-id
  kind: identifier
  location: SafeDelete.db items_sent_to_recycle_bin table → resourceID column
  encoding: utf-8
  references-data:
  - concept: URL
    role: embeddedReferenceUrl
  note: "GraphDriveItemId — joins against OneDrive server-side audit logs and Graph API. Enables cross-checking what the cloud thinks happened vs. what the local client logged."
- name: deletion-time
  kind: timestamp
  location: SafeDelete.db items_sent_to_recycle_bin table → timestamp column
  encoding: unix-epoch-ms or ole-date (build-dependent)
  clock: system
  resolution: 1s
  note: "When the OneDrive client moved the item to Recycle Bin. More reliable than the Recycle Bin $I file's deletion-time field when the user has emptied the Recycle Bin before the investigation."
- name: size
  kind: counter
  location: SafeDelete.db items_sent_to_recycle_bin table → size column
  encoding: int64
  note: "Byte count of the deleted file. Large deletions (documents > 10 MB, zip archives) stand out and pair naturally with 'file was exfiltrated then removed' narrative."
- name: parent-folder
  kind: path
  location: SafeDelete.db items_sent_to_recycle_bin table → parentResourceID column
  note: "Graph driveItem ID of the containing folder. Joins back to OneDrive-SyncEngine state to reconstruct the folder hierarchy of deletions."
- name: db-mtime
  kind: timestamp
  location: SafeDelete.db file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime — updated on every new row. Pairs with row timestamps as an independent clock."
observations:
- proposition: DELETED
  ceiling: C4
  note: 'SafeDelete.db is one of the most important evidence-destruction
    detection artifacts on modern Windows. Unlike the Windows Recycle
    Bin (whose $I records vanish when the Recycle Bin is emptied),
    OneDrive''s SafeDelete.db journals every delete-via-OneDrive
    independently and persists long after the Recycle Bin itself is
    cleared. For insider-threat cases where the user deletes local
    copies of sensitive files after copying them out, this database
    provides a surviving timeline that directly contradicts "I never
    had that file" claims.'
  qualifier-map:
    object.path: field:local-path
    time.start: field:deletion-time
anti-forensic:
  write-privilege: user
  integrity-mechanism: SQLite page-level integrity only; no signing
  known-cleaners:
  - tool: delete SafeDelete.db while OneDrive is not running
    typically-removes: all rows (file is recreated empty on next OneDrive launch)
  survival-signals:
  - items_sent_to_recycle_bin rows post-dating the suspected exfil window = direct deletion evidence
  - SafeDelete.db file missing on a host with OneDrive installed and in-use = deliberate journal wipe (cross-check LocalLow OneDrive logs for recreate event)
  - Delete-row count >> Recycle Bin $I count = user emptied Recycle Bin but SafeDelete captured the history anyway
provenance:
  - labs-2023-onedrive-safedelete-db-a-sleep
  - khatri-2022-onedriveexplorer-parser-for-on
  - matrix-nd-dt061-detect-text-authored-in
---

# OneDrive SafeDelete.db

## Forensic value
OneDrive's sync client maintains a SQLite journal named `SafeDelete.db` in each account's settings directory. Every time a synced file is deleted through the OneDrive client (or through Explorer for a cloud-backed path) a row is inserted into the `items_sent_to_recycle_bin` table. Rows persist independently of:

- Windows Recycle Bin emptying (the $I / $R files go, SafeDelete rows stay)
- OneDrive client restarts
- User-profile logoff

Path: `%LOCALAPPDATA%\Microsoft\OneDrive\settings\Personal\SafeDelete.db` (and `Business1\`, `Business2\`, etc. for work/school accounts).

## Why it matters for insider-threat work
An insider typically:
1. Copies sensitive files to a personal USB / personal OneDrive / personal email.
2. Deletes the local copies to "cover tracks."
3. Empties the Recycle Bin to suppress `$I`/`$R` records.

Steps 1 and 2 leave rows in SafeDelete.db. Step 3 does NOT affect it. Investigators months later parse SafeDelete.db and recover the full deletion timeline — paths, sizes, timestamps, and Graph driveItem IDs that join to cloud-side audit logs.

## Concept references
- None direct — path + timestamp artifact, but the Graph driveItem IDs link it to cloud audit entries (SharePoint-Audit-Log, if populated).

## Triage
```powershell
# Find every SafeDelete.db on the image
Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\OneDrive\settings\*\SafeDelete.db" -ErrorAction SilentlyContinue

# Offline — dump rows with sqlite3
sqlite3 SafeDelete.db "SELECT datetime(timestamp/1000,'unixepoch'), filePath, size FROM items_sent_to_recycle_bin ORDER BY timestamp DESC;"
```

## Parsing
- `OneDriveExplorer` (Beercow) handles SafeDelete.db directly as part of the OneDrive client state export.
- For ad-hoc analysis any SQLite client works — schema is simple: `items_sent_to_recycle_bin(filePath, parentResourceID, resourceID, timestamp, size)`.

## Practice hint
On a test VM with OneDrive signed into a Personal account, create a dummy file inside the OneDrive folder, sync, delete it, then empty the Recycle Bin. Open `SafeDelete.db` and confirm the row survives. This is the exact workflow an insider-threat exfil case reproduces — you want this muscle memory when triaging a real case.
