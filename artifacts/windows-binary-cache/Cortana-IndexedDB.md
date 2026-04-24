---
name: Cortana-IndexedDB
title-description: "Cortana IndexedDB.edb — UWP Cortana app's indexed search content ESE database"
aliases:
- Cortana IndexedDB
- IndexedDB.edb
- Cortana app search index
link: user
link-secondary: application
tags:
- per-user
- uwp-state
- search-index
volatility: persistent
interaction-required: user-action
substrate: windows-binary-cache
substrate-instance: Cortana-IndexedDB
platform:
  windows:
    min: '10'
    max: '11'
    note: "Per-user Cortana UWP app data. Persists through Cortana deprecation as long as the AppData Packages directory remains."
  windows-server: N/A (client-only)
location:
  path: "%LOCALAPPDATA%\\Packages\\Microsoft.Windows.Cortana_*\\AppData\\Indexed DB\\IndexedDB.edb"
  sibling: "CortanaCoreDb.dat (per-user Cortana reminders / geolocation)"
  addressing: file-path
  note: "ESE (JET) database holding UWP Cortana's indexed content. Separate from CortanaCoreDb.dat (the core reminder / place database). IndexedDB contains cached indexed content — search-result tiles, recent queries, suggestion metadata. Exposes historical Cortana usage distinct from the reminder / location data in CoreDb."
fields:
- name: indexed-query
  kind: content
  location: "per-UWP-IndexedDB object-store tables"
  encoding: varies (key-value pairs per object store)
  references-data:
  - concept: URL
    role: visitedUrl
  note: "Text content of indexed queries / tiles. Surfaces recent Cortana search queries, suggestion content, and cached web-result snippets the UWP assistant displayed. Similar in flavor to browser search history but specifically Cortana-sourced."
- name: query-timestamp
  kind: timestamp
  location: per-record timestamp columns
  encoding: filetime-le
  clock: system
  resolution: 1s
  note: "When the query / tile was indexed. Gives per-query timeline of Cortana assistant usage."
- name: file-mtime
  kind: timestamp
  location: IndexedDB.edb $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "Last Cortana IndexedDB write. Stale mtime = Cortana usage tapered off (normal on Win11 builds where Cortana is deprecated)."
observations:
- proposition: HAD_CONTENT
  ceiling: C2
  note: 'Cortana IndexedDB.edb supplements CortanaCoreDb.dat for user-
    activity reconstruction. Where CoreDb has reminders / geolocation,
    IndexedDB has search queries and indexed tile content. Lower
    C-ceiling (C2) because content is derivative / cached from
    upstream sources (web, calendar, OS-wide search) rather than
    user-authored. Still useful as corroborating evidence of
    Cortana interaction patterns.'
  qualifier-map:
    object.content: field:indexed-query
    time.start: field:query-timestamp
anti-forensic:
  write-privilege: user
  integrity-mechanism: ESE page checksums
  known-cleaners:
  - tool: Cortana reset / uninstall
    typically-removes: whole Packages directory
  survival-signals:
  - IndexedDB.edb present on a host = historical Cortana usage worth triaging alongside CoreDb
provenance:
  - ms-uwp-indexeddb-api-storage-model
---

# Cortana IndexedDB

## Forensic value
`%LOCALAPPDATA%\Packages\Microsoft.Windows.Cortana_*\AppData\Indexed DB\IndexedDB.edb` is the UWP IndexedDB storage behind Cortana's indexed content and cached search queries. Sibling to `CortanaCoreDb.dat` which holds the core reminder / geolocation / people data.

Together these two files reconstruct most of the Cortana-usage picture for a user.

## Triage
Open with `esedbexport` or NirSoft `ESEDatabaseView`. Look for tables / object-stores holding query text, tile content, and timestamps.

## Practice hint
Parse both CoreDb and IndexedDB from the same user profile — the combined output gives a fuller picture than either alone.
