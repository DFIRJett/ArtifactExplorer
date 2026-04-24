---
name: Chrome-History
aliases:
- Chromium History
- Edge History
- browser-history-sqlite
link: network
link-secondary: application
tags:
- timestamp-carrying
- per-user
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: History
platform:
  windows:
    min: '7'
    max: '11'
  windows-server:
    min: '2012'
    max: '2022'
  macos:
    min: '10.12'
    max: '15'
  linux:
    min: any
    max: any
location:
  path: '%LOCALAPPDATA%\Google\Chrome\User Data\Default\History'
  edge-path: '%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History'
  brave-path: '%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\History'
  addressing: sqlite-table-row
fields:
- name: url
  kind: path
  location: urls table — url column
  encoding: utf-8
  references-data:
  - concept: URL
    role: visitedUrl
  note: full URL including scheme, host, path, query
- name: host
  kind: identifier
  location: parsed from url column (authority part)
  encoding: ascii-lowercased
  references-data:
  - concept: DomainName
    role: httpRequestHost
- name: title
  kind: identifier
  location: urls table — title column
  encoding: utf-8
  note: HTML <title> at time of visit
- name: visit-count
  kind: counter
  location: urls table — visit_count column
  encoding: int64
- name: typed-count
  kind: counter
  location: urls table — typed_count column
  encoding: int64
  note: how many times the user typed this URL (vs following a link) — high typed_count = bookmarked-equivalent
- name: last-visit-time
  kind: timestamp
  location: urls table — last_visit_time column
  encoding: Chrome-epoch microseconds (μs since 1601-01-01 UTC — same as FILETIME but in μs)
  clock: system
  resolution: 1us
  note: 'convert: unix_ts = (chrome_ts / 1000000) - 11644473600'
- name: visit-time
  kind: timestamp
  location: visits table — visit_time column
  encoding: Chrome-epoch microseconds
  clock: system
  resolution: 1us
  note: each row in visits = one visit event; urls.last_visit_time is the max across visits rows
- name: visit-transition
  kind: enum
  location: visits table — transition column
  encoding: uint32-bitfield
  note: bit 0-7 = core type (LINK, TYPED, BOOKMARK, RELOAD, etc.); bits 8+ = qualifier flags
- name: from-visit
  kind: identifier
  location: visits table — from_visit column
  encoding: int64
  note: references parent visit row — reconstruct browse trail via this FK chain
- name: download-target-path
  kind: path
  location: downloads table — target_path column
  encoding: utf-8
  note: filesystem path where a downloaded file was saved
- name: download-start-time
  kind: timestamp
  location: downloads table — start_time column
  encoding: Chrome-epoch microseconds
  clock: system
  resolution: 1us
- name: download-received-bytes
  kind: counter
  location: downloads table — received_bytes column
  encoding: int64
- name: download-referrer
  kind: path
  location: downloads table — referrer column
  encoding: utf-8
  references-data:
  - concept: URL
    role: referrerUrl
observations:
- proposition: COMMUNICATED
  ceiling: C3
  note: 'Each urls row proves the browser requested that URL at least once,

    and the user had access to the resulting content (unless the page

    failed to load, which doesn''t populate history). Per-user scoped via

    the browser profile.

    '
  qualifier-map:
    direction: sent
    peer.url: field:url
    peer.host: field:host
    time.start: field:last-visit-time
    frequency.count: field:visit-count
- proposition: ACCESSED
  ceiling: C3
  note: downloads table proves specific file acquisition — downloaded file path + referrer URL
  qualifier-map:
    object.path: field:download-target-path
    peer.url: field:download-referrer
    time.start: field:download-start-time
anti-forensic:
  write-privilege: user
  integrity-mechanism: SQLite WAL — recent transactions may not be in main DB
  known-cleaners:
  - tool: Chrome 'Clear browsing data'
    typically-removes: full
    note: user-initiated; can be selective by date range
  - tool: manual delete of History file
    typically-removes: full
    note: browser recreates on next launch but with no history
  - tool: CCleaner browser module
    typically-removes: full
  survival-signals:
  - History file absent but Downloads\ directory has files = history cleared AFTER downloads completed
  - visits table has rows with from_visit references that have no matching id = parent visits were deleted selectively; orphan
    chain
  - WAL file has recent entries not in main DB = ongoing browser session (acquire WAL too)
provenance:
  - chromium-history-schema
  - sqlite-org-fileformat
  - benson-hindsight
---

# Chromium-family Browser History

## Forensic value
Every modern browser based on Chromium (Chrome, Edge, Brave, Opera, Vivaldi) stores its history in a SQLite file named `History`. Three critical tables:

- **urls** — one row per unique URL; `visit_count`, `typed_count`, `last_visit_time`
- **visits** — one row per visit event; `from_visit` links child to parent visits, enabling browse-trail reconstruction
- **downloads** — one row per file download; target path, URL, referrer, byte count, MIME type

For any web-based investigation — phishing victim, malware download, C2 exfiltration — Chrome History is typically the primary browser artifact.

## Two concept references
- URL (urls.url, downloads.target_path as path, downloads.referrer)
- DomainName (parsed host from URL)

## Timestamp format is Chrome-specific
Chrome uses `microseconds since 1601-01-01 UTC` — like FILETIME but in microseconds (FILETIME is 100ns intervals). Conversion to Unix epoch:
```
unix_epoch_seconds = (chrome_ts / 1_000_000) - 11_644_473_600
```

SQL: `datetime(column/1000000-11644473600, 'unixepoch')`

## Known quirks
- **File locked while browser runs.** Must acquire via VSS, or close browser first (disruptive — alerts user).
- **WAL file is critical.** Recent browsing may live only in `History-wal` until Chrome commits. Acquire `History`, `History-wal`, `History-journal`, `History-shm` together.
- **Sync data** doesn't appear here in this file — Chrome's synced-bookmarks and cross-device data lives in `Sync Data/` subdirectory.
- **Per-profile separation.** "Default" profile is the first/main profile; additional profiles are `Profile 1`, `Profile 2`, etc. Each has its own `History` file.
- **Typed vs. link vs. bookmark transitions** in the `visits.transition` field reveal user intent — typed counts as deliberate navigation.

## Practice hint
Copy your own `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` (after closing Chrome). Open with DB Browser for SQLite. Run:
```sql
SELECT
  datetime(v.visit_time/1000000-11644473600, 'unixepoch', 'localtime') AS visited,
  u.url,
  u.title,
  v.transition
FROM visits v JOIN urls u ON v.url = u.id
ORDER BY v.visit_time DESC LIMIT 50;
```
That's your last 50 page visits in timeline order.
