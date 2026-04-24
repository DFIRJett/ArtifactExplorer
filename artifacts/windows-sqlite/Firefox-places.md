---
name: Firefox-places
aliases:
- places.sqlite
- Firefox browser history
- Mozilla history
link: network
link-secondary: application
tags:
- timestamp-carrying
- per-user
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: places.sqlite
platform:
  windows: { min: "7", max: "11" }
  macos: { min: "10.12", max: "15" }
  linux: { any: true }

location:
  path: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<random-id>.default-<channel>\\places.sqlite"
  addressing: sqlite-table-row

fields:
- name: url
  kind: path
  location: moz_places — url column
  encoding: utf-8
  references-data:
  - concept: URL
    role: visitedUrl
- name: host
  kind: identifier
  location: moz_places — rev_host column (reversed-domain for fast suffix search)
  encoding: utf-8
  references-data:
  - concept: DomainName
    role: httpRequestHost
  note: stored in REVERSED form ('moc.elgoog' for 'google.com') — parsers must un-reverse
- name: title
  kind: identifier
  location: moz_places — title column
  encoding: utf-8
- name: visit-count
  kind: counter
  location: moz_places — visit_count column
  encoding: int64
- name: last-visit-date
  kind: timestamp
  location: moz_places — last_visit_date column
  encoding: "Firefox-epoch microseconds (μs since 1970-01-01 UTC — Unix epoch)"
  clock: system
  resolution: 1us
  note: "Firefox uses Unix epoch in μs, unlike Chrome's 1601-epoch — parsers MUST branch on browser family"
- name: visit-date
  kind: timestamp
  location: moz_historyvisits — visit_date column
  encoding: Firefox-epoch microseconds
  clock: system
  resolution: 1us
- name: visit-type
  kind: enum
  location: moz_historyvisits — visit_type column
  encoding: uint32
  note: "1=link, 2=typed, 3=bookmark, 4=embed, 5=redirect-permanent, 6=redirect-temporary, 7=download, 8=framed-link"
- name: from-visit
  kind: identifier
  location: moz_historyvisits — from_visit column
  encoding: int64
  note: referrer-visit id; chain for trail reconstruction like Chrome's from_visit
- name: place-id
  kind: identifier
  location: moz_historyvisits — place_id column
  encoding: int64
  note: FK to moz_places.id — join to get URL

observations:
- proposition: COMMUNICATED
  ceiling: C3
  note: |
    Firefox-specific browser-history analog of Chrome-History. Same
    investigative value: prove the browser requested URL X at time T
    under user U. Per-user profile scoped.
  qualifier-map:
    direction: sent
    peer.url: field:url
    peer.host: field:host
    time.start: field:last-visit-date
    frequency.count: field:visit-count

anti-forensic:
  write-privilege: user
  integrity-mechanism: SQLite WAL
  known-cleaners:
  - tool: Firefox 'Clear recent history'
    typically-removes: full
  - tool: CCleaner browser module
    typically-removes: full
  survival-signals:
  - places.sqlite empty but moz_favicons populated = history cleared but favicons orphan
  - places.sqlite-wal has entries not in places.sqlite = browser was running during acquisition
provenance: [mozilla-places-schema]
---

# Firefox places.sqlite

## Forensic value
Mozilla's browser-history storage. Same forensic role as Chrome-History but different database shape. For Firefox-using targets, places.sqlite is the browser-history artifact.

Same concept references as Chrome-History (URL + DomainName); different substrate-instance. The graph shows both as network-link artifacts in the sqlite cluster — visual proof that concepts span platforms.

## Schema key differences from Chrome
- **Timestamp format**: Firefox uses **microseconds since Unix epoch (1970-01-01)**; Chrome uses microseconds since 1601 (FILETIME base). Don't forget to branch.
- **rev_host column**: Firefox stores domain reversed (`moc.example.www` for `www.example.com`) to speed up suffix-based searches. Un-reverse before reporting.
- **moz_historyvisits** joins to **moz_places** via `place_id` — two-table join for full visit detail.

## Practice hint
Copy places.sqlite after closing Firefox. Run:
```sql
SELECT
  datetime(v.visit_date/1000000, 'unixepoch', 'localtime') AS visited,
  p.url, p.title, v.visit_type
FROM moz_historyvisits v JOIN moz_places p ON v.place_id = p.id
ORDER BY v.visit_date DESC LIMIT 50;
```
Same investigative question as Chrome, different SQL.
