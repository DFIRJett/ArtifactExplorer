---
name: Chrome-Bookmarks
aliases: [Chromium Bookmarks, Edge Bookmarks]
link: user
link-secondary: application
tags: [per-user, json-format, tamper-easy]
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: Chrome-Bookmarks
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Bookmarks"
  alternates:
  - "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Bookmarks"
  addressing: json-file
  note: "JSON file — despite the sqlite substrate, Bookmarks is plain JSON. Grouped here because it sits alongside the other Chromium SQLite stores."
fields:
- name: name
  kind: label
  location: "roots.bookmark_bar.children[].name (and other root arrays)"
- name: url
  kind: url
  location: "roots.bookmark_bar.children[].url"
  references-data:
  - {concept: URL, role: visitedUrl}
- name: date_added
  kind: timestamp
  location: "children[].date_added"
  encoding: webkit-microseconds
  clock: system
  resolution: 1us
- name: date_modified
  kind: timestamp
  location: "children[].date_modified (folders only)"
  encoding: webkit-microseconds
observations:
- proposition: USER_SAVED
  ceiling: C3
  note: "User-saved URLs — deliberate retention. Bookmarks is higher-intent than History (passive) — what the user considered worth keeping."
  qualifier-map:
    actor.user: profile-dir owner
    object.url: field:url
    time.saved: field:date_added
anti-forensic:
  write-privilege: user
  known-cleaners:
  - {tool: Bookmark manager delete, typically-removes: full}
provenance: []
---

# Chrome-Bookmarks

## Forensic value
JSON store of deliberate user bookmarks. Higher-intent signal than browser History (which is passive). The date_added / date_modified timestamps bound when each URL was saved.

## Cross-references
- **Chrome-History** — passive visit record; bookmarks is deliberate
- **Chrome-LoginData** — saved creds may share domains with bookmarks
