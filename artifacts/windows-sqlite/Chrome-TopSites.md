---
name: Chrome-TopSites
aliases: [Chromium most-visited tiles]
link: user
link-secondary: application
tags: [per-user]
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: Chrome-TopSites
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Top Sites"
  addressing: sqlite-table-row
fields:
- name: url
  kind: url
  location: top_sites table → url
  references-data:
  - {concept: URL, role: visitedUrl}
- name: url_rank
  kind: counter
  location: top_sites table → url_rank
  note: "rank among most-visited; survives browser open/close"
- name: title
  kind: label
  location: top_sites table → title
observations:
- proposition: FREQUENTLY_VISITED
  ceiling: C2
  note: "Top N most-visited sites surface on the new-tab page. Ranked list of the user's high-frequency destinations."
  qualifier-map:
    object.url: field:url
    object.rank: field:url_rank
anti-forensic:
  write-privilege: unknown
provenance: [chromium-history-schema]
---

# Chrome-TopSites

## Forensic value
Small SQLite DB that backs the new-tab-page tile grid. Useful for "what does this user actually use the browser for" questions — complements History (full visit list) with a ranked top-N.

## Cross-references
- **Chrome-History** — the full visit-by-visit record
- **Chrome-Bookmarks** — deliberate saves vs TopSites passive frequency
