---
name: Edge-History
aliases:
- Microsoft Edge Chromium history
- Edge urls table
link: application
tags:
- per-user
- tamper-easy
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: Edge-History
platform:
  windows:
    min: '10'
    max: '11'
    note: Chromium-based Edge only (legacy Edge is in windows-ess WebCache)
location:
  path: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History"
  addressing: sqlite-table-row
fields:
- name: url
  kind: url
  location: urls table → url column
  references-data:
  - concept: URL
    role: visitedUrl
- name: title
  kind: label
  location: urls table → title column
- name: visit_count
  kind: counter
  location: urls table → visit_count
- name: typed_count
  kind: counter
  location: urls table → typed_count
  note: times URL was manually typed (vs. clicked) — user-intent discriminator
- name: last_visit_time
  kind: timestamp
  location: urls table → last_visit_time
  encoding: webkit-microseconds
  clock: system
  resolution: 1us
- name: visit_time
  kind: timestamp
  location: visits table → visit_time (joined by url_id)
  encoding: webkit-microseconds
  note: per-visit row; urls.last_visit_time is the max over this set
- name: from_visit
  kind: reference
  location: visits table → from_visit
  note: chain-predecessor visit id for navigation reconstruction (back/forward, redirects)
- name: transition
  kind: flag
  location: visits table → transition
  note: PAGE_TRANSITION_* core type + qualifier bits — typed (0), link (1), auto-bookmark (2), auto-subframe (3), reload (8), etc.
- name: host
  kind: hostname
  location: urls table → extracted from url
  references-data:
  - concept: DomainName
    role: httpRequestHost
observations:
- proposition: ACCESSED
  ceiling: C3
  note: Per-URL visit record. Typed-count + transition type discriminate deliberate navigation from redirects/embedded content.
  qualifier-map:
    actor.user: profile-directory owner
    object.url: field:url
    time.last_access: field:last_visit_time
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - tool: Edge Settings → Clear browsing data
    typically-removes: full (+ VACUUM for row-recovery defeat)
provenance: [chromium-history-schema]
---

# Edge-History

## Forensic value
Chromium-based Edge shares the Chrome history schema byte-for-byte. Same `urls`, `visits`, `downloads`, `keyword_search_terms` tables. Tools built for Chrome-History work on Edge-History with only path changes.

Key difference from Chrome: corporate environments often have Edge managed by policy with sync tied to Azure AD; the sync'd history can include URLs visited on other managed devices under the same AAD user. Verify sync state via Edge settings or the `Login Data` DB.

## Typed vs clicked discrimination
`typed_count` is distinct from `visit_count`. A URL with `visit_count=50` but `typed_count=0` was reached via links/redirects only (rarely user-intentional for unusual sites). A URL with `typed_count>0` was manually entered — much stronger user-intent evidence.

## Visit chains
`visits.from_visit` builds a tree. Start from a URL of interest and walk backwards to find the origin navigation:
```sql
WITH RECURSIVE chain(id, url, from_id, depth) AS (
  SELECT v.id, u.url, v.from_visit, 0
    FROM visits v JOIN urls u ON u.id=v.url
    WHERE u.url LIKE '%suspicious-domain%'
  UNION ALL
  SELECT v.id, u.url, v.from_visit, chain.depth+1
    FROM visits v JOIN urls u ON u.id=v.url, chain
    WHERE v.id = chain.from_id
)
SELECT * FROM chain ORDER BY depth;
```

## Transition bits
Low byte of `transition` is the core type; upper bits are qualifiers (TRANSITION_CHAIN_START, TRANSITION_CHAIN_END, SERVER_REDIRECT, etc.). Mask with `0xFF` for the core type.

## Cross-references
- **Chrome-Downloads** / **Edge-Downloads** — downloads table in this same DB
- **Chrome-Cookies** / **Edge-Cookies** — network/Cookies DB
- **ActivitiesCache** — Edge activity also syncs here with richer payload metadata

## Practice hint
```sql
-- Top 20 typed destinations in last 30 days
SELECT url, typed_count, datetime((last_visit_time-11644473600000000)/1000000,'unixepoch') AS last
FROM urls WHERE typed_count > 0
  AND last_visit_time > (strftime('%s','now','-30 days')+11644473600)*1000000
ORDER BY typed_count DESC LIMIT 20;
```
