---
name: TypedURLs
aliases:
- IE TypedURLs
- Internet Explorer URL history
- Legacy Edge address bar history
link: network
tags:
- per-user
- tamper-easy
- user-intent
- legacy-browser
- recency-ordered
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: XP
    max: '11'
    note: IE is retired on Win10/11 but TypedURLs persists from any historical use and from legacy-mode invocations (Edge IE-mode for intranet sites)
location:
  hive: NTUSER.DAT
  path: Software\Microsoft\Internet Explorer\TypedURLs
  companion-path: Software\Microsoft\Internet Explorer\TypedURLsTime
  addressing: hive+key-path
fields:
- name: url-slot
  kind: url
  location: values named 'url1', 'url2', ..., 'url25'
  type: REG_SZ
  note: one user-typed URL per slot; slot 1 is the most recent
  references-data:
  - concept: URL
    role: visitedUrl
- name: url-time
  kind: timestamp
  location: TypedURLsTime subkey → value of same name as in TypedURLs
  type: REG_BINARY
  encoding: filetime-le (8 bytes)
  clock: system
  resolution: 100ns
  note: per-URL timestamp — when the URL was most-recently typed. Unlike most MRU artifacts where only the key-last-write gives a timestamp, TypedURLsTime gives per-entry timing.
- name: key-last-write
  kind: timestamp
  location: TypedURLs subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: on any url-slot add or reuse
observations:
- proposition: USER_TYPED_URL
  ceiling: C3
  note: User manually typed these URLs into IE/Edge-IE-Mode address bar. TypedURLsTime provides per-entry dating — rare among registry MRUs. Strongest evidence of deliberate web navigation pre-Chromium era. Distinct from NAVIGATED (which includes link-clicks, redirects, autocomplete-selections) — USER_TYPED_URL is strictly the manually-typed subset.
  qualifier-map:
    actor.user: NTUSER.DAT owner
    object.url: field:url-slot
    time.observed: field:url-time (per-URL)
anti-forensic:
  write-privilege: user
  known-cleaners:
  - tool: IE 'Delete browsing history' → Form data + history
    typically-removes: full
  - tool: CCleaner 'Internet Explorer history'
    typically-removes: full
  - tool: manual reg delete
    typically-removes: surgical
provenance: []
exit-node:
  is-terminus: false
  terminates:
    - USER_TYPED_URL
  sources:
    - crucial-2011-typedurls-part-1
    - forensafe-2021-typedurls
    - binalyze-kb-typedurls
  reasoning: >-
    TypedURLs is the unique terminus for manually-typed browser URLs in the IE / Edge-IE-Mode era. Unlike WebCache-V01 or Chrome-History which record visited-URL history broadly (link clicks, redirects, autocomplete selections), TypedURLs captures ONLY URLs the user manually typed. The companion TypedURLsTime key provides per-URL FILETIME dating — rare among registry MRUs which typically give only key-last-write. Population-trigger is strict: URL must be manually typed and the submission must reach the browser's address-bar commit path. USER_TYPED_URL is a narrower proposition than NAVIGATED, providing stronger user-intent evidence for deliberate web navigation.
  implications: >-
    Defensible citation for deliberate web navigation attribution in pre-Chromium browsing history. Even post-IE-deprecation, TypedURLs retains value: (a) historical residue on systems migrated from Win7/8 era; (b) ongoing population via Edge IE-mode for enterprise intranet sites; (c) legacy-malware analysis where implants abused IE for C2 / staging. Pair with WebCache-V01 (IE ESE DB) for typed-vs-all-visited contrast.
  preconditions: "NTUSER hive accessible; transaction logs replayed; user did not clear via IE/Edge 'Delete browsing history' → Form data + history toggle; joiner parser correlates TypedURLs and TypedURLsTime subkeys"
  identifier-terminals-referenced:
    - UserSID
provenance: [libyal-libregf, regripper-plugins]
---

# TypedURLs

## Forensic value
Internet Explorer's (and legacy pre-Chromium Edge's) typed-URL history. A URL appears here ONLY if the user manually typed it — URLs reached via links, redirects, autocomplete, or bookmarks do NOT get recorded here. Purest user-intent web navigation artifact in the Windows registry.

Why it matters despite IE being retired:
- **Historical residue** — users who were on Win7/8/10-pre-Chromium have TypedURLs preserved in NTUSER.DAT; the key isn't cleaned during Edge/Chrome migration
- **IE Mode in Edge** — enterprises running Edge with IE Mode for intranet sites still populate TypedURLs
- **Legacy malware persistence** — some older implants abused IE for C2 / staging; TypedURLs contaminated by abuse still shows up

## The TypedURLsTime companion (crucial)
TypedURLs alone gives you URLs. Its companion subkey `TypedURLsTime` gives you **per-URL timestamps** — a FILETIME per value. Without TypedURLsTime, only the most-recent entry can be dated (via key-last-write). With it, you can date every one of the up-to-25 entries independently.

```
TypedURLs\url1        "https://sensitive-site.internal"
TypedURLsTime\url1     FILETIME bytes → 2024-09-15 14:32:07 UTC
TypedURLs\url2        "https://corp-sharepoint.internal/..."
TypedURLsTime\url2     FILETIME bytes → 2024-09-15 14:15:03 UTC
```

Parsers must join the two subkeys. Registry Explorer and RECmd handle this; raw `reg query` output does NOT correlate them for you.

## Slot rotation and limit
Up to 25 slots (`url1` through `url25`). New typed URL goes to slot `url1`; slots `url1`-`url24` shift up by one; `url25` falls off. Exact collision handling: if an already-cached URL is re-typed, its slot moves to `url1` without creating a duplicate — so TypedURLs cannot tell you how many TIMES a URL was typed, only that it was typed and when-most-recently.

## Cross-references
- **WebCache-V01** (IE/Edge-legacy ESE DB) — visited-URL history including non-typed navigations; TypedURLs is a subset
- **Chrome-History / Edge-History** (Chromium-Edge era) — modern equivalent for typed-count discrimination
- **TypedPaths** — Explorer address bar (filesystem paths, UNC), distinct substrate; not URLs

## Practice hint
```powershell
$tu  = Get-ItemProperty 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLs' -EA 0
$tut = Get-ItemProperty 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLsTime' -EA 0
foreach ($p in $tu.PSObject.Properties) {
  if ($p.Name -match '^url\d+$') {
    $time = if ($tut.($p.Name)) { [datetime]::FromFileTimeUtc([BitConverter]::ToInt64($tut.($p.Name), 0)) }
    "$($p.Name): $($p.Value)  [$time]"
  }
}
```
