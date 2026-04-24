---
name: WordWheelQuery
aliases:
- Explorer search history
- Start menu search MRU
- WordWheel queries
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
    min: '7'
    max: '11'
location:
  hive: NTUSER.DAT
  path: Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
  addressing: hive+key-path
fields:
- name: query-slot
  kind: label
  location: values named '0', '1', '2', ... (numeric)
  type: REG_BINARY
  encoding: UTF-16LE null-terminated
  note: each slot holds one search string the user typed into Explorer's search box or Start menu search
- name: MRUListEx
  kind: order
  location: MRUListEx value
  type: REG_BINARY
  encoding: array of uint32-le (each = a slot number, most-recent-first)
  note: ordering of the numeric value names; same pattern as RecentDocs MRUListEx
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: on each new search submission
observations:
- proposition: SEARCHED
  ceiling: C3
  note: User typed search queries into Explorer/Start search. Rich user-intent artifact — users search for content they know exists or suspect exists; queries often reveal knowledge of specific filenames, keywords, or emails.
  qualifier-map:
    actor.user: NTUSER.DAT owner
    object.query: field:query-slot
    time.last: field:key-last-write (most-recent only)
anti-forensic:
  write-privilege: user
  known-cleaners:
  - tool: Settings → Search → Clear search history
    typically-removes: full (newer Win10+)
  - tool: CCleaner
    typically-removes: full
  - tool: manual reg delete
    typically-removes: surgical
provenance: []
---

# WordWheelQuery

## Forensic value
Every search the user types into Explorer's search box (or the Start menu search, depending on Windows version) is recorded here. Distinct from:

- **RunMRU** (Win+R command history) — commands, not searches
- **TypedPaths** (Explorer address bar) — paths typed for navigation
- **RecentDocs** (per-extension file history) — files opened

WordWheelQuery is the **intent-to-find** artifact. Queries reveal:

- **Knowledge claims** — user searched for "passwords.xlsx" suggests awareness the file might exist
- **Content keywords** — "project phoenix", "Q3 budget", specific codenames indicate subject-matter knowledge
- **Contact-name searches** — searching for a person's name in Explorer suggests looking for emails or documents about them

## Encoding quirk
Unlike most REG_SZ string MRUs, WordWheelQuery stores strings as **REG_BINARY** containing UTF-16LE text. Parsers must read the binary blob and decode it; direct `reg query` output shows raw hex. Use RegistryExplorer, RECmd, or custom scripts that explicitly handle this encoding.

## Most-recent-first ordering
The `MRUListEx` value is a byte array of little-endian uint32s. Each uint32 is a slot number. The first uint32 is the most-recent query, the second is the one before that, and so on. Terminator is `0xFFFFFFFF`.

```
Example MRUListEx: 03 00 00 00 | 01 00 00 00 | 00 00 00 00 | 02 00 00 00 | FF FF FF FF
Interpretation:    slot 3, then 1, then 0, then 2 (most-recent to oldest)
```

## Cross-references
- **Windows-Search-edb** (Windows.edb) — the index the searches RAN against. Queries in WordWheelQuery that returned content hits leave traces in Windows.edb access timestamps.
- **RecentDocs** — files the user opened AFTER searching often appear here
- **ActivitiesCache** — Timeline may capture the Explorer search activity with the query payload

## Practice hint
For a quick user-intent triage:
```powershell
$vals = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery' -EA 0
$vals.PSObject.Properties |
  Where-Object { $_.Name -match '^\d+$' } |
  ForEach-Object { [pscustomobject]@{
    Slot = $_.Name
    Query = [System.Text.Encoding]::Unicode.GetString($_.Value).TrimEnd([char]0)
  }}
```
Shows every cached search query with its slot number.
