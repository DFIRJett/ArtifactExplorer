---
name: Search-Gather-Logs
title-description: "Windows Search gather logs — per-indexer-run records of what content was indexed when (.gthr / .Crwl)"
aliases:
- SystemIndex gather logs
- Windows Search crawl logs
- .gthr files
- .Crwl files
link: file
link-secondary: application
tags:
- search-index-timeline
- file-access-trace
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: Search-Gather-Logs
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  path-gather: "%ProgramData%\\Microsoft\\Search\\Data\\Applications\\Windows\\GatherLogs\\SystemIndex\\SystemIndex.*.gthr"
  path-crawl: "%ProgramData%\\Microsoft\\Search\\Data\\Applications\\Windows\\GatherLogs\\SystemIndex\\SystemIndex.*.Crwl"
  path-jfm: "%ProgramData%\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.jfm"
  companion-edb: "Windows.edb (already covered as separate artifact Windows-Search-edb)"
  addressing: file-path
  note: "Windows Search indexer (SearchIndexer.exe) writes gather logs every time it scans the filesystem / mail stores / other content sources for changes. .gthr files record the crawl batch metadata — start time, end time, items processed, error counts. .Crwl files record the per-item crawl results. Together they provide a TIMELINE of indexer activity + a RECORD of which filesystem paths / items were visited. Distinct from the Windows.edb database (which holds the resulting INDEX); gather logs describe the CRAWL that produced the index. For DFIR, gather logs reveal what the indexer SAW — including paths that have since been deleted or renamed."
fields:
- name: crawl-path
  kind: path
  location: ".Crwl log lines — per-item path entries"
  encoding: utf-16le (text)
  references-data:
  - concept: MFTEntryReference
    role: targetFile
  note: "Path of each item visited in the crawl. Includes local filesystem paths, mail-store item IDs (Outlook), and any other Search-enabled content source. Reveals filesystem paths the indexer reached — and thus files that existed at crawl time even if they've since been deleted. Attacker-dropped files the indexer had time to scan before deletion appear here."
- name: crawl-result
  kind: flags
  location: ".Crwl log lines — per-item status code"
  encoding: integer (Windows status codes)
  note: "Status of each crawl attempt: SUCCESS, FAILED, ACCESS_DENIED, IN_USE, etc. Access-denied on a path the indexer normally reaches = signal of ACL tampering. Large-scale FAILED entries during attacker-window = possible deliberate indexer disruption."
- name: batch-start-time
  kind: timestamp
  location: ".gthr header — CrawlStart field"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "When the crawl batch began. Gives the temporal anchor: 'indexer was scanning filesystem at this moment.'"
- name: batch-end-time
  kind: timestamp
  location: ".gthr header — CrawlEnd field"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "When the batch finished. Short batches with many items = fast-changing directory; long batches = large / slow content source."
- name: items-processed
  kind: counter
  location: ".gthr header — ItemCount / ProcessedCount"
  encoding: uint32
  note: "Number of items processed in this batch. Correlates crawl intensity with user activity periods. Abnormal spikes / drops can indicate malware activity (many new files created) or tampering (indexer disabled / errors)."
- name: file-mtime
  kind: timestamp
  location: each .gthr / .Crwl file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime = when the file was written. For recent logs this is very close to the embedded batch-end-time. For archived logs it's the same — these files are not modified after creation."
- name: log-rotation
  kind: identifier
  location: "SystemIndex.<N>.gthr numbering"
  note: "Sequence number. Sorted chronologically gives an ordered history of crawl batches. Default retention keeps dozens of batches on an active system — weeks of indexer timeline recoverable."
observations:
- proposition: OBSERVED_FILE
  ceiling: C3
  note: 'Windows Search gather logs are an under-appreciated source of
    file-access-adjacent timeline data. The indexer runs
    automatically and scans user-writable directories (Documents,
    Desktop, OneDrive, Outlook mail store by default) on a rolling
    basis. Each scanned item is recorded with its path at the time.
    For DFIR, this means: files that existed in indexed directories
    at any point during the indexer''s scan windows are logged —
    including files the attacker dropped and later deleted, if the
    indexer happened to scan them before deletion. Not a perfect
    artifact — indexed paths are limited by indexer settings — but
    for the default Documents-and-Outlook setup this covers user
    home directory + mail evidence.'
  qualifier-map:
    object.path: field:crawl-path
    time.start: field:batch-start-time
    time.end: field:batch-end-time
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: none
  known-cleaners:
  - tool: disable Windows Search service + delete GatherLogs directory
    typically-removes: all historical gather logs
  - tool: rebuild search index via Control Panel
    typically-removes: gather logs + rebuilds from scratch
  survival-signals:
  - .gthr / .Crwl files present with batch-start-times spanning incident window = timeline of indexer activity during intrusion
  - .Crwl entries for attacker-tooling paths that are no longer on disk = surviving proof of file existence
  - Gap in gather-log sequence numbering corresponding to intrusion window = indexer disabled (tamper signal)
provenance: [ms-windows-search-architecture-gather, moore-2020-powercfg-energy-reports-as-for]
---

# Windows Search Gather Logs

## Forensic value
`%ProgramData%\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex\*.gthr` + `*.Crwl` files record per-batch activity of the Windows Search indexer (SearchIndexer.exe). Every time the indexer runs a crawl batch — scanning the filesystem, mail stores, or other content sources for changes — it writes a new log file pair.

Distinct from `Windows.edb` (the resulting search index database): gather logs record **what the indexer observed during the crawl**, including file paths, per-item status, and batch timing.

## Why this matters
The indexer runs automatically and visits:
- User profile Documents / Desktop / Downloads / Pictures
- Outlook mail store (.ost / .pst)
- Start Menu
- Offline Files namespace (if enabled)
- Any other user-added Indexed Location

Gather logs preserve the path of each indexed item — including files that existed at crawl time even if they have since been deleted. For intrusions that landed binaries / staged files in indexed directories (Downloads is indexed by default), the indexer's crawl of those files leaves a trace.

## Three-file indexer architecture
- `Windows.edb` — ESE-format search index (covered separately as Windows-Search-edb)
- `Windows.jfm` — journal / metadata file
- `GatherLogs\SystemIndex\*.gthr` + `*.Crwl` — per-crawl-batch activity logs

This artifact covers the gather-log pair. Parse all three together for full indexer-history reconstruction.

## Concept reference
- None direct — indexer-timeline artifact.

## Triage
```cmd
dir /a /o:d "%ProgramData%\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex\"
```

## Parsing
The .gthr / .Crwl format is binary with mixed text sections. Community parsers:
- `SearchIndexExtractor` (SANS / Phill Moore releases)
- `libsearch` (Joachim Metz)
- Hex-editor manual walk for one-offs

## Cross-reference
- **Windows-Search-edb** — built search index
- **UsnJrnl** — filesystem-level record of changes the indexer saw
- **Prefetch SearchIndexer.exe** — execution evidence of the indexer itself
- **Microsoft-Windows-Search/Operational** EVTX — indexer operational events

## Practice hint
On a lab VM, wait for the Windows Search service to be active a while (or trigger indexing by creating files in Documents). Then inspect `%ProgramData%\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex\` — multiple `.gthr` / `.Crwl` pairs with sequential numbering. Open in hex to confirm batch-start-times and per-item path entries.
