---
name: RecentFileCache-BCF
title-description: "RecentFileCache.bcf — legacy pre-Amcache execution-evidence binary cache (Win7 / Win8 era)"
aliases:
- RecentFileCache.bcf
- Application Compatibility Cache (legacy)
- pre-Amcache cache
link: application
tags:
- execution-evidence
- legacy-system
- itm:ME
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: RecentFileCache-BCF
platform:
  windows:
    min: '7'
    max: '8.1'
    note: "The BCF cache was replaced by Amcache.hve starting with Windows 8 (coexisted during 8.0 / 8.1) and is absent on stock Windows 10+ installs. However it may still be present on long-lived machines upgraded from Win7 / 8.1 — in-place upgrades do NOT always remove it. Always check even on modern hosts."
  windows-server:
    min: '2008R2'
    max: '2012R2'
location:
  path: "%WINDIR%\\AppCompat\\Programs\\RecentFileCache.bcf"
  addressing: file-path
  note: "Single flat binary file. Sibling directory holds Amcache.hve on modern Windows; on Win7 era systems this BCF file is the only Amcache-equivalent. Format is undocumented by Microsoft; community reversing (Brian Baskin, Harlan Carvey) produced the parser structure."
fields:
- name: executable-path
  kind: path
  location: "RecentFileCache.bcf record — length-prefixed UTF-16LE string"
  encoding: utf-16le with uint32 length prefix
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: "Full path of an executable the Application Compatibility engine observed being launched. Cache is populated by the AELookup service as part of Windows' shim-selection logic. For Win7-era execution-evidence investigations, this is the direct predecessor of Amcache's InventoryApplicationFile data."
- name: record-sequence
  kind: identifier
  location: "record header — sequence number"
  encoding: uint32 le
  note: "Monotonically increasing per-entry. No timestamps are embedded per record (the format's biggest DFIR weakness vs. Amcache); ordering reflects the sequence of observed executions within a single AELookup session window."
- name: magic-header
  kind: label
  location: "file header bytes 0..3"
  encoding: fixed bytes
  note: "Legacy magic identifying the BCF format. Mismatched or absent magic = file has been tampered or is actually something else."
- name: file-mtime
  kind: timestamp
  location: RecentFileCache.bcf file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime of the whole file. Updated each time a new execution is recorded. Serves as the only file-level timestamp clue — the records inside have no per-entry times, so the mtime gives the latest-observed-execution bound."
- name: file-size
  kind: counter
  location: file size
  encoding: uint32
  note: "Grows as records are appended. Very small file (a few KB) on a lightly-used host; can reach tens of KB. A file of zero or near-zero size on an actively-used host = recently cleared."
observations:
- proposition: RAN_PROCESS
  ceiling: C3
  note: 'RecentFileCache.bcf proves program execution on Win7 / 8.x era
    systems the same way Amcache does on modern Windows — except with
    weaker timestamps and a simpler schema. Because in-place upgrades
    from Win7 sometimes leave the file behind on machines that are
    now Windows 10 or 11, this artifact still surfaces in real
    investigations a decade after BCF was deprecated. For cold cases,
    incident retrospectives, or evidence hosts that were upgraded
    rather than wiped, this file is worth grepping for.'
  qualifier-map:
    object.path: field:executable-path
    time.end: field:file-mtime
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  known-cleaners:
  - tool: "delete %WINDIR%\\AppCompat\\Programs\\RecentFileCache.bcf"
    typically-removes: all execution records (file is not recreated on modern systems — AELookup populates Amcache.hve instead)
  survival-signals:
  - RecentFileCache.bcf present on a Windows 10 / 11 host = upgraded-from-Win7 evidence with potential execution history predating the upgrade
  - mtime older than OS install date = evidence from the pre-upgrade OS preserved
  - Entries listing paths that no longer exist on disk = deleted attacker tooling with surviving execution record
provenance:
  - carvey-2013-recentfilecache-bcf-parser-and
---

# RecentFileCache.bcf (legacy pre-Amcache execution evidence)

## Forensic value
Single binary file at `%WINDIR%\AppCompat\Programs\RecentFileCache.bcf`. The Application Compatibility engine (AELookup service) wrote an entry here each time it observed an executable launch — primarily to cache shim-applicability decisions. Forensically, each entry is a record of program execution.

## Historical context
Windows 7 shipped with RecentFileCache.bcf as its primary execution-evidence cache. Windows 8 introduced Amcache.hve as a successor (richer schema, per-entry timestamps, SHA-1 hashes). Windows 8.1 carried both. Windows 10 removed the BCF mechanism from clean installs.

**In practice, BCF files STILL appear on modern systems** because in-place upgrades (Win7 → Win10, Win8.1 → Win10) do not always clean `%WINDIR%\AppCompat\Programs\`. On a host that was upgraded rather than rebuilt, the BCF file can preserve execution evidence from the pre-upgrade operating system — potentially years old — that survives every subsequent forensic window on that machine.

## Limitations vs. Amcache
- **No per-entry timestamps** — only the file-level mtime bounds the most-recent write
- **Paths only** — no SHA-1 hash, no version info, no publisher
- **Fragile** — any tool that cleans `AppCompat\Programs\` as part of "system cleanup" wipes it silently

Despite the weaknesses, when Amcache is missing or cleared, BCF is the fallback execution record.

## Concept reference
- ExecutablePath (one per embedded executable path record)

## Parsing
```cmd
# KAPE includes a BCF parser
RECmd.exe --d %WINDIR%\AppCompat\Programs  # Amcache — separate tool for BCF
```

Community tools:
- Harlan Carvey's `recentfilecache.pl` (Perl) — original reversing work
- `bcfparser` implementations in various IR toolkits
- Hex-editor fallback: find the UTF-16LE BOM and decode path records manually; format is simple enough for one-off scripts

## Triage
```cmd
if exist "%WINDIR%\AppCompat\Programs\RecentFileCache.bcf" (
    echo "BCF present — parse for execution evidence"
    dir /a /t:w "%WINDIR%\AppCompat\Programs\RecentFileCache.bcf"
)
```

On a modern Win10/11 host, the file's *existence* is the signal — it should not be on a clean-install machine.

## Practice hint
On a Windows 7 VM (or an old-era VHD), observe the BCF file growing as you launch various test binaries. Then upgrade the VM to Windows 10 in-place — note whether `%WINDIR%\AppCompat\Programs\RecentFileCache.bcf` survived the upgrade. Parse it to recover the Win7-era execution trail from the post-upgrade Win10 system. This is the exact scenario a cold-case investigator reproduces.
