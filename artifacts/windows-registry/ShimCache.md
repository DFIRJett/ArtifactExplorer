---
name: ShimCache
aliases:
- AppCompatCache
- Application Compatibility Cache
- cache of shim engine
link: application
tags:
- tamper-easy
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: XP
    max: '11'
  windows-server:
    min: '2003'
    max: '2022'
location:
  hive: SYSTEM
  path: CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache
  addressing: hive+key-path
  write-semantics: written to the registry on shutdown — live query sees stale data
fields:
- name: file-path
  kind: path
  location: per-entry — path field
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: may be drive-letter form OR \Device\HarddiskVolume<N>\... form depending on version
- name: last-modified-time
  kind: timestamp
  location: per-entry — $FN (NTFS FileName attribute) Modified time captured at cache
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: this is NOT 'when the exe ran' — it's the target's $FN-modified time at the moment ShimCache observed it
- name: file-size
  kind: counter
  location: per-entry (Win XP/7/8 only — dropped in Win10+)
  encoding: uint32-or-uint64
  availability:
    max-windows: '8.1'
- name: insertion-flag-legacy
  kind: flags
  location: "per-entry InsertFlags DWORD (Win Vista / 7 / 8 / 8.1 only)"
  encoding: "bit flag — 0x00000002 = Executed (Zimmerman's InsertFlags.Executed enum)"
  availability:
    min-windows: Vista
    max-windows: '8.1'
- name: execution-flag-win10
  kind: flags
  location: "per-entry — LAST 4 bytes of the Data field (Win10 1507+ / Win11)"
  encoding: "uint32-le; 0x00000001 = Executed, 0x00000000 = no-execution-confirmed"
  availability:
    min-windows: '10'
    max-windows: '11'
  note: "NOT the InsertFlags DWORD — that field was reorganized on Win10. Zimmerman's AppCompatCacheParser gained support in commit c995e82 (March 2023). Interpretation per Nullsec 23H2 testing: 'Yes' = high confidence executed; 'No' = INCONCLUSIVE (lsass.exe, cmd.exe, explorer.exe frequently show 0 despite clearly running)."
- name: header-magic
  kind: flags
  location: offset 0 of AppCompatCache value
  encoding: uint32-le
  note: "version discriminator: 0xdeadbeef=XP-32 (96 entries), 0xbadc0ffe=2003/Vista/7 (512–1024), 0x80000000 with header-size 0x80=Win8/8.1, header-size 0x30=Win10 1507–1607, header-size 0x34=Win10 1703+ / Win11. Entry magic '10ts' signals Win8.1+ entry layout."
- name: cache-ordinal
  kind: counter
  location: position in the cache list
  encoding: uint32
  note: entries are kept in MRU order; first entry = most recent
observations:
- proposition: EXISTS
  ceiling: C2
  note: 'ShimCache strongly indicates the OS has *seen* this file path — but the

    long-contested insertion-flag means ShimCache is not reliable evidence

    that the file *executed*. Solo ceiling is C2 (the file was on the disk

    at some point); corroboration with Prefetch or Amcache lifts to C3.

    '
  qualifier-map:
    entity.path: field:file-path
    entity.modified-at: field:last-modified-time
    time.start: field:last-modified-time
  preconditions:
  - system was cleanly shut down after the executions of interest (shutdown is when cache is written)
  - SYSTEM hive transaction logs replayed
  runtime-recovery: "for live hosts, ShimCache state lives in kernel memory until shutdown — recoverable from a memory capture via Volatility's shimcachemem plugin"
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  known-cleaners:
  - tool: manual reg-delete of AppCompatCache value
    typically-removes: full
  - tool: CCleaner
    typically-removes: false
    note: does not target this value
  survival-signals:
  - ShimCache shows executables absent from Amcache and Prefetch = unusual; investigate targeted cleanup of the latter two
provenance:
  - matrix-dt093-shimcache-mft-timestamp
  - mandiant-2012-leveraging-appcompatcache
  - mandiant-2015-caching-out-shimcache
  - zimmerman-appcompatcacheparser
  - regripper-plugins
---

# ShimCache

## Forensic value
Per-system cache of file-path + modified-time for executables the OS has "seen." Historically one of the primary execution artifacts because it existed long before Amcache and BAM. Still widely relied upon for Win7/8 forensics.

On modern Windows (10+) ShimCache's forensic value has decreased — file-size dropped, insertion-flag semantics deprecated — but path + modified-time remains useful for establishing that a path existed at some point, useful as a secondary corroborator.

## Key limitation
**ShimCache is written to registry at shutdown**, not during execution. A live-system registry query sees the last-shutdown's cache state. This means:
- Recent activity is not visible until reboot
- An attacker who clears the in-memory cache can prevent persistence
- Forensically, prefer offline SYSTEM hive analysis for Max accuracy

## Parser disagreements
- **Format varies across Windows versions.** XP, 2003, Vista, 7/2008R2, 8/2012, 8.1, 10 each have differences in entry layout, field presence, and encoding. Use version-aware parsers (AppCompatCacheParser / ShimCacheParser).
- **Insertion-flag interpretation**: Older tools label it "executed"; modern analysis treats this as unreliable. Do not report "X executed" based solely on ShimCache's execute-flag.

## Practice hint
Parse a test SYSTEM hive with AppCompatCacheParser. Cross-reference entries with Prefetch and Amcache for the same executables. Observe timestamp divergence — ShimCache captures target $FN-modified, Prefetch captures run time, Amcache captures first-inventoried time. Three timestamps, three different semantics.
