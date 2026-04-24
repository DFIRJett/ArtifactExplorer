---
name: Amcache-InventoryApplicationFile
aliases:
- InventoryApplicationFile
- Amcache PE-file inventory
- Program Compatibility Assistant PE cache
link: application
tags:
- timestamp-carrying
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: Amcache.hve
platform:
  windows:
    min: '8'
    max: '11'
  windows-server:
    min: '2012'
    max: '2022'
location:
  hive: Amcache.hve
  path: Root\InventoryApplicationFile\<FileId>-<PathHash>
  addressing: hive+key-path
  variants:
    win10: Root\InventoryApplicationFile
    win8.1: Root\File
fields:
- name: file-id
  kind: hash
  location: <FileId> portion of subkey name
  encoding: '''0000'' prefix + SHA1 (0000 + 40 hex chars)'
  references-data:
  - concept: ExecutableHash
    role: ranHash
  note: leading four zeros indicate SHA1 algorithm; the remaining 40 chars are the PE content SHA1
- name: lowercase-long-path
  kind: path
  location: LowerCaseLongPath value
  type: REG_SZ
  encoding: utf-16le (lowercased)
  references-data:
  - concept: ExecutablePath
    role: ranProcess
- name: name
  kind: identifier
  location: Name value
  type: REG_SZ
  encoding: utf-16le
  note: filename component
- name: original-file-name
  kind: identifier
  location: OriginalFileName value
  type: REG_SZ
  encoding: utf-16le
  note: PE-declared original name — mismatches with `Name` are suspicious (renamed binaries)
- name: publisher
  kind: identifier
  location: Publisher value
  type: REG_SZ
- name: product-name
  kind: identifier
  location: ProductName value
  type: REG_SZ
- name: product-version
  kind: identifier
  location: ProductVersion value
  type: REG_SZ
- name: bin-file-version
  kind: identifier
  location: BinFileVersion value
  type: REG_SZ
- name: size
  kind: counter
  location: Size value
  type: REG_QWORD
  encoding: uint64
- name: link-date
  kind: timestamp
  location: LinkDate value
  encoding: UTC string ('MM/DD/YYYY HH:MM:SS')
  clock: PE compile time (external — NOT this system's clock)
  resolution: 1s
  note: from PE header — when the executable was compiled by its author, NOT when it ran here
- name: is-pe-file
  kind: flags
  location: IsPeFile value
  type: REG_DWORD
- name: is-os-component
  kind: flags
  location: IsOsComponent value
  type: REG_DWORD
  note: useful baseline — filters out OS binaries during triage
- name: usn
  kind: counter
  location: Usn value
  type: REG_QWORD
  note: USN Journal number at time of Amcache entry creation
- name: binary-type
  kind: enum
  location: BinaryType value
  type: REG_SZ
  note: '''pe32_i386'' / ''pe32plus_amd64'' / ''pe_arm64'' etc.'
- name: language
  kind: enum
  location: Language value
  type: REG_DWORD
- name: long-path-hash
  kind: hash
  location: <PathHash> portion of subkey name
  encoding: hex
  note: hash of the full path — distinguishes same-hash executables at different paths
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: "CRITICAL (Lagny/ANSSI 2019): on Win10 1709+ InventoryApplicationFile layout, subkey LastWriteTime = last run of compattelrunner.exe (Microsoft Compatibility Appraiser scheduled task), NOT last execution of the binary. The legacy Root\\File\\{VolumeGUID}\\<FileID> layout (pre-October 2017 Amcache DLLs) used LastWriteTime to approximate first-execution — those semantics do not apply to the current layout."
observations:
- proposition: EXECUTED
  ceiling: C3
  note: 'Amcache records programs that WERE executed on the system (historically

    contested — some early research argued entries were made on enumeration,

    not execution; modern consensus tilts toward execution-triggered for

    InventoryApplicationFile on Win10+, with some noise).

    '
  qualifier-map:
    process.image-path: field:lowercase-long-path
    process.image-hash: field:file-id
    process.product-name: field:product-name
    process.link-date: field:link-date
    time.start: field:key-last-write
  preconditions:
  - Amcache.hve available (not wiped; not reset by recent Windows feature upgrade)
  - Transaction logs replayed
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  known-cleaners:
  - tool: CCleaner
    typically-removes: partial
  - tool: manual delete of Amcache.hve
    typically-removes: full
    note: Windows will recreate — but recreation timestamp tells on the cleaner
  - tool: windows feature upgrade
    typically-removes: partial
    note: major feature upgrades can reset Amcache — not malicious but a forensic gap
provenance:
  - lagny-2019-anssi-analysis-amcache
  - zimmerman-amcacheparser-tool-docs
  - regripper-plugins
  - synacktiv-2023-pca-parsing-and-cross-comparis
  - carvey-2022-windows-forensic-analysis-tool
  - artefacts-help-repo
---

# Amcache

## Forensic value
The richest single-artifact execution record on modern Windows. One Amcache entry per executed (or inventoried) PE file contains: SHA1 hash, full path, size, PE metadata (publisher, product, original filename, compile date, architecture), and first-seen timestamp. No other single Windows artifact bundles hash + path + metadata + timestamp into one record.

Critical for malware triage: `OriginalFileName` ≠ `Name` indicates a binary renamed after compilation. Unknown `Publisher` with system-like `Name` is a classic masquerade signal.

## Two concept references
- ExecutablePath (LowerCaseLongPath)
- ExecutableHash (FileId / SHA1)

## Known quirks
- **Execution vs. inventory semantic is historically debated.** Recent Microsoft documentation leans toward execution-triggered, but edge cases (installer-staged files that never ran) have been observed populating Amcache.
- **Feature upgrades reset it.** Win10 1803 → 1809 etc. can drop older entries. Acquire pre-upgrade if targeting older activity.
- **FileId format: `0000` + SHA1.** The leading zeros are the algorithm discriminator; parsers that just take "first 40 chars" miss this.
- **LowerCaseLongPath is lowercased.** Case-sensitive filesystems or case-preservation questions require cross-reference to $MFT.
- **LinkDate is NOT "when this ran."** It's the PE compile time written by the linker — evidence of *when the binary was built*, a signal of its provenance but not its execution.

## Practice hint
Parse a live Amcache.hve with RegRipper or Eric Zimmerman's AmcacheParser. Export to CSV. Sort by key-last-write descending — the top entries are what was recently executed. Compare against Prefetch and BAM for corroboration.
