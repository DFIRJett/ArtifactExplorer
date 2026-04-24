---
name: Prefetch
aliases:
- Prefetch file
- .pf
- SuperFetch entry
link: application
tags:
- timestamp-carrying
- tamper-easy
volatility: persistent
interaction-required: none
substrate: windows-prefetch
substrate-instance: Prefetch
substrate-hub: System scope
platform:
  windows:
    min: XP
    max: '11'
  windows-server:
    min: 2008R2
    max: '2022'
    note: often disabled by default on Server SKUs — check EnablePrefetcher
location:
  path: '%WINDIR%\Prefetch\<EXENAME>-<HASH8>.pf'
  addressing: filesystem-path
fields:
- name: version
  kind: enum
  location: decompressed bytes 0-3
  encoding: uint32-le
  note: 17=XP, 23=Vista/7, 26=Win8, 30=Win10, 31=Win11
- name: signature
  kind: identifier
  location: decompressed bytes 4-7
  encoding: FOURCC 'SCCA'
- name: executable-name
  kind: identifier
  location: decompressed offset 0x10, 60 bytes
  encoding: utf-16le (null-terminated, up to 29 chars)
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: short form — the full path is in the filename-strings section; pair them for canonical ExecutablePath
- name: path-hash
  kind: identifier
  location: decompressed offset 0x4C
  encoding: uint32-le
  note: displayed as 8 hex chars in the filename; hashing algorithm varies by Windows version (XP=classical, Win7+=SSDT-style)
- name: run-count
  kind: counter
  location: file-information struct
  encoding: uint32-le
- name: last-run-time
  kind: timestamp
  location: file-information struct — first element of run-times array
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: updated on each execution
- name: last-run-time-minus-1
  kind: timestamp
  location: file-information struct — run-times array [1]
  encoding: filetime-le
  clock: system
  resolution: 100ns
  availability:
    min-windows: '8'
- name: last-run-time-minus-2
  kind: timestamp
  location: file-information struct — run-times array [2]
  encoding: filetime-le
  clock: system
  resolution: 100ns
  availability:
    min-windows: '8'
- name: last-run-time-minus-3
  kind: timestamp
  location: file-information struct — run-times array [3]
  encoding: filetime-le
  clock: system
  resolution: 100ns
  availability:
    min-windows: '8'
- name: last-run-time-minus-4
  kind: timestamp
  location: file-information struct — run-times array [4]
  encoding: filetime-le
  clock: system
  resolution: 100ns
  availability:
    min-windows: '8'
- name: last-run-time-minus-5
  kind: timestamp
  location: file-information struct — run-times array [5]
  encoding: filetime-le
  clock: system
  resolution: 100ns
  availability:
    min-windows: '8'
- name: last-run-time-minus-6
  kind: timestamp
  location: file-information struct — run-times array [6]
  encoding: filetime-le
  clock: system
  resolution: 100ns
  availability:
    min-windows: '8'
- name: last-run-time-minus-7
  kind: timestamp
  location: file-information struct — run-times array [7]
  encoding: filetime-le
  clock: system
  resolution: 100ns
  availability:
    min-windows: '8'
- name: volume-device-path
  kind: path
  location: volumes-information entry — device path
  encoding: utf-16le
  note: typically '\DEVICE\HARDDISKVOLUME<N>' — resolves via MountedDevices to drive letter / volume-GUID
- name: volume-serial-number
  kind: identifier
  location: volumes-information entry — 32-bit serial
  encoding: uint32-le
  references-data:
  - concept: FilesystemVolumeSerial
    role: runtimeSerial
- name: volume-creation-time
  kind: timestamp
  location: volumes-information entry — creation timestamp
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: file-reference-list
  kind: identifier
  location: per-volume file-reference array
  encoding: array of 64-bit MFT segment references
  references-data:
  - concept: MFTEntryReference
    role: referencedFile
  availability:
    min-windows: '8'
  note: on Win8+, each referenced file carries its MFT entry+sequence — direct pivot to the $MFT at the time the prefetch
    was written
- name: loaded-filenames
  kind: path
  location: filename-strings section — UTF-16LE list
  encoding: utf-16le
  note: every file (DLL, config, data) the OS saw loaded during the first 10 seconds of execution — useful for DLL-sideload
    detection
observations:
- proposition: EXECUTED
  ceiling: C3
  note: 'Prefetch proves the executable ran. On Win10+, the 8-run-time array

    gives an approximate ''when'' with 100ns precision. RunCount totals all

    executions since file creation, not just those within the 8-window.

    '
  qualifier-map:
    process.image: field:executable-name
    process.full-path: reconstructed from volume-device-path + loaded-filenames search
    process.source-volume: field:volume-serial-number
    frequency.count: field:run-count
    frequency.last: field:last-run-time
    time.start: field:last-run-time
    time.end: field:last-run-time
  preconditions:
  - EnablePrefetcher not set to 0 (Prefetch disabled)
  - The executable's .pf file wasn't selectively deleted
  - MAM decompression applied correctly (Win10+ parser required)
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: none
  known-cleaners:
  - tool: CCleaner
    typically-removes: full
    note: '''Windows > Prefetch Data'' checkbox deletes the directory contents'
  - tool: manual delete
    typically-removes: surgical
  - tool: disable via EnablePrefetcher=0
    typically-removes: prospective
    note: doesn't remove existing files but stops new ones from being created
  survival-signals:
  - Prefetch directory present but empty + EnablePrefetcher=1 = recent wholesale cleanup. Expected .pf count for an active
    workstation is dozens-to-hundreds.
  - Absence of .pf for known-run executables (cross-check UserAssist/BAM) = selective deletion
  - MFT entries referenced in an existing .pf file's file-reference-list pointing to deleted MFT records = file loaded during
    execution was later deleted
provenance:
  - carvey-2022-windows-forensic-analysis-tool
  - matrix-dt027-windows-prefetch
  - zimmerman-pecmd-tool-docs
  - 13cubed-2020-prefetch-deep-dive
  - picasso-2015-zenaforensics-win10-prefetch
  - forensicartifacts-repo
  - kape-files-repo
---

# Windows Prefetch File

## Forensic value
The canonical "program executed" artifact on Windows. Each run of an executable causes Windows to create or update a `.pf` file capturing path, run count, last run times (8 deep on Win10+), and the full list of files loaded during the first 10 seconds of execution.

Uniquely powerful for three claims:
1. **What ran, and when** — 8 most recent run timestamps with 100ns precision.
2. **What the program loaded** — DLL side-load and config-file references.
3. **Which volume the exe came from** — device path + FS serial, pivoting via MountedDevices to USBSTOR for removable-media execution.

## Three concept references
- FilesystemVolumeSerial — from the volumes-information section
- MFTEntryReference — Win8+ per-file references in the metrics table
- ExecutablePath — from the executable-name + path-hash + loaded-filenames reconstruction

## Known quirks
- **MAM compression on Win10 1803+.** Old parsers misread the file header entirely. Use PECmd or libscca.
- **Path hash isn't cryptographic.** Collisions are rare but possible — particularly for long paths that share prefixes. Two .pf files for `foo.exe` with different hashes = different full paths.
- **Executable-name field is 30-char truncated.** Long executable names are truncated in the header but preserved in the filename-strings section. Use the strings section for canonical name.
- **Run-count totals all runs ever** (since file creation), not just the last 8.
- **Prefetch can be disabled.** On servers, SSD-detecting installers, or hardened configurations, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher = 0` disables it. Absence of Prefetch where it should exist is itself a forensic signal.
- **File-reference-list (MFT refs) is Win8+.** Pre-Win8 prefetch has filename-strings but no MFT entry references.

## Anti-forensic caveats
Prefetch is one of the most-targeted artifacts for cleanup. CCleaner's "Windows > Prefetch Data" checkbox deletes the lot; attackers run `del C:\Windows\Prefetch\*.pf /Q` or PowerShell equivalents. Because Prefetch is kernel-populated at execution time, the cleanup race is one-sided — the attacker can't prevent creation, only cleanup after.

Detection cues:
- Empty or near-empty Prefetch directory on a clearly-used workstation
- .pf count drastically lower than expected (dozens minimum on an active machine)
- Recent $MFT entries showing bulk-delete pattern in the Prefetch directory

## Practice hint
- Run a known executable from C:\ and from a USB drive. Identify the two .pf files with the same executable name but different path hashes. Decode both volumes-information sections.
- Delete a .pf file. Run the executable again. Observe that a new .pf file gets created but run-count resets.
- On Win10+, use PECmd to decode MAM compression. Compare output to a raw-binary viewer on a v30 file — the raw-viewer approach fails.
