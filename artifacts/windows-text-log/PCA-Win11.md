---
name: PCA-Win11
title-description: "Program Compatibility Assistant (Win11) — plaintext launch-tracking (PcaAppLaunchDic.txt / PcaGeneralDb*.txt)"
aliases:
- Program Compatibility Assistant
- PCA
- PcaAppLaunchDic
- PcaGeneralDb0
link: application
tags:
- execution-evidence
- win11-specific
- plaintext-timestamps
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: PCA-Win11
platform:
  windows:
    min: '11'
    max: '11'
    note: "Introduced with Windows 11 as a partial successor to ShimCache / Amcache for interactive user-launched executables. Does NOT exist on Windows 10 or earlier. Widely adopted as a core Win11 DFIR artifact after Andrew Rathbun and Blanche Lagny published their 2023 analyses."
  windows-server:
    min: 'N/A — client-only feature (not on Server SKUs as of 2024)'
location:
  path: "%SystemRoot%\\appcompat\\pca\\PcaAppLaunchDic.txt and PcaGeneralDb0.txt and PcaGeneralDb1.txt"
  addressing: file-path
  note: "Three sibling plaintext (UTF-16LE with BOM) files under C:\\Windows\\appcompat\\pca\\. PcaAppLaunchDic.txt holds a 'most recent launch per binary path' dictionary. PcaGeneralDb0.txt / PcaGeneralDb1.txt are transactional rotating logs of launches with richer metadata (binary path, timestamp, compatibility-issue flags). All three are machine-wide (not per-user) and maintained by the PcaSvc service."
fields:
- name: executable-path
  kind: path
  location: "PcaAppLaunchDic.txt or PcaGeneralDb*.txt — pipe-delimited field 1"
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: "Full path of the launched executable. One of the few DFIR artifacts on Win11 that preserves INTERACTIVE user launches with a UTF-16LE plaintext timestamp AND survives standard cleanup. ShimCache's timestamps are confusing (last-modified of the binary, not launch time); Amcache has launch data but is ESE-format binary; PCA provides a PLAINTEXT, PARSEABLE, TIMESTAMPED launch log."
- name: launch-time
  kind: timestamp
  location: "Pipe-delimited field 2 (PcaGeneralDb*.txt) or last field (PcaAppLaunchDic.txt)"
  encoding: "yyyy-MM-dd HH:mm:ss (UTC, no timezone offset — verify per system)"
  clock: system
  resolution: 1s
  note: "The actual process-launch time. UNLIKE ShimCache's last-modified-of-binary timestamp, this is WHEN THE USER RAN THE BINARY. Plaintext, trivially parseable, directly usable on a timeline — a rarity among Windows execution-evidence artifacts."
- name: compat-issue-flag
  kind: flags
  location: "PcaGeneralDb*.txt — pipe-delimited compatibility-issue fields"
  encoding: utf-16le text
  note: "PCA tracks whether the OS detected a compatibility issue for each launch. For forensic purposes this is secondary — the value of PCA is the launch record itself, not the compatibility-assistance outcome."
- name: record-version
  kind: label
  location: "PcaGeneralDb*.txt — file header / per-line format version"
  note: "Format has evolved across Win11 feature updates (21H2 → 22H2 → 23H2). Parse with tools aware of the evolution (community parsers include a version-detection step)."
- name: file-mtime
  kind: timestamp
  location: PcaAppLaunchDic.txt / PcaGeneralDb*.txt $SI mtime
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime — updates on every PCA write. The most-recent launch recorded inside the file matches the file-level mtime within a few seconds. Serves as independent check against embedded timestamps."
- name: db-rotation
  kind: flags
  location: "PcaGeneralDb0.txt vs PcaGeneralDb1.txt — which file is 'active'"
  note: "Two-file rotation. The active file grows until a size cap, at which point writes swap to the other. Acquire BOTH files — older launches live in whichever file is currently inactive."
observations:
- proposition: RAN_PROCESS
  ceiling: C4
  note: 'PCA is the single most valuable execution-evidence artifact
    specific to Windows 11. It provides what analysts have wanted
    for years: plaintext, timestamped, launch records keyed on
    binary path. Every binary a user launched interactively is
    recorded — including launches of renamed or relocated
    executables. Because the service runs automatically and writes
    plaintext without per-user scope, sweeping PcaAppLaunchDic +
    PcaGeneralDb0 + PcaGeneralDb1 yields a clean machine-wide
    launch timeline that doesn''t depend on the analyst parsing
    ShimCache timestamps correctly or reconciling Amcache ESE
    schemas across Win11 builds. For any Win11 investigation, PCA
    triage should precede every other execution-evidence check.'
  qualifier-map:
    object.path: field:executable-path
    time.start: field:launch-time
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: none (plaintext, unsigned)
  known-cleaners:
  - tool: "stop PcaSvc + delete pca directory contents"
    typically-removes: all PCA history (service recreates empty files on next start)
  - tool: "Disable PcaSvc via services.msc"
    typically-removes: prospective logging (existing files remain unless separately deleted)
  survival-signals:
  - PcaGeneralDb*.txt entries with binary paths in user-writable directories (%TEMP%, %APPDATA%, Downloads) for non-Microsoft signed binaries = likely attacker tooling launches
  - Launch entries for binaries with timestamps inside incident window that are ABSENT from ShimCache / Amcache = the other artifacts were tampered; PCA caught it
  - Multiple distinct paths for obviously-renamed copies of the same binary = attacker iterating on filename
  - PCA files missing on a Win11 host where PcaSvc is set Automatic start = files were deleted
provenance: [rathbun-2023-program-compatibility-assistan, synacktiv-2023-pca-parsing-and-cross-comparis]
---

# Program Compatibility Assistant (PCA) — Windows 11

## Forensic value
Windows 11 introduced the Program Compatibility Assistant as a machine-wide execution-tracking mechanism that partially replaces ShimCache / Amcache for interactive user launches. Three plaintext files live under `C:\Windows\appcompat\pca\`:

- `PcaAppLaunchDic.txt` — most-recent launch per binary path (dictionary)
- `PcaGeneralDb0.txt` + `PcaGeneralDb1.txt` — rotating transactional launch log

All three are UTF-16LE plaintext with pipe-delimited fields. Timestamps are human-readable. For the first time on Windows, execution evidence is in a format a grep / awk pipeline can consume without a specialized parser.

## Why this is transformative
Pre-Win11 execution-evidence artifacts had problems:
- **ShimCache**: timestamps are "last modified of the binary," not launch time — confusing and routinely misinterpreted
- **Amcache**: binary ESE database, schema varies per Windows build, requires specialized parser
- **Prefetch**: limited history depth (1024 entries on Win10+), not every binary gets a prefetch file
- **Security-4688**: disabled by default, fast log roll

PCA sidesteps all of these. Plaintext. Launch-time timestamps. Preserved across reboots. No ESE knowledge required.

## Concept reference
- ExecutablePath (per launched binary)

## Triage
```powershell
$pcaDir = "$env:SystemRoot\appcompat\pca"
Get-Content "$pcaDir\PcaAppLaunchDic.txt" -Encoding Unicode | Select-Object -First 50
Get-Content "$pcaDir\PcaGeneralDb0.txt" -Encoding Unicode | Select-Object -First 50
Get-Content "$pcaDir\PcaGeneralDb1.txt" -Encoding Unicode | Select-Object -First 50
```

## Format quick-parse
Each line is pipe-delimited. Typical fields (observed in 22H2 / 23H2):

```
<executable-path>|<yyyy-MM-dd HH:mm:ss>|<compat-flags>|<other>
```

Example:
```
C:\Users\alice\Downloads\attacker-payload.exe|2026-04-12 14:33:18|None|...
```

## Cross-reference
- **Amcache InventoryApplicationFile** — same binary path should (usually) appear there too; discrepancy = one source was tampered
- **ShimCache** — post-Win11 the two often coexist; PCA adds the true launch time ShimCache lacks
- **Prefetch** — matching prefetch file gives loaded-modules corroboration
- **Security-4688** — if enabled, live process-creation record for the same launch

## Attack-chain example
Attacker drops `payload.exe` to `C:\Users\<user>\Downloads\`, runs it manually. Later cleans up by:
- Deleting `payload.exe`
- Clearing Prefetch
- Clearing Amcache

But PCA file wasn't cleaned (under-documented). DFIR recovers:
```
C:\Users\<user>\Downloads\payload.exe|2026-04-12 14:33:18|None|...
```

Full path + exact launch time — a cleaner artifact than any of the traditional execution-evidence sources provide.

## Practice hint
On a Windows 11 VM: launch any uncommon binary (e.g., download Sysinternals Process Explorer and run it). Within a minute, inspect `C:\Windows\appcompat\pca\PcaGeneralDb0.txt` — the launch is recorded with full path and launch timestamp. Rename the binary and re-run — the new name appears as a separate entry. That 1:1 launch:line mapping is exactly what you rely on in real Win11 investigations.
