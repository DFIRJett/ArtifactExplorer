---
name: WER-Report
title-description: "Windows Error Reporting Report.wer files — crash metadata fingerprinting every faulting binary"
aliases:
- WER report
- Report.wer
- Windows Error Reporting
- crash report
link: application
link-secondary: persistence
tags:
- execution-evidence
- crash-fingerprint
- itm:ME
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: WER-Report
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  path-archive: "%ProgramData%\\Microsoft\\Windows\\WER\\ReportArchive\\<Kind>_<HashName>\\Report.wer"
  path-queue: "%ProgramData%\\Microsoft\\Windows\\WER\\ReportQueue\\<Kind>_<HashName>\\Report.wer"
  path-user: "%LOCALAPPDATA%\\Microsoft\\Windows\\WER\\ReportArchive\\ and \\ReportQueue\\"
  addressing: file-path
  note: "WER writes one Report.wer (UTF-16LE INI-style text file) per faulted process. Naming convention: <Kind>_<HashName> where Kind ∈ {Critical, NonCritical, Update, Upload, Kernel, etc.}. Reports live in ProgramData (machine-wide, includes SYSTEM-process crashes) or in the per-user LocalAppData equivalent. Companion files may include minidump (.dmp), modules lists, and app-compat reports — all grouped under the same <Kind>_<HashName> directory."
fields:
- name: event-name
  kind: label
  location: "Report.wer INI — [EventInfo] EventType key"
  encoding: utf-16le (text line)
  note: "WER event classification — 'APPCRASH', 'BEX', 'BlueScreen', 'LiveKernelEvent 141/177/etc.', 'CbsPackageServicingFailure2'. For malware analysis, APPCRASH (native app crash) and BEX (buffer overflow exception) reports are the highest-yield — they fingerprint an execution that failed."
- name: app-name
  kind: path
  location: "Report.wer INI — [Signature] Parameter0 (AppName) key"
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: "Executable name (without path) that crashed. For malware that caused legitimate apps to crash (DLL injection gone wrong, shellcode overrun), AppName points at the VICTIM — the injected host process. The ATTACKER binary typically surfaces in ModulePath."
- name: app-path
  kind: path
  location: "Report.wer INI — [AppPath] key or Parameter1 (AppVer) + path-reconstructable context"
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: "Full path of the crashing executable. Joins with Amcache / Prefetch / Security-4688. CRITICAL: WER records path EVEN for binaries that were later deleted or renamed — so Report.wer is often the only on-disk evidence that a now-missing attacker binary ran."
- name: module-path
  kind: path
  location: "Report.wer INI — [Signature] Parameter4 (ModName) + Parameter5 path"
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Module (DLL) that caused the fault. For injection-failure crashes, ModulePath IS the attacker DLL. For exploit attempts that crashed the target, ModulePath may point at the vulnerable legitimate DLL that was called incorrectly."
- name: app-version
  kind: label
  location: "Report.wer INI — Parameter1 (AppVer) / Parameter2 (AppStamp)"
  encoding: utf-16le
  note: "File version and PE timestamp of the crashing binary. Useful for correlating against known-malicious IOCs (file-version strings, specific builds) and for cross-referencing the binary's compile time against intrusion timeline."
- name: exception-code
  kind: flags
  location: "Report.wer INI — Parameter6 (ExceptionCode) / Parameter7 (ExceptionOffset)"
  encoding: utf-16le (hex string)
  note: "0xC0000005 = access violation (most common). 0xE0434352 / 0xE0434f4D = .NET exception. 0xC00000FD = stack overflow. Specific codes distinguish native crashes vs. managed-runtime crashes vs. OS-lib errors, narrowing analysis focus."
- name: report-time
  kind: timestamp
  location: "Report.wer INI — EventTime (FILETIME integer) or file $SI mtime"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "Embedded EventTime is the moment the fault occurred. File mtime is moments later (when WER finished writing). Both should align. A significant delta or a rewritten Report.wer mtime = tampering."
- name: user-sid
  kind: identifier
  location: "Report.wer INI — [AppSessionGuid] / OSName / user-info lines"
  encoding: utf-16le
  note: "For per-user reports (LocalAppData path), the SID is implicit from the containing directory. For ProgramData reports, the user-SID of the faulting process may be recorded in session metadata. Pair with Security-4624 to attribute the crash to a specific logon session."
- name: companion-dmp
  kind: content
  location: "<Kind>_<HashName>\\*.dmp next to Report.wer"
  encoding: minidump (MDMP magic 'MDMP')
  note: "Minidump of the crash. When present, this is the FULL process-memory snapshot at fault time — carveable for strings, credentials, decrypted payloads. Much more than Report.wer metadata alone. Acquire the whole <Kind>_<HashName> directory, not just Report.wer."
observations:
- proposition: RAN_PROCESS
  ceiling: C4
  note: 'WER Report.wer files are one of the most under-appreciated
    execution-evidence artifacts on Windows. Every native process
    crash produces a Report.wer; every buffer-overflow exception
    produces one; every .NET unhandled exception produces one.
    Because WER files persist in ReportArchive\\ indefinitely by
    default (no rollover policy) and because each Report.wer
    captures AppPath and ModulePath — even for binaries later
    deleted — this artifact provides surviving execution evidence
    for malware that was cleaned up. For investigations where
    Amcache is tampered / Prefetch is disabled / Security-4688 is
    rolled, WER is often the last witness.'
  qualifier-map:
    object.path: field:app-path
    setting.dll: field:module-path
    time.start: field:report-time
    actor.user: field:user-sid
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: none (plain text INI)
  known-cleaners:
  - tool: "Settings → Privacy → Feedback & diagnostics → Delete diagnostic data"
    typically-removes: per-user WER content (machine-wide ProgramData reports require admin)
  - tool: "Disable-WindowsErrorReporting PowerShell cmdlet (admin)"
    typically-removes: prospective reporting (prior reports remain until manually cleared)
  - tool: "del /s %ProgramData%\\Microsoft\\Windows\\WER\\*"
    typically-removes: all reports — leaves parent directory but empty (itself a signal on a host with any crash history)
  survival-signals:
  - Report.wer entries referencing an AppPath that no longer exists on disk = deleted binary with surviving execution record
  - Repeated Report.wer for a non-Microsoft binary at inconsistent paths = attacker trying multiple injection points
  - ReportArchive directory suspiciously empty on a long-lived Windows system = deliberate wipe
  - Report.wer with EventName='BEX' + ModulePath pointing to a non-Microsoft DLL = likely exploit attempt (buffer-overflow exception)
provenance:
  - ms-windows-error-reporting-architectur
  - mitre-t1497
---

# Windows Error Reporting — Report.wer

## Forensic value
Every native-code process crash on modern Windows produces a `Report.wer` file — a plain-text INI-style record written by the Windows Error Reporting service. Reports live in two-tier directories:

- **Machine-wide**: `%ProgramData%\Microsoft\Windows\WER\ReportArchive\` and `\ReportQueue\`
- **Per-user**: `%LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive\` and `\ReportQueue\`

Each crash produces a directory named `<Kind>_<HashName>` (e.g., `Critical_malware.exe_abc123def456...`) containing:
- `Report.wer` — the INI-style metadata
- Optional `.dmp` minidump
- Optional module list + app-compat report

## Why WER survives cleanup
- ReportArchive has NO default rollover policy — reports accumulate until explicitly deleted
- Most attacker-cleanup scripts target Amcache / Prefetch / Security event logs but NOT `%ProgramData%\Microsoft\Windows\WER\`
- Report.wer contents include AppPath even for executables that have been deleted since the crash — so WER is the surviving witness

## Fields of highest evidentiary value
- `EventType` (APPCRASH / BEX / BlueScreen / etc.)
- `Parameter0` — AppName (crashing executable)
- `Parameter4` / `Parameter5` — ModName + ModulePath (faulting module — often the attacker DLL)
- `EventTime` — when the fault happened
- `AppPath` line — full disk path of the crashed binary

## Concept references
- ExecutablePath (per AppPath and ModulePath)

## Triage
```powershell
# Enumerate all machine-wide reports
Get-ChildItem "$env:ProgramData\Microsoft\Windows\WER\ReportArchive\" -Directory | ForEach-Object {
    $wer = Join-Path $_.FullName "Report.wer"
    if (Test-Path $wer) {
        $content = Get-Content $wer -Raw
        [PSCustomObject]@{
            Directory = $_.Name
            Created = $_.CreationTime
            AppName = if ($content -match 'AppName=([^\r\n]+)') { $Matches[1] } else { '?' }
            AppPath = if ($content -match 'AppPath=([^\r\n]+)') { $Matches[1] } else { '?' }
            ModulePath = if ($content -match 'ModulePath=([^\r\n]+)') { $Matches[1] } else { '?' }
        }
    }
} | Sort-Object Created -Descending | Format-Table -AutoSize
```

## Parsers
- KAPE has a WER compound target + SQLECmd maps for structured output
- Eric Zimmerman has WERParser (EZ Tools ecosystem)

## Cross-reference
- **Amcache InventoryApplicationFile** — SHA-1 hash of the same AppPath
- **Prefetch** — if the app ran long enough before crash to populate Prefetch
- **Security-4688** — process creation event for the crashed process
- **Application EVTX channel** — event ID 1000 (Application Error) is the logged pair of Report.wer

## Attack-chain example
Malicious DLL injected into Edge. Injection causes Edge to fault (memory-corruption crash). Edge terminates; user reopens Edge. Months later DFIR runs:

- Amcache entry for the injected DLL has been cleaned by an attacker script
- Prefetch shows Edge execution with no loaded-modules hint of the injection
- BUT `ReportArchive\APPCRASH_msedge.exe_...\Report.wer` survives with `ModulePath=C:\Users\user\AppData\Local\Temp\atk.dll` — which still points at an attacker artifact whose file no longer exists

This is the scenario WER is uniquely-positioned to witness.

## Practice hint
On a lab VM: write a C program that deliberately dereferences a null pointer. Compile, run. Immediately after the crash, inspect `%ProgramData%\Microsoft\Windows\WER\ReportArchive\` — your APPCRASH report is there with the full AppPath, ExceptionCode 0xC0000005, and EventTime. Rename / delete the .exe. Parse Report.wer again — the AppPath still points at the now-missing file. That post-deletion survival is the forensic superpower.
