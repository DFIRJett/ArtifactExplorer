---
name: ScheduledTask-Job-Legacy
title-description: "Legacy Task Scheduler .job files (pre-Vista binary format) — surviving on upgraded hosts"
aliases:
- .job files
- legacy scheduled task
- pre-Vista task format
link: persistence
tags:
- legacy-system
- upgrade-residue
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: ScheduledTask-Job-Legacy
platform:
  windows:
    min: NT5.0
    max: '11'
    note: "Native pre-Vista. Replaced by XML-based Task Scheduler 2.0 starting Vista. However .job files may STILL appear on Windows 10/11 hosts that were upgraded in-place from Windows 7 / XP / 2003 — the old Tasks directory sometimes survives upgrade without cleanup."
  windows-server:
    min: '2000'
    max: '2022'
location:
  path: "%WINDIR%\\Tasks\\<task-name>.job"
  schedlgu-log: "%WINDIR%\\Tasks\\SchedLgU.txt (legacy text log for task execution)"
  companion: "registry at SYSTEM\\CurrentControlSet\\Services\\Schedule\\TaskCache for modern format (separate artifact)"
  addressing: file-path
  note: "Binary .job files stored under %WINDIR%\\Tasks\\. Format: fixed-size header (produced by Task Scheduler 1.0 API) followed by variable-size trigger / action data. Each file = one scheduled task. Sibling SchedLgU.txt captures task-invocation log entries in plain text. On modern Windows, legacy .job files are essentially historical residue — the running Task Scheduler service consults registry TaskCache + System32\\Tasks XML for current scheduling. But an upgraded-from-Win7 host may STILL have long-forgotten .job files that have never been cleaned up, representing legacy persistence that's invisible to modern enumeration tools (schtasks, Get-ScheduledTask) which focus on the 2.0 format."
fields:
- name: job-executable
  kind: path
  location: ".job header — executable path field"
  encoding: utf-16le (null-terminated)
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: "Command the task runs. For surviving-from-legacy .job files, the path may reference long-gone executables (software uninstalled years ago) — but occasionally surfaces as attacker-placed-long-ago-and-forgotten persistence. Double-check any .job file referencing an extant executable against current scheduled-task enumeration tools: if a .job file references a running binary that DOESN'T appear in schtasks / Get-ScheduledTask output, the legacy task may be dormant OR (rare) actively used."
- name: job-arguments
  kind: content
  location: ".job header — arguments field"
  encoding: utf-16le
  note: "Command-line arguments for the executable. Scripted attacker payloads (cmd /c ..., powershell -enc ...) appear here."
- name: trigger-data
  kind: content
  location: ".job body — trigger records (DAILY / WEEKLY / ATLOGON / ATSTARTUP / ONCE)"
  encoding: binary trigger structures
  note: "When the task fires. Legacy format supports the standard trigger types (daily, weekly, at logon, at startup, run once, event-based). Attacker triggers are typically ONSTART or ATLOGON for persistence."
- name: job-runas-user
  kind: identifier
  location: ".job header — user-account SID/name"
  encoding: utf-16le (NT4-format DOMAIN\\user or SID string)
  note: "Account the task runs as. SYSTEM account tasks = privileged persistence. User-scoped tasks = per-user persistence."
- name: file-mtime
  kind: timestamp
  location: .job file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime = task creation / modification time. For upgrade-survivor .job files this often preserves very old dates (pre-upgrade), making them time-capsule evidence."
- name: schedlgu-entry
  kind: timestamp
  location: "%WINDIR%\\Tasks\\SchedLgU.txt (legacy Task Scheduler service log)"
  note: "Plain-text legacy log. Each entry: 'Task Scheduler Service.' + '<timestamp>: Task <name> started/finished'. On Win10/11 this file may EXIST from pre-upgrade activity but new entries are rarely written (modern Task Scheduler logs to EVTX channel instead). The surviving old content is execution-history evidence."
observations:
- proposition: PERSISTED
  ceiling: C3
  note: 'Legacy .job files are a rare but non-trivial artifact on modern
    Windows hosts. The file FORMAT itself is pre-Vista, yet the
    files persist on upgraded-from-Win7 / WinXP systems without
    being migrated or cleaned. Modern Task Scheduler tools
    (schtasks, Get-ScheduledTask) primarily show 2.0-format tasks
    and may not surface .job files — leaving them invisible to
    routine persistence sweeps. For cold-case investigations and
    long-lived upgrade chains, always check %WINDIR%\\Tasks for
    any .job files present. The format is old but a surviving .job
    CAN still be active if the Task Scheduler service happens to
    process it, and even when inactive, the file preserves
    historical persistence intent.'
  qualifier-map:
    setting.file: "%WINDIR%\\Tasks\\<task>.job"
    setting.command: field:job-executable
    time.start: field:file-mtime
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none (no signing)
  known-cleaners:
  - tool: "del %WINDIR%\\Tasks\\<name>.job"
    typically-removes: the task definition (modern Task Scheduler schtasks /Delete does NOT always touch .job files)
  survival-signals:
  - .job files present in %WINDIR%\Tasks on Windows 10/11 = legacy-format persistence worth triaging
  - .job referencing an executable that still exists on disk = possibly-active legacy task
  - SchedLgU.txt with entries dated pre-upgrade = preserved execution-history from the prior OS install
provenance: [ms-task-scheduler-1-0-legacy-format-re, libyal-libfwnt-job-file-format-libwrc-reverse, mitre-t1053-005]
---

# Legacy Task Scheduler .job Files

## Forensic value
Pre-Vista Task Scheduler persisted tasks as binary `.job` files under `%WINDIR%\Tasks\`. One file per task, each a self-contained binary header + trigger / action records.

Vista introduced Task Scheduler 2.0 (XML format at `%WINDIR%\System32\Tasks\` + registry TaskCache). `.job` files are technically legacy — but they **persist through in-place upgrades**. An upgraded-from-Win7 or upgraded-from-XP host may STILL have `.job` files from the pre-upgrade OS decade-old persistence that current enumeration tools don't surface.

## Why current tools miss these
- `schtasks.exe` primarily lists modern (XML-format) tasks
- `Get-ScheduledTask` PowerShell cmdlet — same
- Autoruns — checks modern TaskCache

Legacy .job files appear to routine sweeps only if the analyst explicitly enumerates `%WINDIR%\Tasks\*.job`.

## Companion: SchedLgU.txt
`%WINDIR%\Tasks\SchedLgU.txt` is the legacy plain-text log. Even on Win10/11 this file may exist (from pre-upgrade activity) with preserved execution-history entries. Modern Task Scheduler writes to EVTX instead, but the old text log is archival evidence.

## Concept reference
- ExecutablePath (via the .job executable-path field)

## Triage
```cmd
dir /a /t:w %WINDIR%\Tasks\*.job
type %WINDIR%\Tasks\SchedLgU.txt | more
```

## Parsing
Binary format — use libyal / libfwnt / specialized .job parsers. Structure:
- Fixed header (product version, UUID, app name, parameters, working dir, author, priority)
- Variable-length trigger records
- Task-specific flags

## Cross-reference
- **%WINDIR%\System32\Tasks\** — modern XML-format tasks (different directory, different format)
- **TaskCache registry** — modern registry side
- **Application EVTX / Microsoft-Windows-TaskScheduler/Operational** — modern tasks' execution events
- **Amcache / Prefetch** — execution evidence of binaries named in .job files

## Attack-chain recovery example
Host was Windows 7 in 2016, attacker dropped a .job file for persistence. Host was in-place-upgraded to Windows 10 in 2018. DFIR analyst in 2024 runs `schtasks /query` — doesn't see the legacy task. Runs `Get-ScheduledTask` — doesn't see it. But `dir %WINDIR%\Tasks\*.job` reveals the old persistence file, preserved through the upgrade.

## Practice hint
Obtain a Windows 7 VM image. Create a scheduled task via `schtasks /create`. Inspect `%WINDIR%\Tasks\<task>.job`. In-place upgrade the VM to Windows 10 via upgrade assistant. Check again — the .job file survives. This upgrade-residue is the artifact you're hunting for on long-lived enterprise machines.
