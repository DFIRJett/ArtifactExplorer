---
name: Registry-Transaction-Logs
title-description: "Registry .LOG1 / .LOG2 transaction logs — unflushed dirty-page recovery (replay to restore deleted keys)"
aliases:
- registry transaction logs
- .LOG1 / .LOG2 files
- hive dirty pages
- registry replay logs
link: persistence
tags:
- deleted-key-recovery
- backup-recovery
- itm:AF
volatility: persistent
interaction-required: user-session
substrate: windows-registry-hive
substrate-instance: Registry-Transaction-Logs
platform:
  windows:
    min: Vista
    max: '11'
    note: "Format changed across Windows versions. Pre-Vista used .LOG files (different format). Vista through Win8 used .LOG. Win8.1+ uses .LOG1 + .LOG2 pair per hive (redundant transactional logs). Always acquire whichever variant is present."
  windows-server:
    min: '2008'
    max: '2022'
location:
  path-machine-hives: "%SystemRoot%\\System32\\config\\SYSTEM.LOG1, .LOG2; SOFTWARE.LOG1, .LOG2; SAM.LOG1, .LOG2; SECURITY.LOG1, .LOG2; DEFAULT.LOG1, .LOG2"
  path-user-hives: "%USERPROFILE%\\NTUSER.DAT.LOG1, .LOG2; %LOCALAPPDATA%\\Microsoft\\Windows\\UsrClass.dat.LOG1, .LOG2"
  path-amcache: "%WINDIR%\\AppCompat\\Programs\\Amcache.hve.LOG1, .LOG2"
  path-bcd: "<BCD path>.LOG1, .LOG2"
  addressing: file-path
  note: "Every registry hive file has a companion transaction-log pair (.LOG1 + .LOG2 on Win8.1+). The logs hold dirty hive-page updates that have NOT yet been flushed into the primary hive file. When Windows shuts down cleanly, the logs are replayed into the hive and then (typically) reset. When Windows crashes / power-cycles / is imaged LIVE, unflushed writes remain ONLY in the logs. Offline parse of hive-without-logs misses those writes. Offline parse of hive-WITH-logs (via rla.exe replay) produces the full current state."
fields:
- name: dirty-pages
  kind: content
  location: "<hive>.LOG1 / <hive>.LOG2 — dirty page blocks"
  encoding: "registry-transaction-log format (HvLE blocks, sequence-numbered)"
  note: "Page-aligned writes that modify the primary hive but have not been flushed. Each dirty page records: target hive block, sequence number, and the new page contents. Replay applies them in sequence to reconstruct the latest state."
- name: sequence-number
  kind: counter
  location: "log header — sequence counter"
  encoding: uint32
  note: "Log writes are sequence-numbered for idempotent replay. The replay tool processes log entries in ascending order and stops at the last valid entry. Corruption / tampering often manifests as gaps or out-of-order sequences — the replay tool reports these."
- name: primary-hive-divergence
  kind: content
  location: "comparison between live hive file and replayed hive-plus-logs"
  encoding: derived
  note: "The whole POINT of this artifact — what lives in the logs that is NOT yet in the hive file. For an attacker who committed a cleanup then immediately imaged the system (or whose cleanup happened right before a crash), the hive file shows CLEAN state but the logs contain the PRE-CLEANUP dirty pages. Replay surfaces those."
- name: log-file-mtime
  kind: timestamp
  location: <hive>.LOGx file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime — when the last unflushed write occurred. For the SYSTEM / SOFTWARE hives this is essentially always very recent on a live system. On acquired images, log mtime bracketed with hive mtime tells you how much unflushed state was pending."
- name: log-file-size
  kind: counter
  location: <hive>.LOGx file size
  encoding: uint32 / uint64
  note: "Log files grow to accommodate unflushed writes, then are reset (truncated or zero-filled) on clean flush. A large log file indicates substantial unflushed state — expect meaningful recovery on replay. Tiny log file indicates hive is nearly-flushed (typical steady state on a gracefully-running system)."
- name: replay-validity
  kind: flags
  location: derived from replay attempt
  note: "The replay tool (rla.exe / Registry Explorer / libhivex) reports whether the log-to-hive replay was 'clean' (all sequence numbers present, all checksums valid) or 'partial' (some entries invalid / tampered). Partial replay still surfaces the valid entries and is still forensically valuable — but note the anomaly."
observations:
- proposition: HAD_CONFIGURATION
  ceiling: C4
  note: 'Registry transaction logs are the most under-appreciated
    registry artifact on Windows. The standard mistake is: acquire
    a hive file, parse offline, conclude "this is the state." Wrong.
    Without replaying the LOG1 + LOG2 companions, parsing sees a
    potentially-stale snapshot missing every write since the last
    flush. For a live-imaged host (imaged without clean shutdown),
    the delta between hive-only-parse and hive+log-replay can be
    substantial — minutes to hours of registry activity sits in the
    logs. For attacker investigations specifically, cleanup
    operations often leave the cleared-key-state in the hive but
    the DELETE-OPERATION RECORD in the logs — recovering the "before"
    state of deleted keys. ALWAYS acquire the .LOG1 and .LOG2
    companions alongside every hive file.'
  qualifier-map:
    setting.file: "<hive>.LOG1 / <hive>.LOG2"
    time.end: field:log-file-mtime
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: per-block checksums; sequence-numbered replay
  known-cleaners:
  - tool: "net stop (then delete hive.LOGx)"
    typically-removes: unflushed writes — destroys pre-shutdown state (very visible; leaves hive LastWrite evidence and possibly Registry-Operational EVTX events)
  - tool: "reg flush (forcing flush before imaging)"
    typically-removes: log content by flushing to hive — less destructive but changes the forensic picture
  survival-signals:
  - .LOG1 or .LOG2 files present on an acquired image = REPLAY to recover unflushed state BEFORE parsing hive
  - Logs missing while hive is present = explicit cleanup or post-flush clean state; note the anomaly
  - Large log file size relative to typical steady state = significant pending state worth replaying
  - Live-image acquisition (imaged without clean shutdown) = logs are critical; offline parse without replay is incomplete
provenance:
  - online-2021-registry-hive-file-format-prim
  - suhanov-2019-windows-registry-forensics-par
---

# Registry Transaction Logs (.LOG1 / .LOG2)

## Forensic value
Every registry hive file on modern Windows has a companion **transaction log pair** (`.LOG1` + `.LOG2` on Windows 8.1+):

- `SYSTEM` + `SYSTEM.LOG1` + `SYSTEM.LOG2`
- `SOFTWARE` + `SOFTWARE.LOG1` + `SOFTWARE.LOG2`
- (and so on for SAM, SECURITY, DEFAULT, NTUSER.DAT, UsrClass.dat, Amcache.hve, BCD)

The logs hold **unflushed dirty pages** — writes made to the hive in memory that have not yet been committed to the primary file. Windows flushes these to the hive at clean shutdown; between flushes, the logs are the authoritative record of the latest state.

## The standard DFIR mistake
Analyst acquires a hive. Analyst loads it in Registry Explorer. Analyst concludes "this is the hive state at acquisition time." WRONG.

Without replaying `.LOG1` / `.LOG2`, the analyst sees a stale snapshot — potentially MINUTES or HOURS of registry activity that was unflushed at acquisition time is missing. On live-imaged hosts (imaged without clean shutdown), this gap is routine.

## Deleted-key recovery
When an attacker deletes a registry value / key:
- The hive primary file's current state = key removed
- The transaction log records the DELETE operation
- Replay with rla.exe reconstructs the hive WITH the key still present (the pre-delete state is in the log)

The log-replay window is small (seconds to minutes — the log flushes continuously) but for attacker-cleanup-followed-by-image cases, it is often the ONLY source of pre-cleanup evidence.

## Concept reference
- None direct — hive-content artifact.

## Acquisition
**ALWAYS acquire the .LOG1 and .LOG2 files alongside every hive**. Standard hive-only acquisition is incomplete.

```cmd
:: Machine hives — acquire the whole config\\ directory
robocopy C:\Windows\System32\config .\evidence\config\ SYSTEM SAM SECURITY SOFTWARE DEFAULT SYSTEM.LOG1 SYSTEM.LOG2 SAM.LOG1 SAM.LOG2 SECURITY.LOG1 SECURITY.LOG2 SOFTWARE.LOG1 SOFTWARE.LOG2 DEFAULT.LOG1 DEFAULT.LOG2

:: Per-user hives
copy "%USERPROFILE%\NTUSER.DAT*" .\evidence\
copy "%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat*" .\evidence\

:: Amcache
copy "%WINDIR%\AppCompat\Programs\Amcache.hve*" .\evidence\
```

## Replay workflow
```cmd
:: Eric Zimmerman's rla.exe
rla.exe --f .\evidence\config\SYSTEM --out .\evidence\config\SYSTEM-replayed --ca y

:: The --out is a new hive file that IS the primary + log replay result
:: Load THAT in Registry Explorer instead of the raw SYSTEM hive
```

## Cross-reference
- Hive primary file (main artifact parse target)
- **RegBack** — hive backups at an earlier time (different snapshot with different properties)
- **Microsoft-Windows-Registry/Operational** EVTX channel — registry-change tracking when Registry-Operational logging is enabled

## Practice hint
On a lab VM: make some registry changes (add Run key, set Defender-Exclusions path). Do NOT reboot. Acquire both SOFTWARE and SOFTWARE.LOG1 / .LOG2. In Registry Explorer, first load SOFTWARE alone — your changes may or may not appear (flush timing). Now use rla.exe to replay logs into SOFTWARE → load the replayed file → your changes DEFINITELY appear. That difference is the value of the log files.
