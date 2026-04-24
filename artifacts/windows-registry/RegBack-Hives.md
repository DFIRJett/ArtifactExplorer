---
name: RegBack-Hives
title-description: "Registry hive backups (C:\\Windows\\System32\\config\\RegBack) — offline-recoverable prior SAM/SOFTWARE/SYSTEM/SECURITY state"
aliases:
- RegBack
- registry backup hives
- config\\RegBack
link: persistence
tags:
- backup-recovery
- deleted-key-recovery
- itm:AF
volatility: persistent
interaction-required: user-session
substrate: windows-registry-hive
substrate-instance: RegBack
platform:
  windows:
    min: '7'
    max: '11'
    note: "Historically populated automatically by the RegIdleBackup scheduled task (every ~10 days). On Windows 10 1803 (April 2018 Update) Microsoft disabled the automatic backup — the RegBack directory EXISTS but on stock installs is EMPTY. On upgraded-from-Win7/Win8 systems the directory may STILL contain old backups predating the 1803 change — those represent a time-capsule of the pre-1803 registry state. Explicitly re-enabling auto-backup requires setting EnablePeriodicBackup=1."
  windows-server:
    min: '2008R2'
    max: '2022'
location:
  path: "%SystemRoot%\\System32\\config\\RegBack\\ (SAM, SECURITY, SOFTWARE, SYSTEM, DEFAULT hives copied here)"
  live-registry-control: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\EnablePeriodicBackup (REG_DWORD)"
  addressing: file-path
  note: "Copies of the primary machine hives. When populated, gives offline-analyzable snapshots of SAM / SOFTWARE / SYSTEM / SECURITY / DEFAULT at the time of the last successful backup (typically 7-10 days before current state). Comparing live hives against RegBack recovers keys deleted by an attacker cleanup within the backup window."
fields:
- name: sam-backup
  kind: content
  location: "RegBack\\SAM"
  encoding: registry hive binary
  references-data:
  - concept: RegistryKeyPath
    role: subjectKey
  note: "Prior SAM state. Recovers deleted local accounts, changed password hashes (you can see the account existed before current state), and RID values that have been reused. Offline-comparable to live SAM with Registry Explorer."
- name: security-backup
  kind: content
  location: "RegBack\\SECURITY"
  encoding: registry hive binary
  note: "Prior SECURITY state — holds LSA policy secrets. Includes cached credentials, service-account secrets, machine key. Comparing to live recovers LSA-Secrets entries that an attacker cleared."
- name: software-backup
  kind: content
  location: "RegBack\\SOFTWARE"
  encoding: registry hive binary
  note: "Prior SOFTWARE state. Recovers deleted Run keys, removed persistence subkeys (Winlogon, Shell extensions, COM hijacks, Defender exclusions, AppCompatFlags Custom shims), and uninstalled-application traces the attacker cleared."
- name: system-backup
  kind: content
  location: "RegBack\\SYSTEM"
  encoding: registry hive binary
  note: "Prior SYSTEM state. Recovers deleted services, registered drivers, Port-Monitor registrations, Time-Providers, TCP/IP parameters, USB device enumerations, MountedDevices entries — all of which are persistence-adjacent and frequently attacker-targeted for cleanup."
- name: default-backup
  kind: content
  location: "RegBack\\DEFAULT"
  encoding: registry hive binary
  note: "Prior DEFAULT hive state. Less commonly forensically pivotal but covers per-default-user profile settings that new accounts inherit."
- name: backup-mtime
  kind: timestamp
  location: each RegBack hive file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime = when the backup was taken. Typical cadence is ~every 10 days on pre-1803 installs (controlled by the RegIdleBackup scheduled task). Post-1803 systems may have a stale mtime from before the upgrade OR have manually-triggered backups from admin / GPO. Compare backup mtime against incident window: if backup is recent ENOUGH to have captured pre-attack state, it's the golden compare-point."
- name: enable-periodic-backup
  kind: flags
  location: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\EnablePeriodicBackup value"
  type: REG_DWORD
  note: "0 or absent = auto-backup disabled (Win10 1803+ default). 1 = auto-backup enabled (pre-1803 default; must be explicitly set on modern Windows). A recent value of 1 on a post-1803 system indicates someone (admin, GPO, or attacker covering their tracks ironically) re-enabled periodic backup."
observations:
- proposition: HAD_CONFIGURATION
  ceiling: C4
  note: 'RegBack is one of the most valuable under-used artifacts on
    Windows because when present it literally contains a snapshot of
    the registry as it was days or weeks before the current state.
    For investigations where the attacker cleared Run keys, removed
    persistence subkeys, altered Defender exclusions, changed audit
    policy, or removed rogue services — RegBack frequently has the
    PRE-CLEANUP state available for offline comparison. Note the
    Win10 1803+ change: stock installs have empty RegBack unless
    explicitly re-enabled, but upgraded-from-Win7 / Win8 systems
    often have backups predating 1803. ALWAYS check this directory
    first — if it has files, they are gold.'
  qualifier-map:
    object.path: "C:\\Windows\\System32\\config\\RegBack\\"
    time.end: field:backup-mtime
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none (hives are not signed)
  known-cleaners:
  - tool: del /f %WINDIR%\System32\config\RegBack\*
    typically-removes: all hive backups
  - tool: "Set EnablePeriodicBackup = 0 (or leave default on 1803+)"
    typically-removes: prospective backups (no new ones written)
  survival-signals:
  - RegBack directory populated with recent mtimes on a host = check for PRE-ATTACK state differences against live hives
  - RegBack empty or missing on a Win10 pre-1803 host = may have been cleared (pre-1803 default is populated)
  - EnablePeriodicBackup=1 on post-1803 system with populated RegBack = deliberate re-enable (unusual; admin or attacker audit trail)
  - mtime on RegBack files significantly pre-dating the suspected intrusion = recoverable pre-attack configuration via offline diff
provenance:
  - ms-the-system-registry-is-no-longer-ba
---

# RegBack hive backups

## Forensic value
`%SystemRoot%\System32\config\RegBack\` is a sibling directory to the live registry config directory (`config\`). When populated, it contains copies of the primary machine hives — SAM, SECURITY, SOFTWARE, SYSTEM, DEFAULT — captured by the `RegIdleBackup` scheduled task at roughly 10-day intervals.

These copies are **registry snapshots from the past** — offline-readable with any registry tool, comparable against the live hives to recover:

- Deleted Run / RunOnce keys
- Cleared Defender Exclusions
- Removed rogue services / drivers
- Altered audit policy
- Disabled EnablePeriodicBackup (ironically)
- Rolled-back LSA-Secrets entries
- Previous SAM account state

## The Windows 10 1803 change
Starting April 2018, Microsoft disabled the automatic RegIdleBackup task by default on new Windows 10 installs. The stated reason was disk usage on systems with size-constrained storage. On post-1803 clean installs, the RegBack directory EXISTS but is EMPTY.

However:
- **Upgraded-from-Win7 / Win8 systems** typically retain pre-1803 backups — those hives are a time-capsule of the pre-upgrade registry state
- **Systems where administrators re-enabled the task** (`EnablePeriodicBackup = 1`) have current backups
- **Some enterprise GPOs re-enable it** for exactly this reason

Always check. If populated, ALWAYS diff.

## Concept reference
- None direct — hive-backup content joins to everything through the live registry.

## Triage
```cmd
dir /a /t:w %SystemRoot%\System32\config\RegBack\
```

Empty → no recovery possible from this source.
Populated → acquire all five hive files and diff against the live equivalents.

## Diff workflow
```cmd
:: Acquire
robocopy C:\Windows\System32\config\RegBack .\evidence\regback\ /MIR
robocopy C:\Windows\System32\config .\evidence\config-live\ SYSTEM SOFTWARE SAM SECURITY DEFAULT
:: Load both sides in Registry Explorer — side-by-side comparison
:: Or use RECmd.exe with -f <hive> --BatchFile <batch> for scripted diff
```

Priority comparison points:
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` / RunOnce (persistence removal)
- `SOFTWARE\Microsoft\Windows Defender\Exclusions\*` (AV-tamper evidence)
- `SYSTEM\CurrentControlSet\Services\` (rogue services removed)
- `SAM\SAM\Domains\Account\Users\` (account state changes)
- `SYSTEM\CurrentControlSet\Control\Lsa\` (security policy changes)

## Cross-reference
- **Task Scheduler** — `\Microsoft\Windows\Registry\RegIdleBackup` is the task that populates RegBack
- **TaskScheduler EVTX** — events 100 / 200 / 201 for RegIdleBackup task run history
- **HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager\EnablePeriodicBackup** — on/off state

## Practice hint
On a clean Windows 11 VM, check `%WINDIR%\System32\config\RegBack\` — the folder exists but is empty. Now run (elevated):
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v EnablePeriodicBackup /t REG_DWORD /d 1 /f
schtasks /run /tn "\Microsoft\Windows\Registry\RegIdleBackup"
```
Check RegBack again — hive files appear with fresh mtimes. This is the mechanism a forensically-aware admin uses to restore the safety net Microsoft removed in 1803.
