---
name: Run-Keys
aliases:
- Run
- RunOnce
- startup registry keys
- autostart
link: persistence
tags:
- tamper-easy
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: NT4
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: NTUSER.DAT
  path: Software\Microsoft\Windows\CurrentVersion\Run (and \RunOnce)
  addressing: hive+key-path
  also-present-in:
    machine-scope: SOFTWARE\Microsoft\Windows\CurrentVersion\Run  and  RunOnce (HKLM)
    wow6432: SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run  (32-bit on 64-bit systems)
fields:
- name: entry-name
  kind: identifier
  location: value name under Run or RunOnce
  encoding: utf-16le
  note: descriptive label; chosen by whatever registered the autostart — often product name
- name: command-line
  kind: path
  location: value data
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: executable path + arguments; may contain environment variables (%ProgramFiles%\...). Microsoft Win32 documentation caps command-line length at 260 characters — attempts to set longer values may truncate or fail silently depending on the writing API.
- name: value-name-prefix
  kind: identifier
  location: first character of RunOnce value name (HKLM\RunOnce + HKCU\RunOnce only)
  encoding: ascii
  note: RunOnce-specific value-name conventions (per MS Win32 spec). `!` prefix defers value deletion until AFTER successful execution (classic retry-on-failure); `*` prefix forces execution even in Safe Mode (used by setup-repair paths and by some anti-forensic-evasion tools). Presence of `*` on an unfamiliar entry is a strong persistence-investigation signal.
- name: user-scope-sid
  kind: identifier
  location: derived from NTUSER.DAT owner (HKCU variant)
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: profileOwner
  note: only for HKCU; HKLM variant is machine-scope with no user binding
- name: key-last-write
  kind: timestamp
  location: Run or RunOnce key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: updated on value add / modify / delete
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'Classic autorun persistence. Values under Run execute on every logon

    (HKCU) or boot (HKLM); RunOnce values execute once then delete.

    Every malware authored since the 1990s has touched these keys at some

    point — still the #1 persistence mechanism in the wild.


    Scope nuance: HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

    only fires when an Administrator logs on after reboot — NOT on every

    boot. If a low-privilege user logs on first, HKLM-RunOnce entries stay

    queued until an admin session begins. This makes HKLM-RunOnce a less

    reliable persistence target than HKLM-Run for attackers.


    Execution ordering: per MS Win32 docs, ordering among same-scope Run

    entries is INDETERMINATE — not alphabetical, not value-creation-order,

    not registry-key-enumeration-order. Don''t infer sequence from value

    position. Execution is also NOT prompt-guaranteed; Windows may delay

    Run-key execution for UX reasons (e.g., deferring until desktop idle).

    '
  qualifier-map:
    setting.registry-path: Run\<entry-name> or RunOnce\<entry-name>
    setting.executable: field:command-line
    actor.user: field:user-scope-sid
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  known-cleaners:
  - tool: Autoruns (Sysinternals)
    typically-removes: surgical
    note: designed for forensic inspection but used by attackers to clean their tracks
  - tool: CCleaner
    typically-removes: false
  - tool: manual reg-delete
    typically-removes: surgical
  survival-signals:
  - RunOnce entries often persist post-execution if the executing program failed — RunOnce is supposed to self-delete, so
    a stale RunOnce value is suspicious
  - Run-key entry referencing a non-existent executable = dangling persistence; the binary was deleted but the persistence
    remained
  - "Rename-rename-back evasion (Raspberry Robin pattern, Carvey 2022 / Avast 2022): attacker sets RunOnce value X → reboots → X executes and self-deletes → attacker renames Run value Y back to X, restoring the persistence config while leaving no RunOnce footprint. Registry transaction log (SYSTEM\\*.LOG1/LOG2) retains the rename sequence even when the current hive shows only the final state — Triforce-style forensic recovery via transaction-log replay exposes the swap."
cross-references:
  attack-technique-bundle:
  - 'ATT&CK T1547.001 groups Registry Run Keys WITH Startup Folder under one sub-technique. Investigation-wise, treat Run-Keys + Startup-LNK as siblings: cross-check for the same command-line appearing in both forms (belt-and-suspenders persistence). Intel 471 2021 APT-hunting analysis corroborates this pairing across multiple threat-actor toolkits.'
  known-siblings:
  - Startup-LNK
  - Active-Setup
  - Winlogon-Userinit-Shell
  - Services
  - Scheduled-Tasks
  - ImageFileExecutionOptions
provenance:
  - mitre-t1547
  - mitre-t1547-001
  - ms-run-and-runonce-registry-keys
  - ms-sysinternals-autoruns
  - forensicartifacts-windowsrunkeys
  - regripper-plugins
  - intel471-2021-hunting-persistence-run-keys-startup
  - carvey-2022-testing-registry-modification-scenario
  - psmths-windows-forensic-artifacts-reg-run-runonce
---

# Run / RunOnce Registry Keys

## Forensic value
Foundational persistence mechanism on Windows. Values under Run execute on every logon (HKCU) or every boot (HKLM); RunOnce values execute once then auto-delete. Every autostart-dependent tool from legitimate installers to every known malware family touches these keys.

Investigative first-pass: dump all four variants (HKCU\Run, HKCU\RunOnce, HKLM\Run, HKLM\RunOnce, plus Wow6432Node). Unrecognized entry names pointing to temp directories or user AppData are immediate red flags.

## Two concept references
- ExecutablePath (command-line value data)
- UserSID (for HKCU scope only)

## Known quirks
- **Command-line vs pure path.** Values may contain arguments and environment variables. `cmd.exe /c ...` or `rundll32.exe shell32.dll,...` patterns are classic evasion.
- **Order of execution** among same-scope Run entries is NOT defined — don't rely on value-ordering for sequence inference.
- **RunOnce supposed to self-delete** on successful execution. A persistent RunOnce entry means execution failed or was intercepted.
- **Similar keys** (same investigative class, not captured in this artifact): `RunServices`, `RunServicesOnce` (legacy), `Explorer\Run`, `Winlogon\Userinit`.

## Anti-forensic caveats
HKCU variants are user-editable without elevation. A sophisticated user can clean their own Run keys with zero audit trail. Cross-reference with:
- Autoruns.sc output if historical
- Prefetch entries for the referenced executable (if it ever ran)
- Amcache for PE metadata of the target

## Practice hint
On a clean Win10 VM, install a known app (e.g., Spotify). Inspect HKCU\Software\Microsoft\Windows\CurrentVersion\Run — observe the new entry. Uninstall the app; many uninstalls leave orphan Run entries. That's a common benign pattern worth recognizing so you don't chase it as malicious.
