---
name: BAM
aliases:
- Background Activity Moderator
- bam
- BackgroundActivityModerator
link: application
tags:
- timestamp-carrying
- tamper-hard
- per-user
- rotation-fast
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: '10.1709'
    max: '11'
  windows-server:
    min: '2019'
    max: '2022'
location:
  hive: SYSTEM
  path: CurrentControlSet\Services\bam\State\UserSettings\<SID>\<executable-path>
  addressing: hive+key-path
  variant-paths:
    win10-1709-to-1803: SYSTEM\CurrentControlSet\Services\bam\UserSettings\<SID>\<path>
    win10-1809-plus: SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>\<path>
  companion-key: CurrentControlSet\Services\dam\State\UserSettings\<SID>\<path>  (Desktop Activity Moderator — same schema)
  lookup-rule: "union query both paths — on upgraded systems both may coexist. Single-path parsers silently miss data on mixed estates."
retention:
  purge-rules:
    - "entries older than 7 days of inactivity are purged on boot"
    - "entries for deleted binaries are removed at next reboot"
fields:
- name: user-scope-sid
  kind: identifier
  location: subkey name under UserSettings
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: profileOwner
  note: BAM's per-user scope is encoded directly in the key hierarchy — no ProfileList lookup needed
- name: executable-path
  kind: path
  location: value name under <SID> subkey
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: the value name IS the full executable path — BAM uses the path as its key
- name: last-execution-time
  kind: timestamp
  location: value data — first 8 bytes
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: set by the BAM kernel service on each execution observed
  note: the canonical per-user per-exe last-run timestamp on Win10 1709+
- name: value-trailer-bytes
  kind: flags
  location: "value data bytes 8–23 (exactly 24 bytes total per Suhanov/dfir.ru — bam.sys rejects anything else)"
  encoding: "bytes 8–15 typically all-zero; bytes 16–23 typically 00 00 00 00 02 00 00 00"
  note: "record-format sentinel; the full record is exactly 24 bytes FILETIME + 16B trailer. Deviation from this layout is a tamper indicator."
- name: bam-key-last-write
  kind: timestamp
  location: State\UserSettings\<SID> key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: updated when any value under <SID> is written — approximates 'most recent BAM activity for this user'
observations:
- proposition: EXECUTED
  ceiling: C4
  note: 'BAM is kernel-service-written. Ordinary user-mode processes cannot

    overwrite its values without elevation; the BAM service owns the key.

    That makes BAM''s timestamps the strongest per-user execution evidence

    on modern Windows — stronger than UserAssist (HKCU, trivially

    user-editable) and stronger than Prefetch for user-attribution

    (Prefetch doesn''t carry a user SID).

    '
  qualifier-map:
    process.image-path: field:executable-path
    actor.user: field:user-scope-sid
    time.start: field:last-execution-time
    time.end: field:last-execution-time
  preconditions:
  - SYSTEM hive available
  - Target system is Win10 1709+ (BAM didn't exist before then)
  - Transaction logs replayed
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: service-scoped ACL on the key
  known-cleaners:
  - tool: USBOblivion
    typically-removes: false
    note: doesn't target BAM at all
  - tool: CCleaner
    typically-removes: false
  - tool: manual reg-delete (as admin)
    typically-removes: surgical
    note: requires SYSTEM token or BAM service stop for non-fighting removal
  - tool: BAM-service-stop + offline hive edit
    typically-removes: full
  survival-signals:
  - BAM entries present for executables whose Prefetch files are missing = selective Prefetch cleanup; BAM survives because
    cleaners miss HKLM\SYSTEM\Services\bam
  - BAM executable-path referencing a file no longer on disk = the exe was deleted after execution; BAM's record persists
  - BAM timestamps earlier than Prefetch's last-run for same exe = Prefetch was recreated after a cleanup (timestamp skew
    is the signal)
provenance: []
---

# BAM — Background Activity Moderator

## Forensic value
Single strongest per-user execution artifact on Win10 1709+. BAM is a kernel service that tracks program execution per-user as part of Windows' power-management background-task throttling. Because the service writes to `HKLM\SYSTEM\...\bam\State\UserSettings\<SID>` (a SYSTEM-hive-scoped key, not HKCU), BAM entries are tamper-hard against ordinary user activity.

The artifact's form is maximally simple: one subkey per user SID, one value per executable path the user has run, with the last-execution FILETIME in the value data. That directness is its forensic strength — no decoding, no parsing gymnastics, no ROT13.

## Two concept references
- UserSID — from the subkey name (direct, not derived)
- ExecutablePath — from the value name (direct, not decoded)

## Why C4
1. **Kernel-service-written.** Ordinary user-mode processes cannot modify BAM.
2. **User-SID embedded in the key path.** No session-chain inference needed.
3. **Executable path as value name.** Atomic per-path-per-user evidence.
4. **Survives most cleaner tools.** Not in the standard cleaner target lists.

Ceiling caps at C4 rather than C5 because the key IS still registry-edit-able with admin + SYSTEM token, and the field is not cryptographically signed. For C5-class removable-media evidence the combination of BAM + Partition/Diagnostic 1006 + USBSTOR reaches C5 via multi-source agreement.

## Known quirks
- **Path moved in Win10 1809.** Pre-1809: `...\bam\UserSettings\<SID>\...`. Post-1809: `...\bam\State\UserSettings\<SID>\...`. Parsers that only check one path miss the other. Tools like `bam.py` and RegRipper handle both.
- **Companion DAM key** at `...\dam\State\UserSettings\<SID>` has the same schema for desktop-level throttling. Extract both when sweeping for execution evidence.
- **Value data format is partially undocumented.** The first 8 bytes are always the last-execution FILETIME; the remainder has varied between Windows versions and isn't fully reverse-engineered in public sources.
- **No run count.** Unlike UserAssist or Prefetch, BAM only records the *most recent* execution time per (user, exe). Multiple runs leave no count trail.
- **Doesn't distinguish interactive vs. non-interactive launches.** Programs run by scheduled tasks, services running as a user, or shell-spawns all appear identically in BAM if they execute under that user's token.

## Anti-forensic caveats
Because BAM lives in HKLM\SYSTEM and is owned by a service, the common user-mode cleaning tools (USBOblivion, CCleaner, Autoruns) don't touch it. Attackers who know about BAM must either run with admin + SYSTEM token, stop the BAM service, or edit the hive offline — each of which leaves its own traces (event log entries, service-state anomalies).

The most common failure mode is *absence* — a target Windows box that's pre-1709 simply doesn't have BAM. Don't mistake absence for evidence-of-cleanup if the OS version predates the feature.

## Practice hint
- On a clean Win10 VM: log in as User A, run Notepad; log in as User B, run Calculator. Parse BAM. Confirm two distinct user-SID subkeys, each with one value reflecting their respective program.
- Run `regedit` as admin and attempt to edit a BAM value while logged in as a regular user. Observe access-denied — the BAM service owns the key.
- Run Notepad. Delete the Notepad .pf file immediately. Wait several minutes. Verify that BAM's last-execution-time for Notepad remains intact even though Prefetch was cleaned.
- Compare BAM's `last-execution-time` for a known exe to Prefetch's `last-run-time` for the same exe. They should match within one second (both are kernel-written on execution).
