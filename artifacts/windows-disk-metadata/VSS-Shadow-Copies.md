---
name: VSS-Shadow-Copies
title-description: "Volume Shadow Copies — point-in-time snapshots of NTFS volumes holding prior filesystem state"
aliases:
- Volume Shadow Copy
- VSS snapshots
- Shadow Volume
- System Restore volume
link: file
link-secondary: system
tags:
- time-travel-forensics
- deleted-file-recovery
- itm:AF
volatility: persistent
interaction-required: none
substrate: windows-disk-metadata
substrate-instance: VSS-Shadow-Copies
substrate-hub: Disk Metadata
platform:
  windows:
    min: XP
    max: '11'
  windows-server:
    min: '2003'
    max: '2022'
location:
  path-hidden: "<volume root>\\System Volume Information\\{GUID}{GUID} (hidden system directory; ACL-restricted to SYSTEM)"
  catalog: "<volume root>\\System Volume Information\\ VSS metadata tables + diff-area files"
  live-enumeration: "vssadmin list shadows"
  addressing: disk-region + file-path
  note: "Volume Shadow Copy Service (VSS) provides point-in-time copy-on-write snapshots of NTFS volumes. Each snapshot is accessible via a unique Shadow Copy path (\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyN) while mounted. Snapshots are created automatically by System Restore, Windows Backup, Previous Versions, and installer-initiated checkpoints; manually via vssadmin / wbadmin. For DFIR, VSS is the built-in TIME MACHINE — every snapshot is a previously-frozen filesystem state that can be mounted read-only and compared against current to recover deleted files, prior registry-hive state, prior user artifacts. Commonly attacker-targeted for deletion (vssadmin delete shadows) as part of pre-ransomware evidence-destruction — the deletion itself generates Security-4688 telemetry."
fields:
- name: snapshot-id
  kind: identifier
  location: "VSS metadata — Shadow Copy ID (GUID)"
  encoding: guid-string
  references-data:
  - concept: VolumeGUID
    role: mountedVolume
  note: "Unique ID per snapshot. Exposed by `vssadmin list shadows` output. Used to reference the snapshot for mounting (`vssadmin mount` / mklink junction to \\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyN)."
- name: snapshot-creation-time
  kind: timestamp
  location: "VSS metadata — OriginatingMachine + CreationTime"
  encoding: filetime-le (UTC)
  clock: system
  resolution: 100ns
  note: "When the snapshot was taken. This is the 'frozen-at' moment — the filesystem state preserved in the snapshot. Cross-reference with incident timeline: a snapshot FROM BEFORE incident window = pre-intrusion forensic baseline available."
- name: originating-machine
  kind: identifier
  location: "VSS metadata — OriginatingMachine"
  encoding: hostname string
  note: "Hostname of the machine at snapshot creation. Sanity check for transplanted/misidentified snapshots. Should match the host being investigated."
- name: service-machine
  kind: identifier
  location: "VSS metadata — ServiceMachine"
  encoding: hostname string
  note: "Hostname where VSS service executed the snapshot (normally the same as OriginatingMachine). Differs on SAN-level VSS arrangements — usually noise for standard host DFIR."
- name: provider-type
  kind: flags
  location: "VSS metadata — ProviderId"
  encoding: guid-string
  note: "VSS provider — 1 = System (default), 2 = Software, 3 = Hardware. Most host snapshots use System / Software providers. Hardware VSS (SAN) provider use indicates an enterprise-storage-backed snapshot schedule."
- name: diff-area-file
  kind: path
  location: "<volume>\\System Volume Information\\{GUID}{GUID} — copy-on-write diff-area file"
  note: "Each snapshot's delta-storage. Copy-on-write: when a file is modified on the live volume, the original block is copied to the diff-area first, then the live block is updated. Reading the snapshot layers the diff-area reads over the live volume to reconstruct the frozen state. Diff-area size grows with volume change rate."
- name: shadow-storage-config
  kind: content
  location: "vssadmin list shadowstorage output — storage volume, allocated / used / maximum"
  note: "VSS storage configuration per volume. MaxSizeBytes caps snapshot space; when full, oldest snapshots auto-evict. Attacker technique: set MaxSizeBytes very small to force immediate eviction of existing snapshots without triggering the 'vssadmin delete shadows' command-line that EDR flags."
observations:
- proposition: HAD_PRIOR_STATE
  ceiling: C4
  note: 'VSS snapshots are the single most valuable evidence-recovery
    mechanism on Windows. Each snapshot is a point-in-time
    filesystem capture that can be mounted read-only and treated
    exactly like the live volume was at that moment — directory
    listings, file contents, registry hives, EVTX logs, browser
    databases, attacker tooling that was later deleted. For
    investigations within the snapshot-retention window, VSS can
    recover pre-tamper state of essentially any filesystem-resident
    artifact. Ransomware operators routinely delete shadows (vssadmin
    delete shadows) before encryption to prevent victim recovery —
    the deletion command itself is a strong forensic signal even
    when successful. For non-ransomware intrusions, snapshots often
    survive attacker cleanup and provide the pre-intrusion baseline.'
  qualifier-map:
    object.id: field:snapshot-id
    time.start: field:snapshot-creation-time
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: VSS copy-on-write consistency model; internal checksum per diff-area block
  known-cleaners:
  - tool: "vssadmin delete shadows /all /quiet"
    typically-removes: all snapshots on default volume (very common ransomware pre-encryption command)
  - tool: "wmic shadowcopy delete"
    typically-removes: all snapshots (Security-4688 captures the wmic command-line)
  - tool: "PowerShell Delete-ShadowCopy"
    typically-removes: specific or all snapshots via PowerShell API
  - tool: "vssadmin resize shadowstorage /maxsize=401MB"
    typically-removes: forces eviction of oldest snapshots silently by shrinking space
  survival-signals:
  - vssadmin list shadows returns snapshots with CreationTime PRE-DATING the incident window = pre-tamper baseline available
  - Security-4688 / Sysmon-1 for 'vssadmin delete shadows' or 'wmic shadowcopy delete' in intrusion timeline = evidence-destruction technique T1490
  - Shadow storage silently shrunk via 'vssadmin resize shadowstorage' with reduced maxsize = alternative evidence destruction with weaker telemetry
provenance:
  - ms-volume-shadow-copy-service-vss-arch
  - mitre-t1490
  - libyal-libvshadow-libvshadow-offline-vss-metadat
  - carvey-2009-working-with-volume-shadow-copies
  - zimmerman-vscmount
exit-node:
  is-terminus: true
  primary-source: ms-volume-shadow-copy-service-vss-arch
  attribution-sentence: 'VSS coordinates the actions that are required to create a consistent shadow copy (also known as a snapshot or a point-in-time copy) of the data that is to be backed up (Microsoft, 2022).'
  terminates:
    - HAD_FILE
    - RAN_PROCESS
  sources:
    - ms-volume-shadow-copy-service-vss-arch
    - libyal-libvshadow-libvshadow-offline-vss-metadat
    - carvey-2009-working-with-volume-shadow-copies
    - zimmerman-vscmount
  reasoning: >-
    Each shadow copy IS the authoritative answer to 'what did this volume look like at snapshot time T.' For HAD_FILE at time T, the snapshot contains the file (or proves it was absent). For RAN_PROCESS corroboration, prior Prefetch / Amcache / UsnJrnl in a snapshot directly evidences execution that has since been cleaned from the live state. The snapshot is its own terminus for its specific timepoint — no 'downstream' evidence can refine a point-in-time claim.
  implications: >-
    Anti-forensic-survival anchor. When attacker cleanup deletes live evidence but VSS was not nuked (T1490 partially succeeded), the shadow copies reconstruct pre-cleanup state. Mount read-only and re-run every parser against the snapshot's filesystem. Also valuable for 'file existed and was deleted' chain-of-custody when the live deletion post-dates snapshot creation.
  identifier-terminals-referenced:
    - FilesystemVolumeSerial
    - VolumeGUID
---

# Volume Shadow Copies (VSS)

## Forensic value
Volume Shadow Copy Service creates point-in-time copy-on-write snapshots of NTFS volumes. Each snapshot is an offline-mountable, read-only filesystem state from the moment it was taken. For DFIR purposes, VSS is the built-in Windows **time machine**.

Snapshots are created automatically by:
- **System Restore** — manual & install-triggered restore points (before driver installs, Windows Updates, etc.)
- **Windows Backup** / **File History**
- **Previous Versions** feature
- **Installer checkpoints** — many MSI installers create snapshots before proceeding

Manually via `vssadmin`, `wbadmin`, `PowerShell`, `Windows.Backup`.

## Recovery scope
Each snapshot preserves:
- Complete directory structure + file contents
- Registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT — all as they were)
- EVTX logs (before current rollover)
- Browser databases
- Amcache / Prefetch / UsnJrnl entries
- Filesystem timestamps
- Any file that has been modified / deleted since the snapshot

## The ransomware deletion signal
`vssadmin delete shadows /all /quiet` is one of the most common pre-encryption ransomware commands (MITRE T1490 — Inhibit System Recovery). ALL major ransomware families (LockBit, Conti, Ryuk, BlackBasta, Akira, Play, Black Cat) include it. The command generates:

- **Security-4688** — process creation for vssadmin.exe with delete / shadows arguments
- **Sysmon-1** — same command-line with fuller context
- **System-7036** — VSS service state changes

Even when successful, the command's execution is forensic evidence. For ongoing ransomware cases, look for this command in incident timeline.

## Concept reference
- None direct — filesystem-level snapshot artifact.

## Triage
```cmd
:: Live enumeration
vssadmin list shadows
vssadmin list shadowstorage

:: Mount a specific snapshot
mklink /D C:\snap1 \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

:: Offline image (libvshadow)
vshadowmount image.raw /mnt/shadows
```

## Cross-reference
- **Security-4688 / Sysmon-1** — vssadmin / wmic / PowerShell delete commands
- **System-7036 / 7045** — VSS service state
- **Microsoft-Windows-VSS** EVTX channel — snapshot lifecycle events
- **ShimCache / Amcache / Prefetch in prior snapshots** — execution-evidence recovery across time
- **Registry hives in prior snapshots** — pre-tamper configuration recovery

## Attack-chain recovery example
Attacker cleans up: deletes dropper, clears Prefetch, empties Recycle Bin, modifies Defender exclusions to remove the staging path. Then encrypts.

VSS snapshot from 3 days before the intrusion still contains:
- The dropper file (encrypted by ransomware but filename + path survive)
- Prefetch for the attacker's recon tooling
- Amcache SHA-1 of their enumeration binaries
- Pre-tamper Defender exclusions registry state
- UsnJrnl records of their first-day activity

DFIR recovers these from the snapshot using libvshadow on the offline image. The pre-tamper forensic baseline was the ENTIRE snapshot's contents as of 3 days ago.

## Practice hint
On a lab VM: create a file, enable System Restore, trigger a restore point (Control Panel → System Properties → System Protection → Create). Delete the file from the live volume. List shadows with `vssadmin list shadows`, mount the newest snapshot with `mklink`, navigate to the snapshot's file — your deleted file is there unchanged. That recovery capability is the forensic value.
