---
name: Boot
aliases: ["$Boot", NTFS boot sector]
link: file
tags: [system-wide, tamper-hard]
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: $Boot
substrate-hub: NTFS Metadata
platform:
  windows: {min: XP, max: '11'}
location:
  path: "<root>\\$Boot (MFT entry 7; occupies first cluster of volume)"
  addressing: NTFS-metadata-file
fields:
- name: oem-id
  kind: label
  location: "offset 0x03 — 'NTFS    ' for NTFS volumes"
- name: bytes-per-sector
  kind: size
  location: "offset 0x0B — BIOS parameter block"
- name: sectors-per-cluster
  kind: size
  location: "offset 0x0D"
- name: total-sectors
  kind: size
  location: "offset 0x28 (uint64)"
- name: mft-cluster
  kind: identifier
  location: "offset 0x30 (uint64) — cluster address of $MFT start"
- name: mft-mirr-cluster
  kind: identifier
  location: "offset 0x38"
- name: volume-serial-number
  kind: identifier
  location: "offset 0x48 (uint64) — filesystem-level serial"
  references-data:
  - {concept: FilesystemVolumeSerial, role: runtimeSerial}
observations:
- proposition: VOLUME_IDENTITY
  ceiling: C4
  note: "Authoritative source of cluster size, $MFT location, and volume serial number. Required to interpret any other NTFS metadata."
  qualifier-map:
    object.volume.serial: field:volume-serial-number
    object.volume.mft_start: field:mft-cluster
anti-forensic:
  write-privilege: kernel-only
provenance:
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
exit-node:
  is-terminus: true
  primary-source: libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  attribution-sentence: 'The $Boot metadata file contains the volume signature, the BIOS parameter block, and the boot loader (Metz, 2021).'
  terminates: []
  sources:
    - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
    - ms-ntfs-on-disk-format-secure-system-f
    - carrier-2005-file-system-forensic-analysis
  reasoning: >-
    $Boot (MFT entry 7) carries the NTFS Volume Serial Number assigned at format time in the BPB. Downstream artifacts — LNK files, ShellBags, MountPoints2, jump lists — record FilesystemVolumeSerial values derived from $Boot. For the question 'where did this volume-serial originate,' $Boot is the source; nothing more upstream exists on disk.
  implications: >-
    Volume-provenance terminus. When an analyst cites FilesystemVolumeSerial = XXXX in a LNK and needs to prove that value truly identifies the volume (not a forged serial in a crafted shell-item), reading $Boot from the target volume (or a VSS snapshot of it) closes the question. Relevant in USB attribution cases when the attacker reformatted the drive — $Boot from the new format contains a NEW VSN, which is itself forensic evidence of reformatting.
  identifier-terminals-referenced:
    - FilesystemVolumeSerial
---

# $Boot

## Forensic value
NTFS's boot sector — the one-cluster artifact that bootstraps every other NTFS operation. Carries the volume serial number that artifacts like ShellLNK, Prefetch, and ShellBags record at access time.

## Cross-references
- **FilesystemVolumeSerial** concept — serial recorded here IS what LNK files and ShellBags capture
- **FAT32-Boot / exFAT-Boot** — sibling boot-sector artifacts for the FAT family; VSN at different offsets (FAT32 0x43, exFAT 0x64) but same concept
- **MFT** — $Boot points at the MFT cluster
- **Bitmap** — $Boot provides the volume-size the bitmap must cover
