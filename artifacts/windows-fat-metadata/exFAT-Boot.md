---
name: exFAT-Boot
aliases: [exFAT boot sector, exFAT main boot region, VBR-exFAT]
link: file
tags: [system-wide, tamper-easy]
volatility: persistent
interaction-required: none
substrate: windows-fat-metadata
substrate-instance: exFAT
substrate-hub: FAT
platform:
  windows: {min: 'XP-SP2-via-update', max: '11'}
  windows-server: {min: '2008-via-update', max: '2022'}
location:
  path: "sector 0 of an exFAT partition (main boot region); sectors 12-23 hold the backup boot region"
  addressing: raw-LBA-partition-relative
fields:
- name: jump-instruction
  kind: label
  location: "offset 0x00 (3 bytes) — typically EB 76 90 (JMP +0x76 NOP)"
  note: "differs from FAT32's EB 58 90 — useful filesystem-identifier hint"
- name: oem-id
  kind: label
  location: "offset 0x03 (8 bytes ASCII) — 'EXFAT   ' (5 chars + 3 spaces), required by spec"
  note: "unlike FAT32, exFAT spec MANDATES this exact OEM-ID string. Any variation indicates non-spec formatter or tamper."
- name: zero-region
  kind: label
  location: "offset 0x0B to 0x3F (53 bytes) — required to be zero per spec"
  note: "distinguishes exFAT from FAT32: FAT32 has BPB fields in this range; exFAT explicitly zeros it and puts the BPB at offset 0x40+"
- name: partition-offset
  kind: identifier
  location: "offset 0x40 (uint64 LE) — LBA of this partition in the whole-disk view"
- name: volume-length
  kind: size
  location: "offset 0x48 (uint64 LE) — partition size in sectors"
- name: fat-offset
  kind: identifier
  location: "offset 0x50 (uint32 LE) — sector offset of FAT (relative to partition)"
- name: fat-length
  kind: size
  location: "offset 0x54 (uint32 LE) — FAT size in sectors"
- name: cluster-heap-offset
  kind: identifier
  location: "offset 0x58 (uint32 LE) — sector offset of cluster heap"
- name: cluster-count
  kind: counter
  location: "offset 0x5C (uint32 LE)"
- name: first-cluster-of-root
  kind: identifier
  location: "offset 0x60 (uint32 LE) — cluster address of root directory"
- name: volume-serial-number
  kind: identifier
  location: "offset 0x64 (uint32 LE) — filesystem-level serial, generated at format time"
  references-data:
  - {concept: FilesystemVolumeSerial, role: runtimeSerial}
  note: "THE VSN. Offset differs from FAT32 (0x43) and NTFS (0x48). Same shell-artifact representation: 4-byte LE integer, often shown XXXX-XXXX in Explorer."
- name: filesystem-revision
  kind: label
  location: "offset 0x68 (uint16 LE) — high byte major, low byte minor (e.g., 01 00 = revision 1.0)"
  note: "currently always 01 00; future revisions may change BPB layout"
- name: volume-flags
  kind: enum
  location: "offset 0x6A (uint16 LE) — bitfield: bit0 ActiveFat, bit1 VolumeDirty, bit2 MediaFailure, bit3 ClearToZero"
  note: "VolumeDirty bit = clean-unmount flag; analog to NTFS $Volume dirty bit. Set when volume is mounted RW, cleared on clean unmount. Always-set value suggests frequent unsafe removal."
- name: bytes-per-sector-shift
  kind: size
  location: "offset 0x6C (uint8) — log2 of bytes-per-sector (typically 9 = 512)"
- name: sectors-per-cluster-shift
  kind: size
  location: "offset 0x6D (uint8) — log2 of sectors-per-cluster"
- name: number-of-fats
  kind: counter
  location: "offset 0x6E (uint8) — typically 1 on exFAT (can be 2 for TexFAT, rare)"
- name: drive-select
  kind: label
  location: "offset 0x6F (uint8) — INT 13h drive number"
- name: percent-in-use
  kind: counter
  location: "offset 0x70 (uint8) — volume fullness, 0-100 or 0xFF if unknown"
- name: boot-code
  kind: content
  location: "offset 0x78 to 0x1FD — 390 bytes of real-mode bootstrap"
- name: boot-signature
  kind: label
  location: "offset 0x1FE (2 bytes) — 0x55 0xAA, same as FAT32"
- name: boot-checksum
  kind: hash
  location: "sector 11 of main boot region (end-of-boot-region) — stored repeatedly across the sector as uint32 values"
  encoding: "32-bit rolling checksum of sectors 0-10 per exFAT spec §3.4; VolumeFlags and PercentInUse excluded from the computation"
  note: "INTEGRITY MECHANISM. After hex-editing the boot sector (including VSN), this checksum must be recomputed or the volume will fail mount on Windows. Tamper-detection signal unavailable on FAT32."
observations:
- proposition: EXISTS
  ceiling: C3
  note: "exFAT boot sector existence + VSN combination uniquely identifies a specific formatting of the volume. Checksum raises confidence vs FAT32 but admin can still recompute it."
  qualifier-map:
    entity.filesystem: field:oem-id
    entity.volume-serial: field:volume-serial-number
    entity.dirty-state: field:volume-flags
  preconditions:
  - raw-disk access to the partition
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: "boot-region checksum — sectors 0-10 hashed into sector 11, validated at mount time by Windows exFAT driver"
  audit-trail: none
  detection-cues:
  - "boot-region checksum mismatch between stored (sector 11) and recomputed value = tamper evidence"
  - "backup boot region (sectors 12-23) should be byte-identical to main region (sectors 0-11). Divergence = tamper."
  - "OEM-ID != 'EXFAT   ' on a volume that mounts as exFAT is anomalous — spec-mandated value; Windows exFAT driver verifies it."
provenance: [carrier-2005-file-system-forensic-analysis]
---

# exFAT Boot Sector

## Forensic value
The authoritative source of an exFAT volume's identity. Carries the 4-byte volume serial number (VSN) at offset 0x64 that shell artifacts record at access time. For USB flash >32GB and SDXC cards — the dominant modern exFAT deployments — this sector is the pivot back from per-user artifacts to the physical volume.

exFAT has two properties that FAT32 lacks, which raise forensic confidence:
1. **Boot-region checksum** (sector 11) over sectors 0-10. Tamper-evident — a hex-edit of the VSN without recomputing the checksum makes the volume unmountable on Windows.
2. **Backup boot region** (sectors 12-23) is a full byte-identical replica of sectors 0-11. Divergence between main and backup is a high-confidence tamper signal.

C3 ceiling: admin can still recompute the checksum and mirror the backup region, so not tamper-hard. But detection threshold is meaningfully higher than FAT32's naive hex-edit path.

## Offset geometry vs FAT32
| Field | FAT32 | exFAT |
|---|---|---|
| Volume serial | 0x43 | 0x64 |
| OEM-ID string | variable (Windows writes 'MSWIN4.1') | MUST be 'EXFAT   ' |
| BPB start | 0x0B | 0x40 (with 0x0B-0x3F zeroed) |
| Backup boot sector | relative sector 6 (just sector 0 replicated) | relative sectors 12-23 (FULL 12-sector main boot region replicated) |
| Integrity | none | boot-region checksum + redundant backup region |

## Cross-references
- **FilesystemVolumeSerial** concept — offset 0x64 is the authoritative source.
- **PartitionDiagnostic-1006** — `Vbr0/Vbr1/Vbr2` fields capture raw VBR at mount time, enabling historical VSN recovery after reformat.
- **ShellLNK, ShellBags, Recent-LNK, jump lists, Prefetch** — VSN consumers.

## Known quirks
- **Dirty bit** (volume-flags bit 1) is set on mount and cleared on clean unmount. Forensic images acquired from a mounted volume routinely show dirty-bit set — not a forensic signal per se, but a reminder that the acquisition context matters (live vs offline).
- **Active-FAT bit** (volume-flags bit 0) indicates whether the primary or secondary FAT is authoritative. On default exFAT (one FAT), it's always 0. If 1, you're looking at TexFAT or a non-standard exFAT — rare but flagged behavior.
- **`chkdsk` clears the checksum validation** on volumes it believes are inconsistent. Absence of matching checksum isn't automatically tamper — investigate chkdsk history (System.evtx, CBS log).

## Practice hint
- Format an SDXC or ≥64GB USB as exFAT (`format X: /FS:exFAT /V:TESTVOL /Q`).
- Dump sector 0: `dd if=\\.\X: bs=512 count=1 | xxd`. Confirm bytes 0x00-0x02 are `EB 76 90`, bytes 0x03-0x0A spell "EXFAT   ", bytes 0x0B-0x3F are zero.
- Read VSN at offset 0x64 (4 bytes LE). Compare to `vol X:` output (Windows displays the VSN in hex form).
- Dump sector 11: `dd if=\\.\X: bs=512 skip=11 count=1 | xxd`. It is filled with a repeating 32-bit checksum value.
- Dump the backup boot region: `dd if=\\.\X: bs=512 skip=12 count=12 | sha256sum`; compare to main `dd if=\\.\X: bs=512 count=12 | sha256sum`. They must match on a clean volume.
- Open a file; check the resulting LNK's DriveSerialNumber via `LECmd.exe` — it equals the VSN at offset 0x64.
