---
name: windows-fat-metadata
kind: filesystem-metadata
substrate-class: Filesystem/Metadata
aliases: [FAT family, VFAT, FAT boot sector, exFAT boot sector]

format:
  filesystem-family: FAT / exFAT
  variants:
    FAT12: "tiny volumes (<16 MB); rare on modern Windows; VSN in BPB extended boot record at offset 0x27"
    FAT16: "small removable media; VSN at offset 0x27 of the boot sector"
    FAT32: "ubiquitous on legacy USB flash drives, SD cards, camera storage; VSN at offset 0x43"
    exFAT: "Microsoft's replacement for FAT32 on flash media (>4GB files, >32GB volumes); VSN at offset 0x64"
  authoritative-spec:
    - title: "Microsoft Extensible Firmware Initiative FAT32 File System Specification (v1.03)"
      author: Microsoft
      url: https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf
      note: "primary source for FAT32 BPB layout"
    - title: "exFAT file system specification"
      author: Microsoft
      url: https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification
      note: "official spec published 2019; BPB + boot region layout"

structure:
  common-boot-sector:
    jump-instruction: "offset 0x00 (3 bytes, JMP/NOP) — distinguishes FAT32 (EB 58 90 typical) from exFAT (EB 76 90 typical)"
    oem-id: "offset 0x03 (8 bytes ASCII) — 'MSWIN4.1' / 'MSDOS5.0' (FAT32), 'EXFAT   ' (exFAT)"
    bpb: "BIOS Parameter Block follows; layout diverges between FAT32 and exFAT"
    signature: "offset 0x1FE (2 bytes) — 0x55 0xAA magic; present on both FAT32 and exFAT boot sectors"
  fat32-specifics:
    volume-serial: "offset 0x43 (4 bytes, little-endian)"
    volume-label: "offset 0x47 (11 bytes, space-padded ASCII) — shell-visible label; often differs from entry in root directory"
    filesystem-type: "offset 0x52 (8 bytes) — 'FAT32   '"
  exfat-specifics:
    volume-serial: "offset 0x64 (4 bytes, little-endian)"
    filesystem-revision: "offset 0x68 (2 bytes)"
    volume-flags: "offset 0x6A (2 bytes) — dirty bit, media-failure bit"
    backup-boot-sector: "sectors 12-23 (main boot region), 0-11 (backup region); boot sector is replicated + checksummed"
    boot-checksum: "sector 11 (end of main boot region) — CRC-like checksum of sectors 0-10; tamper detection"

persistence:
  acquisition:
    - "raw disk image — only way to see the boot sector directly (not a named file like NTFS $Boot)"
    - "dd / FTK Imager / Arsenal Image Mounter sector 0 of the partition"
    - "PartitionDiagnostic-1006 Vbr0/Vbr1/Vbr2 fields — kernel captures raw VBR at mount time (up to 3 partitions per device)"
  locked-on-live-system: no — raw sector reads work on mounted FAT volumes via `\\.\<letter>:` or `\\.\PhysicalDriveN`
  parsers:
    - name: The Sleuth Kit (fsstat)
      strengths: [displays BPB fields including VSN for FAT32 and exFAT]
    - name: hexdump / xxd
      strengths: [direct read at known offsets — trivially scriptable]
    - name: FTK Imager
      strengths: [interpreted boot-sector view; exports sector range]
    - name: exFAT-Tools (github.com/exfatprogs)
      strengths: [exFAT-specific — validates boot region checksum]

forensic-relevance:
  - volume-identity: "FAT32/exFAT boot sector is the authoritative source of the volume's 4-byte serial number. Shell artifacts (LNK, shellbags, jump lists, prefetch) record this serial at access time; matching a per-user artifact's serial back to the boot sector serial is the core cross-reference for proving a user accessed a specific volume."
  - usb-flash-dominance: "FAT32 and exFAT dominate removable flash storage. Most USB drives >32GB ship exFAT; <32GB still ship FAT32. An NTFS-only analyst workflow misses the boot-sector VSN path on essentially every consumer USB examined."
  - reformat-detection: "VSN regenerates on format. If a device's hardware DeviceSerial matches a previously-seen device but the FilesystemVolumeSerial differs, the volume was reformatted between sightings — itself a forensic signal (intentional anti-forensic action or legitimate reuse)."

integrity:
  signing: none (FAT32); boot-region checksum (exFAT)
  tamper-vectors:
    - "direct hex edit of boot sector — no integrity check on FAT32"
    - "exFAT boot-region checksum (sector 11) must be recomputed after tamper, or volume fails mount"
    - "reformat regenerates VSN — cheap way to invalidate historical shell-artifact correlations"
  detection-cues:
    - "FAT32: OEM-ID strings other than the Windows defaults ('MSWIN4.1', 'MSDOS5.0') may indicate third-party formatter (mkfs.vfat on Linux writes 'mkfs.fat'). Not malicious but identifies non-Windows formatting."
    - "exFAT: boot-region checksum mismatch between sector 11 computed value and stored value indicates post-format tamper."

known-artifacts:
  # FAT family boot sectors — raw-sector artifacts (not named files).
  # Authored subset covers the two paper-documented VSN-carrying variants.
  # FAT12/FAT16 are legacy and deferred — add if a case warrants them.
  authored:
    - FAT32-Boot               # FAT32 boot sector — VSN at offset 0x43
    - exFAT-Boot               # exFAT boot sector — VSN at offset 0x64
  unwritten:
    - name: FAT16-Boot
      location: sector 0 of FAT16 partition
      value: legacy FAT16 boot sector — VSN at offset 0x27 in extended BPB. Mostly historical (pre-2008 small media, embedded systems).
    - name: FAT-DirectoryEntry
      location: 32-byte directory entries within FAT cluster chain
      value: short/long filename slots, 8.3 legacy timestamps, cluster allocation — parallel to NTFS $MFT records but far less information-dense
    - name: exFAT-AllocationBitmap
      location: exFAT root directory → allocation bitmap entry
      value: cluster allocation bitmap (exFAT's equivalent of NTFS $Bitmap); essential for carving unallocated regions
provenance:
  - carrier-2005-file-system-forensic-analysis
  - ms-efi-fat32-spec-v103
  - libyal-libfsfat
---

# FAT / exFAT Metadata

## Forensic value
The FAT family (FAT12/16/32) and exFAT dominate removable flash storage. Where NTFS has a rich on-disk metadata file tree (`$MFT`, `$UsnJrnl`, `$LogFile`, ...), FAT variants have only the boot sector plus directory entries and the FAT itself — a far smaller metadata surface. But the boot-sector volume serial number (VSN) is the critical identifier for cross-correlating per-user shell artifacts back to the filesystem.

## Relationship to NTFS metadata
- **NTFS $Boot** is a named metadata file (MFT entry 7) and the filesystem has many other metadata files.
- **FAT32/exFAT boot sectors** are raw sectors (LBA 0 of the partition) — there is no "named" artifact, you read the sector directly. That's the main cataloging difference from `windows-ntfs-metadata`.

## VSN offsets summary

| Filesystem | VSN offset | Width | Shell-artifact representation |
|---|---|---|---|
| FAT12/16 | 0x27 | 4 bytes LE | `FilesystemVolumeSerial` (same concept) |
| FAT32    | 0x43 | 4 bytes LE | `FilesystemVolumeSerial` |
| exFAT    | 0x64 | 4 bytes LE | `FilesystemVolumeSerial` |
| NTFS     | 0x48 | 8 bytes (high 4 ignored in shell artifacts) | `FilesystemVolumeSerial` |

The shell-artifact representation is always 32-bit — NTFS's 64-bit VSN is truncated at the high 4 bytes when LNK/ShellBags/etc. record it.

## Practice hint
- Format a USB as FAT32 on one system; record the VSN by hex-dumping sector 0 at offset 0x43.
- Open a file on the USB from a second system; examine the resulting LNK in that user's `Recent\`. Parse the DriveSerialNumber — it should equal the VSN you read from the boot sector.
- Reformat the USB (same tool, same filesystem). The VSN will change. Re-examine the LNK's DriveSerialNumber — now mismatched with the current boot sector. That mismatch is the reformat signal.
