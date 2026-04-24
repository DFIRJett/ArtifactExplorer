---
name: windows-disk-metadata
kind: disk-substrate
substrate-class: Filesystem/Disk
aliases: [disk-level metadata, pre-filesystem structures, partition-table structures]

format:
  scope: "whole-disk structures that sit below any filesystem — the MBR and GPT regions. Filesystem boot sectors (NTFS $Boot, FAT32/exFAT boot sectors) live one layer up in their respective containers (windows-ntfs-metadata, windows-fat-metadata)."
  variants:
    - name: MBR
      location: "LBA 0 of a whole disk (not a partition) — 512 bytes"
      contents: "bootstrap code (0x00-0x1B7), disk signature (0x1B8-0x1BB), reserved (0x1BC-0x1BD), 4-entry partition table (0x1BE-0x1FD), boot signature 0x55AA (0x1FE-0x1FF)"
      scheme: "legacy BIOS; hard cap of ~2.2TB addressable and 4 primary partitions"
    - name: GPT
      location: "LBA 1 onward (primary GPT header + partition-entry array); LBA -1 onward (backup GPT)"
      contents: "GPT header (disk GUID, partition-entry LBA, entry count, header CRC), partition-entry array (type GUID, unique GUID, LBA range, attributes, name)"
      scheme: "UEFI-era; 128 partitions typical, 64-bit LBA"
      note: "GPT disks carry a 'protective MBR' at LBA 0 for legacy-tool compatibility — one partition of type 0xEE spanning the disk. The real partition table is the GPT structure."
  authoritative-spec:
    - title: "IBM PC DOS 3.0 master boot record layout"
      author: IBM
      note: "no formal spec; de-facto standard documented across every OS-dev resource"
    - title: "UEFI Specification §5 (GPT Disk Layout)"
      author: UEFI Forum
      url: https://uefi.org/specifications
      note: "authoritative for GPT header + partition-entry array layout"

structure:
  mbr:
    bootstrap-code: "offset 0x000-0x1B7 (440 bytes) — 16-bit real-mode bootloader; Windows-installed MBR runs NTLDR / bootmgr; OEM MBR may chain-load vendor recovery"
    disk-signature: "offset 0x1B8 (4 bytes LE) — THE MBR disk signature. Windows assigns this at disk initialization; referenced by MountedDevices binding-data (MBR case) and by Partition/Diagnostic-1006 EventData\\Mbr\\Signature"
    reserved: "offset 0x1BC (2 bytes) — typically 0x0000; 'copy-protected' flag historically"
    partition-table: "offset 0x1BE (64 bytes) — 4 entries × 16 bytes each. Per entry: boot-flag (0x80/0x00), start CHS (3 bytes), partition type (1 byte), end CHS (3 bytes), start LBA (uint32 LE), sector count (uint32 LE)"
    signature: "offset 0x1FE (2 bytes) — 0x55 0xAA; same magic as FS boot sectors"
  gpt-header:
    signature: "offset 0x00 — 'EFI PART' (8 bytes)"
    revision: "offset 0x08 (uint32)"
    header-size: "offset 0x0C (uint32) — typically 92"
    header-crc32: "offset 0x10 (uint32) — CRC32 over the header itself"
    current-lba: "offset 0x18 (uint64) — LBA where this header lives (1 for primary, N-1 for backup)"
    backup-lba: "offset 0x20 (uint64) — LBA of the other header"
    disk-guid: "offset 0x38 (16 bytes) — whole-disk GUID"
    partition-entry-lba: "offset 0x48 (uint64) — typically LBA 2"
    partition-count: "offset 0x50 (uint32) — typically 128"
    entry-size: "offset 0x54 (uint32) — typically 128 bytes"
    entry-array-crc32: "offset 0x58 (uint32) — CRC32 of the partition-entry array"

persistence:
  acquisition:
    - "raw disk image of full physical disk (NOT partition) — FTK Imager, dd, X-Ways; partition-scope images lose the MBR/GPT"
    - "`\\\\.\\PhysicalDriveN` on Windows (admin) — sector 0 is the MBR"
    - "PartitionDiagnostic-1006 EventData\\Mbr\\* and \\Gpt\\* fields — kernel captures these at device mount"
  parsers:
    - name: "mmls (The Sleuth Kit)"
      strengths: [partition table dump, MBR and GPT]
    - name: "fdisk -l / gdisk -l (Linux)"
      strengths: [interpreted partition table view]
    - name: "DiskPart list disk + detail disk (Windows)"
      strengths: [live disk metadata; shows disk signature + GPT disk GUID]
    - name: "FTK Imager"
      strengths: [raw sector-0 hex view]
    - name: "gptfdisk (gdisk)"
      strengths: [GPT repair + header CRC verification]

forensic-relevance:
  - disk-identity: "MBR disk signature is a 4-byte device-level identifier — distinct from any filesystem VSN. Windows uses it as the unique key in the Boot Configuration Data store and in MountedDevices bindings. A disk signature collision (two disks with the same signature) forces Windows to auto-regenerate one — `chkdsk` or `diskmgmt.msc` will log the change."
  - partition-reconstruction: "Even with all filesystem-level evidence destroyed, the partition table tells you the volume layout: where partitions started, how big they were, what type (0x07 NTFS, 0x0B/0x0C FAT32, 0x07 or 0xAF on macOS, 0xEE protective-MBR for GPT). Carving unallocated space starts here."
  - gpt-disk-guid: "Whole-disk GUID in GPT header — analogous to MBR disk signature but 128-bit. MountedDevices doesn't directly record it; Partition/Diagnostic-1006 does via EventData\\Gpt\\DiskId."

integrity:
  signing: none
  tamper-vectors:
    - "direct hex edit of sector 0 — no integrity check on MBR"
    - "GPT header + partition-entry-array carry CRC32s; tamper must recompute both or the UEFI firmware rejects the disk. Backup GPT at end-of-disk is cross-validated."
    - "`bootsect.exe`, `fixmbr`, `bcdedit`, `diskpart clean` — legitimate tools that rewrite MBR/GPT; can be misused to purge disk signature"
  detection-cues:
    - "MBR disk signature of 0x00000000 — uninitialized disk OR post-`diskpart clean` state. Not forensically expected on a once-used disk."
    - "GPT header CRC mismatch — tamper evidence (or severe corruption); rare in nature"
    - "Main vs backup GPT divergence — header fields should be mirrored exactly except current-lba/backup-lba; any other divergence = tamper"
    - "Protective-MBR partition entry of type != 0xEE on a disk with valid GPT — hybrid MBR (legitimate on Mac Boot Camp) vs. malicious deception; context matters"

known-artifacts:
  # Disk-level structures — raw-sector artifacts below any filesystem.
  # Authored: MBR (in-scope for MBR disk signature VSN corroboration).
  # GPT header / partition-entry array are deferred but the container
  # describes their structure for future authoring.
  authored:
    - MBR                      # sector 0 of whole disk; carries 4-byte disk signature at 0x1B8
  unwritten:
    - name: GPT-Header
      location: LBA 1 (primary) and LBA -1 (backup) of whole disk
      value: whole-disk GUID, partition-entry-array pointer + CRC, header CRC. Primary vs backup divergence = tamper signal.
    - name: GPT-PartitionEntries
      location: LBA 2+ (primary array); LBA -33+ (backup array)
      value: 128 × 128-byte entries with per-partition unique GUID, type GUID, LBA range, name (UTF-16LE)
    - name: Protective-MBR
      location: LBA 0 of GPT disks — single partition of type 0xEE spanning the disk
      value: UEFI compatibility shim for legacy MBR-only tools; abnormalities indicate hybrid-MBR (legitimate on Mac) or deception
provenance:
  - carrier-2005-file-system-forensic-analysis
  - libyal-libvshadow-libvshadow-offline-vss-metadat
  - ms-volume-shadow-copy-service-vss-arch
---

# Disk Metadata (MBR / GPT)

## Forensic value
Disk-level structures below any filesystem. The MBR's 4-byte disk signature (offset 0x1B8) is referenced by MountedDevices binding-data (Format 2 — MBR case) and by the kernel's Partition/Diagnostic-1006 event. GPT's whole-disk GUID serves the analogous role for UEFI-era disks.

## Relationship to other containers
- **windows-ntfs-metadata** — NTFS $Boot sits on top of this layer. The MBR/GPT tells you where the NTFS partition starts.
- **windows-fat-metadata** — FAT32 and exFAT boot sectors similarly sit on top.
- **windows-registry → MountedDevices** — consumer of MBR disk signature (binding-data Format 2).
- **windows-evtx → PartitionDiagnostic-1006** — consumer of MBR disk signature (EventData\\Mbr\\Signature) and GPT disk GUID (EventData\\Gpt\\DiskId).

## MBR vs GPT quick reference
| | MBR | GPT |
|---|---|---|
| Location | LBA 0 only | LBA 1 (primary) + LBA -1 (backup) |
| Disk identifier | 4-byte disk signature at 0x1B8 | 16-byte disk GUID |
| Partition count | 4 primary (with extended-partition extension for more) | 128 typical |
| Max disk | ~2.2 TB | effectively unlimited (64-bit LBA) |
| Integrity | none | header CRC + partition-entry-array CRC + full backup |
| Windows uses for | pre-UEFI boot, small removable media, legacy | all modern installs since Win8+ UEFI, all disks ≥2TB |

## Practice hint
- On a test VM: `wmic diskdrive get DeviceID,Signature` to list disks with MBR signatures.
- Dump sector 0 of a physical disk: `dd if=\\.\PhysicalDrive0 bs=512 count=1 of=mbr.bin`. Open in HxD; identify the 4 bytes at offset 0x1B8. Convert little-endian to match the `wmic` output (wmic reports decimal).
- Correlate that signature against `HKLM\SYSTEM\MountedDevices` values — the 12-byte Format 2 bindings whose first 4 bytes match are the MBR-case volume bindings for this disk.
- Correlate against `Microsoft-Windows-Partition/Diagnostic` event 1006's `EventData\\Mbr\\Signature` field — kernel-level record of the same value.
