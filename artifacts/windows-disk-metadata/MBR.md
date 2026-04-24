---
name: MBR
aliases: [Master Boot Record, sector-0, legacy boot sector]
link: file
tags: [system-wide, tamper-easy]
volatility: persistent
interaction-required: none
substrate: windows-disk-metadata
substrate-instance: MBR
substrate-hub: Disk Metadata
platform:
  windows: {min: XP, max: '11'}
  windows-server: {min: '2003', max: '2022'}
  note: "platform-independent — PC-BIOS artifact predates any OS lineage"
location:
  path: "LBA 0 of a whole physical disk (NOT a partition) — 512 bytes"
  addressing: raw-LBA-whole-disk
fields:
- name: bootstrap-code
  kind: content
  location: "offset 0x000 to 0x1B7 (440 bytes)"
  note: "16-bit real-mode bootloader. Windows-installed MBR chain-loads bootmgr from the active partition; OEM MBR may chain-load vendor recovery. Bytes identify the installer (mbrwizard, syslinux, GRUB, Windows, ThinkPad recovery, etc.)."
- name: disk-signature
  kind: identifier
  location: "offset 0x1B8 (uint32 LE) — 4-byte MBR disk signature"
  encoding: uint32-le
  references-data:
  - {concept: MBRDiskSignature, role: diskIdentity}
  note: "THE MBR disk signature. Written by Windows at disk initialization (diskmgmt, diskpart, Windows Setup). Read by Windows on every boot to correlate the disk against Boot Configuration Data. Referenced by MountedDevices binding-data (Format 2 — MBR case) and by PartitionDiagnostic-1006 EventData\\Mbr\\Signature."
- name: reserved
  kind: label
  location: "offset 0x1BC (2 bytes)"
  note: "typically 0x0000; some older docs label this a 'copy-protected' flag but no modern OS interprets it"
- name: partition-table
  kind: content
  location: "offset 0x1BE (64 bytes) — 4 entries × 16 bytes"
  encoding: |
    Per 16-byte entry:
      0x00  boot-flag           (0x80 = active/bootable, 0x00 = inactive)
      0x01  start-chs           (3 bytes — legacy cylinder/head/sector; ignored on LBA-addressed disks)
      0x04  partition-type      (1 byte — 0x07 NTFS/exFAT, 0x0B/0x0C FAT32, 0x83 Linux, 0xEE GPT-protective)
      0x05  end-chs             (3 bytes)
      0x08  start-lba           (uint32 LE — partition start, in sectors, from LBA 0)
      0x0C  sector-count        (uint32 LE — partition size in sectors)
  note: "4 primary partitions max. 'Extended' partitions (type 0x05/0x0F) chain-load a secondary partition table in an EBR for >4 partitions. GPT disks use a single protective-MBR entry of type 0xEE spanning the disk."
- name: boot-signature
  kind: label
  location: "offset 0x1FE (2 bytes) — 0x55 0xAA"
  note: "magic marker required for BIOS to consider the sector bootable. Absence = BIOS will refuse to boot from this disk; MBR-less disks (freshly zeroed, GPT-only-with-zeroed-protective-MBR) exhibit this."
observations:
- proposition: EXISTS
  ceiling: C3
  note: "MBR existence + disk-signature uniquely identifies a specific initialization of the disk. Signature is device-level (persists across filesystem reformats unless explicitly cleared)."
  qualifier-map:
    entity.disk-signature: field:disk-signature
    entity.partition-layout: field:partition-table
  preconditions:
  - raw-disk access to the physical drive (NOT partition-level access)
- proposition: CREATED
  ceiling: C2
  note: "Partition-table entries document partition creation points in LBA space. Timestamp-free — creation-TIME is not in the MBR; infer from adjacent artifacts (setupact.log, first filesystem formatting in Partition/Diagnostic-1006)."
  qualifier-map:
    object.partition-layout: field:partition-table
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: none (no checksum or signature over the MBR)
  audit-trail: "none at MBR itself; Partition/Diagnostic-1006 records the kernel-read MBR at every mount — historical MBR recovery path if the live disk is modified post-incident"
  detection-cues:
  - "disk-signature == 0x00000000 — uninitialized OR post-`diskpart clean` state; NOT expected on a once-used disk"
  - "bootstrap-code differing from Windows default (hashable against known installers) — custom bootkit, user-installed multi-boot manager (GRUB, rEFInd), OR malicious boot-sector override"
  - "MBR disk signature differs from the value recorded in MountedDevices binding-data Format 2 for same disk — disk signature was changed post-binding; Windows handles this by regenerating the signature and logging, so also search System.evtx for `PartMgr` events"
  - "partition-table entry spans beyond sector-count of the physical disk — partition-table crafted on larger disk then cloned to smaller; forensic-hostile state"
provenance: [carrier-2005-file-system-forensic-analysis]
exit-node:
  is-terminus: false
  terminates: []
  sources:
    - carrier-2005-file-system-forensic-analysis
  reasoning: >-
    MBR carries the MBRDiskSignature at disk offset 0x1B8 — the authoritative 4-byte disk identifier that MountedDevices, PartitionDiagnostic-1006, and Windows volume-mount logic use to bind a SYSTEM-hive device reference to a physical disk. For MBRDiskSignature provenance (where does this value originate), MBR is the source; no artifact upstream of the disk itself exists.
  implications: >-
    Parallel to Boot ($Boot) for NTFS-VSN: MBR terminates disk-identity provenance at the physical-media layer. When attacker wipes registry but leaves the disk intact, MBR preserves the identifier needed to match recovered filesystem artifacts back to the specific disk. Reformatting the disk generates a NEW MBRDiskSignature — that change is itself forensic evidence.
  identifier-terminals-referenced:
    - MBRDiskSignature
---

# Master Boot Record

## Forensic value
The disk-level substrate artifact. Sector 0 of every legacy-partitioned disk. The 4-byte disk signature at offset 0x1B8 is the device-level identifier that Windows tracks in:
- **MountedDevices** `binding-data` Format 2 — first 4 bytes literally equal the MBR disk signature
- **PartitionDiagnostic-1006** — `EventData\Mbr\Signature` captures it at every mount
- **Boot Configuration Data** — references disks by MBR disk signature for MBR boot entries

Distinct from the filesystem's volume serial number: the MBR disk signature persists across filesystem reformats within the partition, because the MBR sits outside any partition. It changes only when the MBR itself is rewritten (diskpart clean, disk initialization).

C3 ceiling: on-disk, persists, but admin-editable with no integrity mechanism.

## When to read it
- Whenever MountedDevices binding-data is in Format 2 (exactly 12 bytes, not a device-string). The first 4 bytes reference this artifact.
- When investigating whether a disk has been reinitialized — signature change between historical artifacts and current MBR indicates post-incident disk reinit.
- Partition-carving work: the partition-table entries tell you where filesystems start, regardless of whether the filesystem boot sectors survive.

## Known quirks
- **Cloned disks sharing a signature**. When a disk is `dd`-imaged to another disk, both carry the same signature. Windows detects this on simultaneous attach and auto-regenerates one signature, logging an Event Log entry. If you see two disks in an enterprise with identical MBR signatures but only one attached to a system, the ghost collision may explain anomalous MountedDevices entries.
- **GPT disks have a protective MBR at sector 0**. It looks like an MBR but contains a single entry of type 0xEE spanning the disk. The 4 bytes at offset 0x1B8 on a protective MBR are typically zero — GPT disks do not use an MBR disk signature. Consult the GPT header for the disk GUID instead.
- **Hybrid MBR** (used by Mac Boot Camp): protective MBR entries are non-zero, pointing at real partitions alongside a partially-honored GPT. Legitimate but rare. Don't confuse with tamper.
- **`diskpart clean`** writes 0x00 across the entire MBR sector (signature and partition table gone). `diskpart clean all` zeroes the whole disk — irrecoverable without prior imaging.

## Cross-references
- **MBRDiskSignature** concept — offset 0x1B8 is the authoritative source
- **MountedDevices** — consumes MBR disk signature as the first 4 bytes of binding-data Format 2
- **PartitionDiagnostic-1006** — kernel records MBR disk signature + full raw MBR at mount time
- **FAT32-Boot / exFAT-Boot / Boot ($Boot)** — partition boot sectors that the MBR's partition-table entries point at

## Practice hint
- `wmic diskdrive get DeviceID,Signature,Caption,Model,SerialNumber` — live enumeration of MBR signatures for all physical disks on the system.
- `dd if=\\.\PhysicalDrive0 bs=512 count=1 of=mbr.bin` (admin) — dump sector 0.
- `xxd mbr.bin` — find bytes at offset 0x1B8. Compare to wmic's decimal signature (convert 4-byte LE to uint32).
- `wevtutil qe Microsoft-Windows-Partition/Diagnostic /q:"*[System/EventID=1006]" /c:5 /rd:true /f:xml` — find kernel records of the same signature. The `Mbr.Signature` field should match the live disk.
- On a test VM: `diskpart` → `select disk N` → `clean` → re-read sector 0. Signature is now zero. This is the signature-wipe state to recognize in production incidents.
