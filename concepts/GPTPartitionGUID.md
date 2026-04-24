---
name: GPTPartitionGUID
kind: identifier
lifetime: permanent
link-affinity: device
description: |
  16-byte GUID identifying a partition on a GPT-formatted disk. Analogous
  to MBRDiskSignature + partition-offset for MBR disks, but scoped to the
  partition rather than the whole disk. Written to the GPT Partition Entry
  Array at disk initialization; Windows preserves it across remounts.
  Distinct from GPT-Disk-GUID (whole-disk identity, different field).
canonical-format: "16-byte GUID; mixed-endian per the GUID wire format"
aliases: [PartitionGUID, GPT-Partition-GUID, UniquePartitionGUID]
roles:
  - id: volumeBinding
    description: "GPT partition GUID as embedded in MountedDevices binding-data Format 3 — a 24-byte value whose first 8 bytes are 'DMIO:ID:' and trailing 16 bytes are the partition GUID"
  - id: kernelMountRecord
    description: "GPT partition GUID as recorded by the Partmgr kernel driver in Partition/Diagnostic-1006 PartitionTableBytes (parsed out of the raw GPT Partition Entry Array)"

known-containers:
  # Kernel event-log capture — records the partition table at every device mount
  - PartitionDiagnostic-1006     # PartitionTableBytes contains the GPT entries
  # Registry binding — MountedDevices keys GPT-case volume bindings via 24-byte payload
  - MountedDevices               # binding-data Format 3: 'DMIO:ID:' + 16-byte PartitionGUID
provenance: [carrier-2005-file-system-forensic-analysis]
---

# GPT Partition GUID

## What it is
A 16-byte GUID written to the **GPT Partition Entry Array** for each partition on a GUID Partition Table disk. Each partition has its own `UniquePartitionGUID`. GPT has both:

- **DiskGUID** — the whole-disk identifier in the GPT header (LBA 1). Analogous to MBRDiskSignature conceptually but 16 bytes instead of 4.
- **UniquePartitionGUID** — one per partition in the Partition Entry Array.

**This concept is the per-partition GUID** (the one that appears in MountedDevices binding data). The disk-level GUID is adjacent but distinct.

## How it differs from adjacent identifiers

| Identifier | Scope | Sourced from | MBR analog |
|---|---|---|---|
| **GPTPartitionGUID** | partition | GPT Partition Entry Array | MBRDiskSignature + partition byte-offset (combined) |
| **MBRDiskSignature** | physical disk (whole) | MBR sector 0 offset 0x1B8 | N/A (this IS the MBR form) |
| **GPT DiskGUID** | physical disk (whole) | GPT header (LBA 1) | MBRDiskSignature |
| **VolumeGUID** | volume (mount-manager-assigned) | MountedDevices, MountPoints2 | same (GUID-based both cases) |
| **FilesystemVolumeSerial** | filesystem inside partition | NTFS $Boot 0x48, FAT32 0x43 | same |

## Encoding variations

| Artifact | Where | Encoding |
|---|---|---|
| GPT Partition Entry Array | per-entry offset 16 | 16-byte GUID (mixed-endian) |
| MountedDevices | binding-data Format 3 — 24 bytes total: 8-byte `DMIO:ID:` ASCII prefix + 16-byte partition GUID | GUID bytes appended |
| PartitionDiagnostic-1006 | `PartitionTableBytes` XML field | raw bytes; must be parsed as a GPT Partition Entry Array |

## Forensic value

- **MountedDevices disambiguation for GPT disks**. When a MountedDevices binding is 24 bytes long with the `DMIO:ID:` prefix, the partition GUID names the specific partition that was mounted. This is the GPT equivalent of the `{signature, partition-offset}` MBR pair and is strictly more precise — the GUID is per-partition rather than a disk+offset composition.
- **Independent corroboration path**. The same partition GUID appears in Partition/Diagnostic-1006 (kernel-side, event-log) AND MountedDevices (registry). Agreement between the two is an `Established` corroboration join under the xlsx join-key taxonomy.
- **Tier-3 distinction vs. VolumeGUID**. Partition-GUID is below the Mount-Manager layer (it exists in the partition table regardless of whether Windows has assigned a VolumeGUID). VolumeGUID is a Mount-Manager decoration keyed off the partition; when VolumeGUID is missing (device not mounted during acquisition), partition GUID still survives on-disk.

## Limitations

- **Does not exist on MBR-partitioned disks**. MBR uses the 4-byte DiskSignature + 8-byte partition offset combination instead. Authored as `MBRDiskSignature` in the project.
- **Protective MBR on GPT disks has zeros at 0x1B8** — don't be fooled by a GPT disk appearing to have a zero MBR signature.
- **Admin-writable via raw disk tools**. Anyone with raw-write access to the partition table can edit the GUID. Tamper detection: compare against Partition/Diagnostic-1006 historical records, which record the value Windows observed at mount time.
- **GUID reuse not enforced by spec**. The spec strongly advises uniqueness but Windows does not validate global uniqueness across all systems. Two disks cloned byte-for-byte will carry the same partition GUIDs; disambiguation requires other identity fields (DeviceSerial, ContainerID).

## Cross-event chain with MBRDiskSignature

```
Partition/Diagnostic-1006 (mount event, any disk type)
  ├─ if MBR-partitioned:
  │     Mbr\Signature  ──┐
  │                       ├─ match with MountedDevices binding (12-byte, Format 2)
  │                       └─ = MBRDiskSignature concept
  │
  └─ if GPT-partitioned:
        DiskId (GPT disk GUID)                   ← whole-disk identity
        PartitionTableBytes → per-partition GUID ──┐
                                                   ├─ match with MountedDevices binding (24-byte, Format 3)
                                                   └─ = GPTPartitionGUID concept
```

## Not exit-node
Partition GUID is a plumbing identifier — it terminates to a physical partition, not a real-world subject. Pair with DeviceSerial or ContainerID (exit-nodes) to resolve to a physical device identity.
