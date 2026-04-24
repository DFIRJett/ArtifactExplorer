---
name: ObjId
aliases: ["$ObjId", NTFS object identifiers, DLT object IDs]
link: file
tags: [system-wide, tamper-hard]
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: $Extend\$ObjId
substrate-hub: NTFS Metadata
platform:
  windows: {min: XP, max: '11'}
location:
  path: "<root>\\$Extend\\$ObjId"
  addressing: NTFS-metadata-file
fields:
- name: object-id
  kind: identifier
  location: "per-record ObjectID (16 bytes, GUID-like)"
  note: "assigned to a file when a shell operation (like creating a LNK to it) requests an ObjectID. Persists for the file's lifetime on this volume."
- name: birth-object-id
  kind: identifier
  location: per-record BirthObjectId
  note: "original ObjectID at the moment the ObjectID was first assigned — survives volume-change / file-move if DLT is enabled"
- name: birth-volume-id
  kind: identifier
  location: per-record BirthVolumeId
  references-data:
  - {concept: VolumeGUID, role: accessedVolume}
- name: birth-domain-id
  kind: identifier
  location: per-record BirthDomainId
- name: mft-reference
  kind: identifier
  location: per-record FileReference
  references-data:
  - {concept: MFTEntryReference, role: referencedFile}
observations:
- proposition: DISTRIBUTED_LINK_TRACKING
  ceiling: C3
  note: "NTFS Object ID catalog — the index consulted by Distributed Link Tracking (DLT) service to resolve LNK targets after file moves. LNK TrackerDataBlock.DroidFileIdentifier and DroidVolumeIdentifier values RESOLVE HERE."
  qualifier-map:
    object.mft.reference: field:mft-reference
    object.volume: field:birth-volume-id
anti-forensic:
  write-privilege: kernel-only
provenance:
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
---

# $ObjId

## Forensic value
NTFS Object ID catalog. Whenever a LNK or similar shell artifact records a TrackerDataBlock, the DroidFileIdentifier and DroidVolumeIdentifier values resolve through this metadata file. Essential for cross-referencing "LNK file points at ObjectID X" → "file currently at MFT entry Y on volume Z."

## Cross-references
- **ShellLNK** — TrackerDataBlock Droid fields point here
- **JumpList-Embedded-LNK** — same
- **MFT** — ObjId entries join on file MFT reference
