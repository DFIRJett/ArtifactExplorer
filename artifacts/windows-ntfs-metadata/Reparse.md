---
name: Reparse
aliases:
- $Reparse
- NTFS reparse points
- symlink / junction catalog
link: file
tags:
- system-wide
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: $Extend\$Reparse
substrate-hub: NTFS Metadata
platform:
  windows:
    min: XP
    max: '11'
location:
  path: <root>\$Extend\$Reparse
  addressing: NTFS-metadata-file
fields:
- name: reparse-index-entry
  kind: record
  location: $R index inside $Reparse
  note: per-reparse-point entry — reparse tag + MFT entry reference + data pointer
- name: reparse-tag
  kind: flag
  location: reparse-index-entry → Tag
  note: identifies reparse-point type — IO_REPARSE_TAG_SYMLINK (0xA000000C), IO_REPARSE_TAG_MOUNT_POINT (0xA0000003), IO_REPARSE_TAG_DEDUP (0x80000013), IO_REPARSE_TAG_CLOUD (0x9000001A for OneDrive placeholders), IO_REPARSE_TAG_WOF (0x80000017 for Windows Overlay / compressed files)
- name: referenced-mft
  kind: identifier
  location: reparse-index-entry → FileReference
  references-data:
  - concept: MFTEntryReference
    role: referencedFile
- name: target-path
  kind: path
  location: the reparse point's REPARSE_DATA_BUFFER in the referenced file
  note: actual symlink/junction target, dedup reference, or cloud placeholder path
observations:
- proposition: FILESYSTEM_INDIRECTION
  ceiling: C2
  note: Catalog of every reparse point on the volume. Reveals junction/symlink targets, dedup stubs, OneDrive placeholder files, and Windows Overlay compressed files.
  qualifier-map:
    object.mft.reference: field:referenced-mft
    object.reparse.tag: field:reparse-tag
    object.target.path: field:target-path
anti-forensic:
  write-privilege: kernel-only
  known-attacks:
  - symlink-redirection for TOCTOU / privilege escalation via mount-point abuse
  - hidden-directory redirection via unprivileged junctions to system paths
provenance:
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
---

# $Reparse

## Forensic value
Centralized catalog of every reparse point on an NTFS volume. Reparse points are NTFS's generic indirection mechanism — used by:

- **Symbolic links** (`mklink`) — arbitrary path indirection, user-space
- **Junctions** (`mklink /J`) — directory-level, same-volume
- **Volume mount points** — drive-letter-less volume mounts
- **NTFS Deduplication** — dedup stubs replacing original file content
- **OneDrive Files-On-Demand** — cloud placeholder files; tag 0x9000001A + custom payload
- **Windows Overlay Filter (WOF)** — Windows 10 compressed-files feature
- **CI (Code Integrity)** — WDAC catalog references (rare)

Without $Reparse, an examiner has to walk every MFT entry looking for IS_REPARSE_POINT flags. With $Reparse, the catalog is immediate.

## OneDrive placeholder files
Modern forensic concern: a "file" visible in a user's OneDrive folder may be a reparse-point placeholder with no local content. Tag 0x9000001A with payload indicating cloud-only residence. Mishandling (e.g., copying the placeholder but not the content) loses data. Check $Reparse for cloud tags before assuming `dir` output represents full file state.

## Dedup caveat
Servers running Windows Data Deduplication have thousands of dedup reparse points. Their true content lives in `\System Volume Information\Dedup\ChunkStore`. An image acquired without the chunk store will fail to resolve dedup reparse points to file content.

## Tag decoding
Microsoft publishes the reparse-tag list in the WDK headers (`ntifs.h`) — `IO_REPARSE_TAG_*` constants. MFTECmd decodes them with human-readable names. Unrecognized tags in $Reparse are a forensic anomaly worth investigating (custom filter drivers).

## Cross-references
- **MFT** — per-file reparse-point flag + REPARSE_DATA_BUFFER
- **ObjId** — object-ID catalog, complementary volume-scoped index

## Practice hint
```
fsutil reparsepoint query <path>
```
queries a single reparse point on a live system. For offline enumeration, MFTECmd with `--rp` flag (if available) or INDXParse.py against $Reparse.
