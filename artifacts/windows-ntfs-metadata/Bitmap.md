---
name: Bitmap
aliases: ["$Bitmap", cluster allocation bitmap]
link: file
tags: [system-wide, tamper-hard]
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: $Bitmap
substrate-hub: NTFS Metadata
platform:
  windows: {min: XP, max: '11'}
location:
  path: "<root>\\$Bitmap"
  addressing: NTFS-metadata-file
fields:
- name: cluster-state
  kind: flags
  location: "each bit = one volume cluster; 1=allocated, 0=free"
  note: "volume_size_bytes / cluster_size / 8 bytes long; parses to a per-cluster allocation map"
- name: file-mft-reference
  kind: identifier
  location: $Bitmap MFT record (entry 6)
  references-data:
  - {concept: MFTEntryReference, role: thisRecord}
observations:
- proposition: CLUSTER_ALLOCATION_STATE
  ceiling: C3
  note: "Authoritative map of which volume clusters are allocated. Required for carving unallocated space (where deleted-file recovery happens) — a cluster marked free is a candidate for salvage."
  qualifier-map:
    object.volume.alloc-map: field:cluster-state
anti-forensic:
  write-privilege: kernel-only
provenance:
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
---

# $Bitmap

## Forensic value
NTFS's cluster-allocation map — one bit per cluster on the volume. Gives the authoritative free-vs-used space picture. Carving tools consult $Bitmap to identify unallocated regions worth scanning for deleted-file content.

## Cross-references
- **MFT** — files declare their cluster runs in $DATA attributes; compare against $Bitmap for carve opportunities
- **LogFile** — bitmap changes are journaled; $LogFile can surface recent allocate/free operations pre-commit
- **I30-Index** — directory slack recovery complements unallocated-cluster carving
