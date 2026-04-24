---
name: Extend-Quota
aliases: ["$Extend\\$Quota", NTFS per-user disk quota]
link: user
tags: [system-wide, per-user-attribution]
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: $Extend\$Quota
substrate-hub: NTFS Metadata
platform:
  windows: {min: '2000', max: '11'}
  note: "quota feature must be enabled on the volume — off by default on most consumer installs"
location:
  path: "<root>\\$Extend\\$Quota"
  addressing: NTFS-metadata-file
fields:
- name: owner-sid
  kind: identifier
  location: $Q quota index → per-SID entry
  references-data:
  - {concept: UserSID, role: identitySubject}
- name: bytes-used
  kind: size
  location: per-SID quota entry → BytesUsed
  note: "total bytes owned by this SID on this volume"
- name: quota-limit
  kind: size
  location: per-SID quota entry → QuotaLimit
- name: last-change-time
  kind: timestamp
  location: per-SID entry → ChangeTime
  encoding: filetime-le
observations:
- proposition: PER_USER_DISK_USAGE
  ceiling: C3
  note: "Per-SID disk usage count on the volume. Rarely-enabled feature but authoritative when present — correlates a SID to owned bytes, independent of per-file owner ACLs."
  qualifier-map:
    actor.user.sid: field:owner-sid
    object.bytes.used: field:bytes-used
anti-forensic:
  write-privilege: kernel-only
provenance:
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
---

# $Extend\$Quota

## Forensic value
When NTFS disk-quota is enabled, this metadata file maintains per-SID byte counts for every user with owned files on the volume. Each SID's `bytes-used` is a summary-level claim: "this SID owns N bytes on this volume." Useful for attributing bulk-storage activity without walking every file's ACL.

## Cross-references
- **SAM** / **ProfileList** — translate the SID to a human account
- **MFT** — per-file $STANDARD_INFORMATION owner SID (finer grain than Quota's rollup)
