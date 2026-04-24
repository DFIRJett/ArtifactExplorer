---
name: Secure-SDS
title-description: "NTFS $Secure:$SDS stream — the per-file security descriptor (ACL) store on an NTFS volume"
aliases:
- $Secure $SDS
- Security Descriptor Stream
- NTFS ACL store
link: file
tags:
- acl-history
- tamper-signal
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: Secure-SDS
substrate-hub: NTFS Metadata
platform:
  windows:
    min: NT4.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  path: "<volume>\\$Secure:$SDS (NTFS system file, MFT entry 9)"
  siblings: "$Secure:$SII (security-ID index) + $Secure:$SDH (security-descriptor-hash index)"
  addressing: file-path + NTFS alternate-data-stream
  note: "On NTFS, file security descriptors (SDs) are NOT stored with each file's MFT entry. Instead, the volume maintains a shared security-descriptor stream at $Secure:$SDS — one stream, one volume, holding the UNIQUE SDs used across the entire volume. Each file's MFT $STANDARD_INFORMATION attribute holds a SecurityId (uint32) that indexes into $Secure. Two companion indexes ($SII sorted by SecurityId, $SDH sorted by SD hash) enable lookup. For DFIR: $Secure:$SDS holds every DISTINCT security descriptor ever applied on the volume, even those no longer referenced by any live file — deleted-file-ACL recovery window. Pair with MFT analysis to recover 'what ACL did this file have before it was deleted or its ACL changed.'"
fields:
- name: security-descriptor-blob
  kind: content
  location: "$SDS stream at SecurityId-referenced offset"
  encoding: Windows security descriptor binary format (SELF_RELATIVE_SECURITY_DESCRIPTOR)
  note: "Each record: header (hash + SecurityId + offset + size) + SELF_RELATIVE_SECURITY_DESCRIPTOR blob (Owner SID + Group SID + DACL + SACL). Blob can be parsed to recover per-file ACL. Since $SDS holds UNIQUE SDs, many files typically share one record (common ACLs for user-profile subtrees, Program Files, etc.)."
- name: security-id
  kind: identifier
  location: "MFT $STANDARD_INFORMATION attribute → SecurityId field (uint32)"
  encoding: uint32 le
  note: "Per-MFT-entry index into $SDS. MFT entry's SecurityId joined to $SDS record produces the file's ACL. When a file's ACL is changed, Windows may allocate a new SecurityId + append new $SDS record — the OLD SD may remain in $SDS until the volume reuses the space. DFIR recovery: compare MFT entry's current SecurityId to historical values (if archived) OR scan $SDS for SIDs matching incident-relevant accounts."
- name: sd-hash
  kind: hash
  location: "$SDS record header → SD hash"
  encoding: SHA-1 hash of the descriptor
  note: "Used for deduplication — Windows hashes each new SD and consults $SDH index to reuse an existing SDS record when hash matches. Not typically a DFIR pivot directly but confirms a given SD is shared across multiple files."
- name: orphaned-sd
  kind: content
  location: "$SDS records with no corresponding SecurityId in the live MFT"
  note: "SDs that no file currently references — but still in $SDS. These are ACL history: SDs that were applied to files that have been deleted OR had their ACL changed. Scanning orphan SDs recovers deleted-file-ACLs (including the attacker user that owned them) that no longer exist in the live filesystem."
- name: owner-sid
  kind: identifier
  location: "inside SD blob — Owner SID field"
  encoding: SID binary
  references-data:
  - concept: UserSID
    role: identitySubject
  note: "SID of the file owner at SD-write time. Recovering historical owner SIDs from $SDS lets analysts identify which users created / owned specific files (including deleted ones). An attacker SID owning files in an unexpected directory = evidence of their prior activity."
- name: dacl-aces
  kind: content
  location: "inside SD blob — DACL → per-ACE Trustee SID + access mask"
  note: "Access Control Entries granting / denying access. Historical ACL reconstruction from $SDS reveals e.g., 'Everyone Full Control' ACLs that an attacker applied to stage a file-share attack, even if those ACLs have since been normalized."
- name: file-volume-stream
  kind: content
  location: "NTFS volume $Secure file — accessed via raw NTFS read, not standard file API"
  note: "Access requires NTFS-level file reader (dd / FTK Imager / libtsk). Standard Windows APIs can't expose this stream directly."
observations:
- proposition: HAD_FILE
  ceiling: C3
  note: 'The NTFS $Secure:$SDS stream is the volume-wide store of every
    security descriptor ever applied on the filesystem. For DFIR,
    this is primarily an ACL-history artifact: recover the ACL and
    owner of files that were deleted, or whose ACL was changed, by
    scanning orphan SDs that no MFT entry currently references. Pair
    with MFT + UsnJrnl for full ACL-change timeline reconstruction.
    Distinct from other NTFS forensic artifacts because $Secure
    centralizes ACL data — one stream per volume, not per-file —
    making it a uniquely compact source of historical access-control
    evidence.'
  qualifier-map:
    object.owner: field:owner-sid
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: NTFS journaling + MFT consistency
  known-cleaners:
  - tool: "defrag / volume-rewrite"
    typically-removes: orphan $SDS records (new $SDS allocation may overwrite)
  survival-signals:
  - $Secure:$SDS records with Owner SIDs of users who no longer exist in SAM + unusual ACLs = historical anomaly worth ACL-change investigation
  - Orphan $SDS records with recent offsets = deleted/modified-file ACLs from recent window
provenance:
  - ms-ntfs-on-disk-format-secure-system-f
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
exit-node:
  is-terminus: true
  primary-source: libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  attribution-sentence: 'The $Secure metadata file contains the security descriptors used for access control (Metz, 2021).'
  terminates:
    - CONTROLLED_ACCESS
  sources:
    - ms-ntfs-on-disk-format-secure-system-f
    - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  reasoning: >-
    $SDS records bind each security-descriptor-ID to an explicit Owner SID
    and full DACL. Because NTFS security-descriptors are content-addressed
    by security-id and never deleted when files reference them, the owner-SID
    field directly terminates CONTROLLED_ACCESS (principal, object) without
    requiring cross-artifact resolution.
  implications: >-
    Filesystem-to-principal binding survives file rename, file move, and
    file deletion (orphan $SDS entries preserve historical ACLs). Analysts
    investigating unauthorized-access or privilege-escalation cases can
    prove ownership/permission grants at the filesystem layer even after
    attacker modifies visible file metadata. Cross-validates audit events
    (Security-4656/4663) at a lower layer.
  identifier-terminals-referenced:
    - UserSID
---

# NTFS $Secure:$SDS

## Forensic value
NTFS does NOT store per-file security descriptors (ACLs) with each file's MFT entry. Instead, the volume maintains `$Secure` (MFT entry 9) — a system file with three streams:

- `$SDS` — the security-descriptor data stream (blob store)
- `$SII` — index sorted by SecurityId
- `$SDH` — index sorted by SD hash

Each file's MFT $STANDARD_INFORMATION has a `SecurityId` that indexes into `$Secure:$SDS` to retrieve the file's actual ACL.

## ACL-history recovery
Because `$Secure:$SDS` is append-only (within volume lifetime, absent defrag), SDs that were once applied but are no longer referenced remain as **orphan records**. These represent:

- Deleted files' ACLs
- Files whose ACL was changed (old SD orphaned, new SD created)

Scanning orphan SDs recovers historical access-control evidence unavailable from the live MFT.

## Concept reference
- UserSID (Owner SID within each SD blob)

## Parsing
Requires raw NTFS reading — standard file APIs can't expose `$Secure:$SDS`. Tools:
- `libfsntfs` (Joachim Metz) — open-source
- FTK Imager — GUI browse of NTFS system files
- MFTECmd (Eric Zimmerman) — partial support
- `fls` / `icat` from The Sleuth Kit — raw NTFS read

## Cross-reference
- **MFT** — SecurityId linking each MFT entry to $SDS record
- **UsnJrnl** — USN_REASON_SECURITY_CHANGE records document ACL-change events
- **Security-4670** EVTX event — Permissions on an object were changed

## Practice hint
Obtain an NTFS disk image. Use libfsntfs or FTK Imager to browse to `$Secure` (volume root, typically MFT entry 9). Extract the `$SDS` stream. Parse for SELF_RELATIVE_SECURITY_DESCRIPTOR records — inspect Owner SID and DACL entries. Compare SecurityIds in live MFT against $SDS record list — orphan records reveal historical ACLs.
