---
name: MFT
aliases:
- $MFT
- Master File Table
- NTFS MFT record
- MFT entry
link: file
tags:
- timestamp-carrying
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: $MFT
substrate-hub: NTFS Core
platform:
  windows:
    min: NT4
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  filesystem: NTFS volume
  file: $MFT (special NTFS metafile at root of volume)
  addressing: mft-entry-number + sequence-number
fields:
- name: mft-entry-number
  kind: counter
  location: position in $MFT — 48-bit record index
  encoding: uint48-le
- name: sequence-number
  kind: counter
  location: FILE record header — incremented on record reuse
  encoding: uint16-le
- name: mft-entry-reference
  kind: identifier
  location: composed from entry-number + sequence-number
  encoding: 64-bit packed (entry:sequence)
  references-data:
  - concept: MFTEntryReference
    role: thisRecord
- name: logfile-sequence-number
  kind: identifier
  location: FILE record header — offset 0x08, 8-byte LSN
  encoding: uint64-le
  note: "Points to the last $LogFile transaction affecting this record. Enables the Triforce correlation pattern (Cowen HECFBlog) — MFT record LSN links directly into the $LogFile transaction chain, which in turn cross-references $UsnJrnl RecordNumbers for that transaction. Gives full transaction-level change history for any file."
- name: hard-link-count
  kind: counter
  location: FILE record header — offset 0x12
  encoding: uint16-le
  note: number of directory entries referencing this record. >1 means hard-linked file (common for system DLLs and some installer-managed files); 0 on deleted records after unlink.
- name: base-record-reference
  kind: identifier
  location: FILE record header — offset 0x20
  encoding: 64-bit packed (entry:sequence)
  note: "Zero if this IS a base record. Non-zero if this is an extension record whose base lives elsewhere — set when a file's attributes overflow a single 1024-byte MFT record and spill into extension records linked via $ATTRIBUTE_LIST. When parsing, always check this before interpreting a record standalone."
- name: filename-namespace
  kind: flags
  location: $FILE_NAME attribute — Namespace byte
  encoding: uint8
  note: "0 = POSIX (case-sensitive, any-char), 1 = Win32 (case-insensitive Unicode), 2 = DOS (8.3 short name), 3 = Win32+DOS (combined). Files with a Win32 long filename and a DOS 8.3 alias have TWO $FILE_NAME attributes — one with namespace=1, one with namespace=2. Forensic consequence: parsers that stop after the first $FILE_NAME miss the alias; investigations looking for obfuscated short-name references need to enumerate ALL $FILE_NAME attributes per record."
- name: record-header-signature
  kind: identifier
  location: first 4 bytes of MFT record
  encoding: '''FILE'' FOURCC (deleted records may show ''BAAD'' if corrupted)'
- name: in-use-flag
  kind: flags
  location: MFT header flags field
  encoding: uint16-bitfield
  note: 0x01 = record in use, 0x02 = directory; absence of 0x01 = deleted
- name: si-created
  kind: timestamp
  location: $STANDARD_INFORMATION attribute — CreationTime
  encoding: filetime-le
  clock: system
  resolution: 100ns
  references-data:
  - concept: FILETIME100ns
    role: absoluteTimestamp
- name: si-modified
  kind: timestamp
  location: $STANDARD_INFORMATION — LastModificationTime
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: si-accessed
  kind: timestamp
  location: $STANDARD_INFORMATION — LastAccessTime
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: atime updates may be disabled via NtfsDisableLastAccessUpdate registry — default varies by Windows version
- name: si-mft-changed
  kind: timestamp
  location: $STANDARD_INFORMATION — LastMftChangeTime
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: MFT-record metadata change time — updates on any $MFT attribute change, even without file content change
- name: fn-created
  kind: timestamp
  location: $FILE_NAME attribute — CreationTime
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: harder to forge than $SI timestamps — requires kernel-level access
- name: fn-modified
  kind: timestamp
  location: $FILE_NAME — LastModificationTime
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: fn-accessed
  kind: timestamp
  location: $FILE_NAME — LastAccessTime
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: fn-mft-changed
  kind: timestamp
  location: $FILE_NAME — LastMftChangeTime
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: filename
  kind: identifier
  location: $FILE_NAME — FileNameLength + FileName
  encoding: utf-16le
- name: parent-mft-reference
  kind: identifier
  location: $FILE_NAME — ParentDirectory field
  encoding: 64-bit packed (entry:sequence)
  references-data:
  - concept: MFTEntryReference
    role: parentDirectory
  note: references the PARENT DIRECTORY's MFT record — walk these to reconstruct full path
- name: allocated-size
  kind: counter
  location: $DATA attribute — allocated size
  encoding: uint64
- name: real-size
  kind: counter
  location: $DATA attribute — real size
  encoding: uint64
- name: is-resident-data
  kind: flags
  location: $DATA attribute non-resident flag
  encoding: bit-flag
  note: small files (<~700 bytes) have $DATA resident within the MFT record itself; larger files reference external clusters
- name: security-id
  kind: identifier
  location: $STANDARD_INFORMATION — SecurityId (link to $Secure metafile)
  encoding: uint32
- name: file-attributes
  kind: flags
  location: $STANDARD_INFORMATION — FileAttributes
  encoding: uint32-bitfield
  note: READONLY, HIDDEN, SYSTEM, DIRECTORY, ARCHIVE, etc. (standard DOS attributes)
observations:
- proposition: EXISTS
  ceiling: C4
  note: MFT is the authoritative filesystem ground-truth. Near-highest ceiling for file-existence claims; kernel maintains
    the MFT directly.
  qualifier-map:
    entity.filename: field:filename
    entity.parent-ref: field:parent-mft-reference
    entity.mft-reference: field:mft-entry-reference
    entity.size: field:real-size
    time.created: field:fn-created
    time.modified: field:fn-modified
  preconditions:
  - $MFT acquired from raw disk image (not live-system queries)
  - no evidence of timestomp against $SI (compare $SI vs $FN)
- proposition: CREATED
  ceiling: C4
  qualifier-map:
    object.path: reconstructed from parent-chain + filename
    time.start: field:fn-created
  preconditions:
  - same as EXISTS
- proposition: MODIFIED
  ceiling: C3
  qualifier-map:
    object.path: reconstructed
    time.start: field:si-modified
  note: $SI.modified is the obvious source but is user-writable; cross-check with $FN.modified for anti-tamper confirmation
- proposition: DELETED
  ceiling: C3
  note: DELETED is inferred from `in-use-flag == 0` — record exists but flagged free
  qualifier-map:
    object.mft-reference: field:mft-entry-reference
    time.start: field:si-mft-changed
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: record fixup + log journaling ($LogFile)
  known-cleaners:
  - tool: timestomp
    typically-removes: partial
    note: modifies $SI timestamps but NOT $FN — mismatch is the detection cue
  - tool: SetMace
    typically-removes: partial
    note: "Currently the only PUBLIC tool that modifies $FN timestamps directly (via kernel-level write). Most timestomp tools only touch $SI and leave $FN as a canary; SetMace closes that gap. However, SetMace has its own tell: post-modification $FN timestamps often still don't MATCH $SI (setter error-tolerances differ), leaving a residual mismatch for detection. Kernel-level execution also requires SeTcbPrivilege / Driver-signing-disabled, which constrains deployment."
  - tool: rename-or-move-trick
    typically-removes: partial
    note: "$SI/$FN copy-on-rename escape: if attacker timestomps $SI and then RENAMES or MOVES the file, Windows copies the (stomped) $SI values into a NEW $FN attribute at the rename target. The old $FN disappears with the old directory entry. Net effect: both $SI and $FN now show the fake time; detection via $SI/$FN comparison no longer works. Detect via alternative signals — LogFileSequenceNumber chain through $LogFile, $UsnJrnl RENAME records, or the nanosecond-precision pattern below."
  - tool: sdelete (secure delete)
    typically-removes: partial
    note: overwrites data; MFT entry sequence increments on slot reuse — reveals historical delete
  - tool: wipe-disk
    typically-removes: full
  survival-signals:
  - $FN timestamps more recent than $SI = timestomp against $SI almost certain
  - $SI timestamps zeroed or at 2000-01-01 = default-zeroing wiper
  - MFT entry present with `in-use-flag == 0` + filename readable = deleted file, possibly recoverable
  - "Zero-nanosecond fractional pattern (Galhuber 2022 peer-reviewed, Univ. Vienna): legitimate OS file operations produce timestamps with varied nanosecond-precision fractional parts (the low-order 100ns ticks of FILETIME). Timestomp tools typically set timestamps to whole-second values (e.g., 2023-01-01 12:00:00.0000000), leaving zero-nanosecond fractions. Cluster of files in the same directory with zero-fractional $SI timestamps on otherwise legitimate-looking content is a strong timestomp signal. Survives the rename-trick above because the fractional zeros are retained through the copy."
cross-references:
  transaction-triad:
  - "LogFileSequenceNumber on this MFT record + matching $LogFile transaction record + $UsnJrnl RecordNumber for the same operation = full transaction-level change history (Triforce correlation, Cowen HECFBlog). When any of the three is tampered with, the other two remain as independent witnesses. When all three agree, the change claim is C4 anti-tamper-hard."
  known-siblings:
  - UsnJrnl
  - LogFile
  - I30-Index
  - Secure-SDS
provenance:
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
---

# $MFT (Master File Table)

## Forensic value
The single most authoritative filesystem artifact on Windows NTFS volumes. One MFT record per file or folder captures: 8 timestamps (4 per $SI + 4 per $FN), filename, parent directory MFT reference, size, allocated size, security descriptor reference, file attributes. Everything other artifacts claim about files ultimately traces back to $MFT records.

## Concept references
- MFTEntryReference — both THIS record's ref AND the parent directory's ref

## The dual-timestamp system — the reason $MFT is forensically special
Every file has TWO sets of 4 MAC(B) timestamps:
- **$STANDARD_INFORMATION** ($SI) — user-mode accessible; modified by touch-tools, timestomp, etc.
- **$FILE_NAME** ($FN) — kernel-mode only; much harder to forge

Canonical timestomp detection: $FN timestamps newer than $SI timestamps for the same record. Legitimate operations update $SI but NOT $FN (on most file ops), so $FN lagging is normal; $FN leading is diagnostic of tampering.

## Deleted records
When a file is deleted, its MFT record's `in-use-flag` bit is cleared but the record body (including filename, timestamps, data attribute) remains intact until the slot is reallocated. Sequence number increments on reallocation — a reference to a pre-delete sequence number can still resolve to evidence of the former file.

## Path reconstruction
Each record's `parent-mft-reference` points to the parent directory's MFT record. Walk the chain (entry → entry → ... → entry 5 (NTFS root `.`)) to reconstruct the full path. The build-graph pipeline doesn't do this automatically — it's case-time work.

## Practice hint
Image a small test volume. Parse $MFT with MFTECmd. Pick a known file, note its $SI and $FN timestamps. Touch the file (update mtime only via PowerShell `(Get-Item X).LastWriteTime = ...`) — re-parse, observe $SI.modified changed, $FN.modified unchanged. The invariant holds.
