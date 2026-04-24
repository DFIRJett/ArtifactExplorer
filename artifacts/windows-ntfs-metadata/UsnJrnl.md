---
name: UsnJrnl
aliases:
- $UsnJrnl
- $J stream
- USN Journal
- NTFS Change Journal
link: file
tags:
- timestamp-carrying
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: $Extend\$UsnJrnl:$J
substrate-hub: NTFS Core
platform:
  windows:
    min: '2000'
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  filesystem: NTFS volume
  ads-stream: $Extend\$UsnJrnl:$J (alternate data stream)
  addressing: stream record — USN (Update Sequence Number)
fields:
- name: usn
  kind: counter
  location: record header
  encoding: uint64
  note: monotonically increasing — serves as record identifier + chronological ordering
- name: file-reference
  kind: identifier
  location: record body
  encoding: entry:sequence (MFT file reference)
  references-data:
  - concept: MFTEntryReference
    role: referencedFile
- name: parent-file-reference
  kind: identifier
  location: record body
  encoding: entry:sequence
  references-data:
  - concept: MFTEntryReference
    role: parentDirectory
  note: parent directory at time of event — useful for path reconstruction of deleted files
- name: timestamp
  kind: timestamp
  location: record body
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: when the change event occurred — kernel-timestamped
- name: reason-flags
  kind: flags
  location: record body
  encoding: uint32-bitfield
  note: 'bitfield: DATA_OVERWRITE, DATA_EXTEND, DATA_TRUNCATION, NAMED_DATA_OVERWRITE, FILE_CREATE, FILE_DELETE, EA_CHANGE,
    SECURITY_CHANGE, RENAME_OLD_NAME, RENAME_NEW_NAME, INDEXABLE_CHANGE, BASIC_INFO_CHANGE, HARD_LINK_CHANGE, COMPRESSION_CHANGE,
    ENCRYPTION_CHANGE, OBJECT_ID_CHANGE, REPARSE_POINT_CHANGE, STREAM_CHANGE, CLOSE'
- name: source-info
  kind: flags
  location: record body
  encoding: uint32-bitfield
  note: bits indicating WHO caused the event (OS-initiated, replication, etc.) — mostly 0 for user activity
- name: filename
  kind: identifier
  location: record body
  encoding: utf-16le
  note: filename at the moment of the event — for rename events paired with OLD_NAME/NEW_NAME reason flags
- name: file-attributes
  kind: flags
  location: record body
  encoding: uint32-bitfield
observations:
- proposition: CREATED
  ceiling: C3
  note: record with FILE_CREATE reason flag = file creation event
  qualifier-map:
    object.mft-reference: field:file-reference
    object.filename: field:filename
    time.start: field:timestamp
- proposition: MODIFIED
  ceiling: C3
  note: DATA_OVERWRITE / DATA_EXTEND / DATA_TRUNCATION flags = content modification events
  qualifier-map:
    object.mft-reference: field:file-reference
    object.filename: field:filename
    time.start: field:timestamp
- proposition: DELETED
  ceiling: C3
  note: FILE_DELETE flag + usually followed by CLOSE = deletion event
  qualifier-map:
    object.mft-reference: field:file-reference
    object.filename: field:filename
    time.start: field:timestamp
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: USN counter monotonicity — gaps reveal edits
  known-cleaners:
  - tool: fsutil usn deletejournal
    typically-removes: full
    note: legitimate deletion via fsutil — detectable via Windows event logs (USN journal deleted admin action)
  - tool: raw-disk overwrite of $UsnJrnl:$J
    typically-removes: full
    note: advanced — requires kernel/admin raw access
  survival-signals:
  - USN gap (sequential records with USN jumps) = journal truncation OR selective overwrite
  - File appears in $MFT but no USN records for its creation = journal was rolled/truncated before analysis OR journal was
    never enabled (rare)
provenance:
  - libyal-libusnjrnl-usn-journal-format-max-header
  - ms-change-journal-record-header-fsctl
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - carrier-2005-file-system-forensic-analysis
  - jschicht-usnjrnl2csv-tool-docs
  - cowen-2013-hecfblog-ntfs-triforce
---

# $UsnJrnl:$J — NTFS Change Journal

## Forensic value
Rolling log of every file-metadata change on the volume, timestamped to 100ns precision. Each record captures: MFT file reference, parent MFT reference, filename, change type (create/delete/modify/rename/etc.), timestamp.

For file-lifecycle questions, $UsnJrnl is often the SECOND most important NTFS artifact after $MFT itself. $MFT tells you a file exists (or existed); $UsnJrnl tells you **every change that ever happened to it** within the journal retention window.

## Concept references
- MFTEntryReference — both for the file itself AND for its parent directory

## Storage detail
The journal is an alternate data stream ($J) under the $UsnJrnl special file, living under $Extend\. Records are variable-length; parsers walk the stream in USN-order.

Default retention is ~32MB of journal space, rolling. On a busy system, records age out within hours to days. On an idle system, records can persist for weeks. Acquire early.

## Key capabilities
1. **Delete-detection with filename recovery.** A FILE_DELETE record captures the filename EVEN AFTER the MFT record is gone. Combined with parent MFT reference, you reconstruct the full deleted path.
2. **Rename tracking.** RENAME_OLD_NAME + RENAME_NEW_NAME pair of records captures both filenames — detects rename-based evasion.
3. **Modification timelining.** Every content write emits DATA_OVERWRITE or DATA_EXTEND with timestamps. Build a per-file edit history.

## Acquisition
- Raw-disk image via FTK Imager / dd
- `fsutil usn readjournal C: > journal.dump` (live-system, requires admin)
- MFTECmd can extract and parse in one step: `MFTECmd.exe -f $J --csv out`

## Practice hint
Acquire $UsnJrnl from a small test volume. Filter records for a known filename — observe the full lifecycle chain (create → multiple modifies → delete). Each record's USN monotonically increases; gaps indicate missing coverage.
