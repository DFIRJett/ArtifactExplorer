---
name: I30-Index
aliases:
- $I30
- NTFS directory index slack
- INDEX_ALLOCATION
link: file
tags:
- system-wide
- slack-recovery
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: $I30 (per-directory)
substrate-hub: NTFS Core
platform:
  windows:
    min: XP
    max: '11'
location:
  path: each directory MFT entry → $INDEX_ALLOCATION attribute (named ':$I30')
  addressing: NTFS-directory-internal
fields:
- name: index-entry
  kind: record
  location: $I30 node
  note: each allocated entry is a directory listing — filename, MFT reference, $SI and $FN timestamps, file size, attribute flags
- name: filename
  kind: label
  location: index-entry → FileName field
- name: referenced-mft
  kind: identifier
  location: index-entry → FileReference (pre-filename field)
  note: MFT reference of the file/subfolder this entry points at
  references-data:
  - concept: MFTEntryReference
    role: referencedFile
- name: parent-directory
  kind: identifier
  location: parent MFT entry owning this $I30
  references-data:
  - concept: MFTEntryReference
    role: parentDirectory
- name: $SI-timestamps
  kind: timestamps
  location: index-entry → StandardInformation timestamps
  encoding: filetime-le
  note: snapshot of the referenced file's $SI times AT THE MOMENT the index was written
- name: $FN-timestamps
  kind: timestamps
  location: index-entry → FileName timestamps
  encoding: filetime-le
  note: snapshot of $FN times at the moment of the last rename/creation
- name: slack-entry
  kind: record
  location: space between end-of-used-entries and end-of-$I30-node
  note: THE forensic payoff — deleted filenames + their timestamps remain intact in slack until the node is rebalanced by B-tree operations
observations:
- proposition: HISTORICAL_FILE_PRESENCE
  ceiling: C2
  note: Pre-eminent slack-recovery target. Filenames of deleted entries survive in $I30 slack long after $MFT cells are reallocated.
  qualifier-map:
    object.file.name: field:filename
    object.mft.reference: field:referenced-mft
    time.observed: field:$FN-timestamps (creation proxy)
anti-forensic:
  write-privilege: kernel-only
  known-cleaners:
  - tool: defragmenter (destroys slack ordering; filesystem rewrites indexes)
  - tool: chkdsk /f (may rebalance indexes on corruption)
provenance:
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
---

# $I30 Directory Index Slack

## Forensic value
NTFS directories are B-trees of `$INDEX_ALLOCATION` nodes. Each node is a fixed-size buffer (typically 4096 bytes) holding a list of directory entries. When entries are deleted or renamed, the entry is marked deallocated but the bytes are **NOT** zeroed — they remain in slack until a B-tree rebalance operation overwrites that region.

Result: deleted filenames + their $SI and $FN timestamps persist in $I30 slack long after the file's $MFT record has been reused for another file. This is one of the highest-value slack recoveries in NTFS forensics.

## What's recoverable
Each slack entry can yield:
- Full filename (Unicode)
- Referenced MFT entry number (pre-deletion)
- File-size at the moment of indexing
- $SI timestamps — approximation of when the file existed and was modified
- $FN timestamps — creation and rename history

Practical implication: a user deletes `secrets_q4.xlsx`. The MFT entry is reused quickly. But the containing folder's $I30 slack holds the filename + timestamps for weeks.

## Node coverage
Only directories with **many entries** get allocated $I30 nodes (small directories fit in the MFT entry's $INDEX_ROOT attribute). Focus recovery on large/heavily-used directories — Downloads, Desktop, Documents, `%APPDATA%\Microsoft\Windows\Recent`, browser profile directories.

## Parsers
- **MFTECmd** — with `--is-dir` carving option
- **INDXParse.py** (Willi Ballenthin)
- **inflatemft / Sleuth Kit istat -i raw $MFT** with $I30 stream inspection
- **X-Ways Forensics** — dedicated directory-index slack view

## Cross-references
- **MFT** — current-state view; what exists NOW
- **UsnJrnl** — change-journal view; WHAT happened
- **LogFile** — per-operation transactions

## Practice hint
On a test VM, create 100 files in a folder, delete half, then acquire the image. Parse the folder's $I30 with INDXParse.py — the deleted filenames remain visible long after $MFT has reused their records.
