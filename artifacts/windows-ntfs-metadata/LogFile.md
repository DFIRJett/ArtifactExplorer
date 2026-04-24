---
name: LogFile
aliases:
- $LogFile
- NTFS transaction log
link: file
tags:
- system-wide
- tamper-hard
- transient
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: $LogFile
substrate-hub: NTFS Core
platform:
  windows:
    min: XP
    max: '11'
location:
  path: <root-of-NTFS-volume>\$LogFile
  addressing: NTFS-metadata-file
fields:
- name: restart-area
  kind: state
  location: first N bytes of $LogFile
  note: checkpoint metadata — last-flushed LSN, active transaction list
- name: log-record
  kind: record
  location: $LogFile body (circular buffer)
  note: per-transaction redo+undo pair recording a single NTFS metadata change (MFT entry update, directory-index insert, attribute list update, etc.)
- name: redo-op
  kind: opcode
  location: log-record → RedoOperation
  note: SetNewAttributeSizes / CreateAttribute / DeleteAttribute / SetBitsInNonresidentBitMap / OpenNonresidentAttribute / AddIndexEntryRoot / DeleteIndexEntryAllocation / ...
- name: undo-op
  kind: opcode
  location: log-record → UndoOperation
- name: lsn
  kind: counter
  location: log-record header → LSN
  note: monotonically-increasing log sequence number; provides strict ordering of filesystem operations
- name: target-file-reference
  kind: identifier
  location: log-record referenced MFT entry
  note: the $MFT record this transaction acted upon
  references-data:
  - concept: MFTEntryReference
    role: referencedFile
- name: transaction-scope
  kind: state
  location: transaction table in restart area
  note: groups related log records; partial transactions on a dirty volume are the recovery target
observations:
- proposition: FILESYSTEM_OPERATION_RECENT
  ceiling: C3
  note: Per-transaction record of recent NTFS metadata changes. Provides operation-level detail that $MFT alone cannot — an MFT entry reflects current state; $LogFile shows how it got there.
  qualifier-map:
    object.mft.reference: field:target-file-reference
    object.operation: field:redo-op
    time.order: field:lsn
anti-forensic:
  write-privilege: kernel-only
  circular-buffer-overwrite: oldest records evicted as new activity fills the log
  known-cleaners:
  - tool: "FSUTIL usn deletejournal /D C: then /N (unrelated to $LogFile, often confused)"
    typically-removes: "target is $UsnJrnl NOT $LogFile — $LogFile size is controlled by chkdsk /l, not user-deletable"
  detection-signals:
    - incomplete transactions in restart area indicate unclean dismount OR forensic-acquisition-in-flight
provenance:
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
---

# $LogFile

## Forensic value
NTFS's transaction journal. Every change to NTFS **metadata** (not file content) generates a pair of redo/undo log records before the change is committed. The filesystem uses $LogFile to recover after a crash; forensically, $LogFile is the **operation-level history of recent metadata activity**.

Key distinction:
- **$MFT** = current state of every file
- **$UsnJrnl:$J** = high-level summary of *what* changed (file renamed, deleted, modified)
- **$LogFile** = low-level *how* — the actual NTFS-internal transactions

## Triforce methodology
David Cowen's "NTFS Triforce" cross-references $MFT + $LogFile + $UsnJrnl to reconstruct filesystem history with more fidelity than any alone:
- $MFT gives the file's current state and its timestamps.
- $UsnJrnl gives the sequence of high-level operations.
- $LogFile gives the per-transaction record chain that produced those operations.

When timestomping is suspected, $LogFile can reveal the original MFT entry state pre-modification because the undo record of the SetNewAttributeSizes / SetNewAttributes transaction captures the pre-values.

## Capacity + retention
Default size is 64MB per volume (tunable via `chkdsk /l`). Circular: oldest transactions are overwritten as new activity fills. Busy volumes evict in hours; quiet volumes retain weeks. High-value forensic artifacts often live here for a limited window — acquire early.

## Dirty-file caveat
A clean-dismounted $LogFile has all transactions flushed (undo records discarded). A dirty/in-flight $LogFile has active transactions in the restart area — those are the juiciest records because they carry pre-modification state.

## Parsers
- **LogFileParser** (Joakim Schicht / `jschicht` on GitHub) — the dedicated $LogFile parser. Outputs structured CSV/TSV records of NTFS transaction-log entries. Part of Schicht's NTFS-forensics tool suite alongside Mft2Csv and UsnJrnl2Csv. Not related to LECmd (that's a separate Zimmerman tool for LNK files).
- **MFTECmd** (Eric Zimmerman) — use with `-f <path-to-LogFile> --jf` switches for $LogFile extraction. This is Zimmerman's correct tool for $LogFile (NOT LECmd which is an LNK parser, NOR RECmd which is Registry Explorer).
- **NTFS-Log-Tracker** (Cho & Rogers / Fitalk slides reference)
- **libfsntfs** (Joachim Metz) — format-correct read access; documents LFS_RESTART_PAGE_HEADER + record layout
- **TriforceANJP** (David Cowen / HECFBlog) — correlates $LogFile with $MFT + $UsnJrnl for full transaction chain reconstruction

## Cross-references
- **MFT** / **UsnJrnl** — the Triforce trio
- **Security-4663** — object-access audit hits for the same files, if SACL set

## Practice hint
On a test VM, create/modify/delete files and acquire $LogFile via FTK Imager immediately. Parse with LogFileParser and trace per-file LSN sequences to see the actual NTFS transaction chain.
