---
name: TRANSACTED_FILE_OPERATION
summary: "Per-operation chronology of NTFS file actions via the MFT + $LogFile + $UsnJrnl triad (Cowen 2013 Triforce methodology)."
yields:
  mode: new-proposition
  proposition: TRANSACTED_FILE_OPERATION
  ceiling: C4
  casey-rationale: "Three independent subsystems record each NTFS file operation — the MFT record itself, the $LogFile transaction log, and the $UsnJrnl change journal. When all three agree on an operation (type + time + target record), the claim is C4 anti-tamper-hard because compromising one log does not affect the other two. Disagreement or single-witness observations drop to C3."
inputs:
  - OBSERVED_FILESYSTEM_CHANGE
input-sources:
  - proposition: OBSERVED_FILESYSTEM_CHANGE
    artifacts:
      - MFT
      - UsnJrnl
      - LogFile
join-chain:
  - concept: MFTEntryReference
    join-strength: strong
    sources:
      - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
      - carrier-2005-file-system-forensic-analysis
      - ms-ntfs-on-disk-format-secure-system-f
    primary-source: ms-ntfs-on-disk-format-secure-system-f
    description: |
      MFT entry reference ({record-number, sequence-number} pair) is the
      globally-unique identifier for an NTFS file across the Triforce. MFT
      records each file's current state keyed by this reference; $UsnJrnl
      USN_RECORD entries include the FileReferenceNumber for every
      operation; $LogFile transaction records name the target MFT entry
      being mutated. Without this pivot, the three sources would report
      operations on "some file" — with it, they report operations on THE
      SAME file, enabling the three-witness agreement that produces C4.
    artifacts-and-roles:
      - artifact: MFT
        role: referencedFile
      - artifact: UsnJrnl
        role: referencedFile
      - artifact: LogFile
        role: referencedFile
  - concept: FILETIME100ns
    join-strength: moderate
    sources:
      - carrier-2005-file-system-forensic-analysis
      - ms-ntfs-on-disk-format-secure-system-f
    primary-source: ms-ntfs-on-disk-format-secure-system-f
    description: |
      Timestamp is the secondary pivot — each witness timestamps the same
      operation independently. MFT $SI/$FN record kernel-written times
      for the current file state; $UsnJrnl USN_RECORD carries TimeStamp
      per operation; $LogFile records transaction completion times.
      Agreement on operation time (within 100ns FILETIME resolution)
      strengthens the Triforce claim; disagreement on time but agreement
      on MFT reference is a timestomp indicator (MFT times rewritten,
      journals not). Moderate strength because precision differs across
      witnesses and timestamps are the easiest field to selectively tamper.
    artifacts-and-roles:
      - artifact: MFT
        role: ordered-operation
      - artifact: UsnJrnl
        role: ordered-operation
      - artifact: LogFile
        role: ordered-operation
exit-node:
  - MFT
  - UsnJrnl
  - LogFile
via-artifacts: []
notes:
  - "MFT: provides the file's current record state + LogFileSequenceNumber (LSN) pointer into the $LogFile transaction chain (header offset 0x08). $SI/$FN timestamps give current time state; the LSN ties this record to its last transaction."
  - "$LogFile ($LogFile metafile, MFT entry 2): transaction log of every filesystem operation at the redo/undo granularity. Records are structured as log records containing before-image + after-image data for the affected MFT record. Retention is typically hours to days on a busy volume; transaction records circle out as newer entries overwrite. When present, authoritative for 'what did this operation look like' per-transaction."
  - "UsnJrnl ($UsnJrnl:\\$J stream on NTFS): per-record change journal. Emits a USN_RECORD entry for every create / delete / rename / modify / security-change / ADS-operation. Reason flags (USN_REASON_*) enumerate the operation type. Retention is longer than $LogFile (weeks on typical volumes, months on less-active ones). Authoritative for 'what operations happened in order' per-record."
  - "Triforce correlation (Cowen 2013 HECFBlog): when the MFT record's LSN chain, the $LogFile transaction record for that LSN, and the $UsnJrnl RecordNumber for the same operation all agree on operation-type + timestamp + target, the observation reaches C4. One tampered witness cannot move the conclusion; two must be compromised simultaneously (not a realistic attacker model on a live system)."
  - "Degradation: when $LogFile has rolled but $UsnJrnl retains the operation, claim drops to C3 — same witness-count as $MFT + $UsnJrnl agreement (two independent subsystems, but $MFT reflects only the CURRENT state, not the operation sequence). When only $UsnJrnl survives (attacker overwrote MFT timestamps, $LogFile rolled), claim is C2 — single-subsystem recollection."
provenance:
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - carrier-2005-file-system-forensic-analysis
  - ms-ntfs-on-disk-format-secure-system-f
---

# Convergence — TRANSACTED_FILE_OPERATION

Tier-2 convergence yielding proposition `TRANSACTED_FILE_OPERATION`.

Captures **per-operation chronology** of NTFS file actions — distinct from `HAD_FILE` (existence at a point) and `DELETED` (terminal state). The Triforce correlation pattern (Cowen 2013) triangulates across three independent NTFS structures: the `$MFT` record, the `$LogFile` transaction log, and the `$UsnJrnl:$J` change journal.

Participating artifacts: MFT, UsnJrnl, LogFile.

## Why this convergence exists

NTFS records filesystem operations in three independent places, each with different retention and tampering profiles. A forensic question like *"when was this file renamed, and by which transaction?"* can be answered from any one of them with different confidence levels, and from the combination with near-kernel-level certainty.

## Operations covered

| Operation | MFT signal | $LogFile signal | $UsnJrnl signal |
|-----------|-----------|------------------|------------------|
| Create | New record with `in-use=1` + `$FN.create` timestamp | log record, redo="create record" | `USN_REASON_FILE_CREATE` |
| Rename / move | Parent-MFT-reference change in `$FN`; new `$FN` attribute added at target | log record, redo="rename" + old-name + new-name | `USN_REASON_RENAME_OLD_NAME` + `USN_REASON_RENAME_NEW_NAME` |
| Data write | `$SI.modified` + `$SI.mftChange` update | log record, redo="data write" | `USN_REASON_DATA_OVERWRITE` or `_APPEND` |
| Delete | `in-use=0` + sequence# retained | log record, redo="delete record" | `USN_REASON_FILE_DELETE` + `USN_REASON_CLOSE` |
| Security change | `$STANDARD_INFO.SecurityId` change | log record, redo="change security-id" | `USN_REASON_SECURITY_CHANGE` |
| ADS create | New `$DATA` attribute named | log record, redo="add attribute" | `USN_REASON_STREAM_CHANGE` |

## Anti-forensic resistance

Triforce correlation was specifically identified by Cowen as the pattern adversaries fail to fully erase. SetMace, timestomp, `sdelete`, and `cipher /w` all target the MFT state but leave $UsnJrnl RecordNumbers behind. `fsutil usn deletejournal` removes the journal but creates a conspicuous `USN_REASON_DELETE_JOURNAL` terminal record. Selective `$LogFile` edits require kernel-mode access (FltMgr bypass or offline image manipulation).

**Survival-signal hierarchy:**
- All three agree → C4 (exit-node terminus on all three)
- Any two agree, third rolled-out / untrustworthy → C3
- Only $UsnJrnl survives → C2, operation sequence intact but no transaction-level corroboration
- Only $MFT current-state → C1-C2 depending on timestomp-detection signal

## Training-canon relevance

Core FOR500/FOR508 content. The Triforce analysis pipeline (Cowen's TriforceANJP, EnCase Triforce module, or hand-correlation via MFTECmd + LogFileParser + UsnJrnl2Csv) is tier-3 analyst-standard methodology.

## Cross-references

- Cowen 2013 HECFBlog Triforce series — canonical reference (lead queued in `back_propagation` for eventual source registration; Cowen's writeups not currently in the source registry)
- Each artifact's own body documents its own structure; this convergence documents the **reasoning across the three**.
- Pairs downstream with `DELETED` (terminal) and `HAD_FILE` (existence) convergences — the three form a minimal filesystem-investigation T2 trio.
