---
name: MFTEntryReference
kind: identifier
lifetime: permanent
link-affinity: file
description: |
  The NTFS Master File Table identifier — a 64-bit value composed of a 48-bit
  entry (record) number and a 16-bit sequence number. Uniquely identifies a
  specific MFT record for the life of the filesystem, and can pivot to the
  $MFT artifact for complete lifecycle history of a file or folder.
canonical-format: "<entry>:<sequence>  (often written as '123:2' or hex 0x7B:0x02)"
aliases: [MFT-record, file-reference, MFT-segment-reference, FRN-sequence]
roles:
  - id: thisRecord
    description: "This MFT entry IS the record's own reference (MFT artifact primary identity)"
  - id: parentDirectory
    description: "MFT reference to the parent directory of the entity (path reconstruction)"
  - id: referencedFile
    description: "MFT reference captured by a shell artifact pointing at a specific file/folder"
  - id: targetFile
    description: "MFT reference captured as the target / object of a surrounding operation — clipboard drop, search crawl, copy-move destination"

known-containers:
  - ShellBags
  - ShellLNK
  - AutomaticDestinations
  - CustomDestinations
  - MFT
  - UsnJrnl
provenance:
  - carrier-2005-file-system-forensic-analysis
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
---

# MFT Entry Reference

## What it is
The NTFS $MFT indexes every file, folder, and metadata stream by a 64-bit identifier that combines:
- **Entry (record) number** — 48 bits. The row number in the $MFT. Persists for the life of the record.
- **Sequence number** — 16 bits. Incremented each time the record slot is reused (i.e., the entry is deleted and reallocated to a new file). Lets forensic tools tell whether two references point to the *same* file or to reuse of the same slot.

Together they form a unique pointer to a specific MFT record at a specific point in time.

## Forensic value
When a shell artifact (LNK, shellbag, jump list) captures an MFT entry reference, it preserves a **direct pointer into the filesystem's own metadata**. That means:

1. **Positive correlation with $MFT.** The shell artifact's MFT reference can be matched against the current $MFT. Match + sequence agreement = same file. Match + sequence mismatch = slot reuse (file was deleted, another created in its place).
2. **Deletion detection.** If a shell artifact references MFT entry 12345:2 and the current $MFT shows that entry as 12345:3 pointing to a different filename, you know the original file was deleted between the shell artifact's creation and acquisition.
3. **File survival beyond name.** If the filename was renamed but the MFT record persists, the MFT reference stays stable — the shell artifact still points at the correct file.

## Encoding variations

| Artifact | Where |
|---|---|
| ShellBags | inside folder-type shell items (0x31) embedded in BagMRU numbered values |
| ShellLNK | inside folder/file shell items in LinkTargetIDList; also ExtensionBlock v3 |
| AutomaticDestinations | inside the embedded LNK-format entries per DestList entry |
| CustomDestinations | inside each pinned LNK-format entry |
| $MFT | the $MFT's own record numbering is the source of truth |

## Known quirks
- **Sequence number starts at 1, not 0.** A newly-created MFT record has sequence 1. Sequence 0 is invalid / uninitialized.
- **Deleted records retain their entry number** until the slot is reused — so a reference to a deleted file's MFT entry still resolves to the same $MFT row (useful for deleted-file recovery via shell artifacts).
- **Parser output format varies:** decimal vs. hex, colon vs. dash, with or without leading zeros. Normalize before cross-artifact matching.
