---
name: LogFile-T-Stream
title-description: "NTFS $LogFile:$T companion stream — metadata for the NTFS transaction log"
aliases:
- $LogFile $T
- LogFile T stream
- NTFS log metadata
link: file
tags:
- filesystem-metadata
- transaction-journal
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: LogFile-T-Stream
substrate-hub: Streams
platform:
  windows:
    min: NT4.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  path: "<volume>\\$LogFile:$T (NTFS system file stream, MFT entry 2 alternate data stream)"
  companion: "<volume>\\$LogFile (the main NTFS transaction log — separate artifact LogFile)"
  addressing: file-path + NTFS alternate-data-stream
  note: "The NTFS $LogFile system file has two streams. The default / unnamed stream is the actual transaction-log data ($LogFile's main stream — covered as the LogFile artifact). The $T stream is a companion metadata stream used by NTFS internals for log-state / restart-area bookkeeping. Tools like MFTECmd / libfsntfs expose it separately. For DFIR this artifact is mostly supporting context — parsing the main $LogFile data correctly sometimes requires knowing where restart records and LSN bookmarks live, which the $T stream carries. Not commonly a direct evidentiary pivot but occasionally necessary for accurate transaction-log replay."
fields:
- name: log-metadata-blob
  kind: content
  location: "$T stream body"
  encoding: NTFS-proprietary binary (reverse-engineered by libfsntfs / libtsk)
  note: "Binary blob carrying NTFS log-state metadata including restart-area references and LSN bookmarks. Format is not publicly documented by Microsoft; community parsers handle it. Directly inspectable in hex but meaningful only in context with the main $LogFile stream."
- name: log-stream-coupling
  kind: identifier
  location: "implicit — $T is coupled to the parent $LogFile by its alternate-data-stream nature"
  note: "The $T stream cannot be acquired independently — it lives on MFT entry 2 as an ADS of $LogFile. Correct acquisition captures both streams together. Accidentally acquiring only the default $LogFile data stream misses $T."
- name: stream-size
  kind: counter
  location: "$T stream size"
  encoding: uint64
  note: "Stream size is small relative to the main $LogFile (which is typically 64 MB default). $T is a few KB to tens of KB."
observations:
- proposition: FILESYSTEM_METADATA
  ceiling: C2
  note: 'The $LogFile:$T stream is a companion / supporting artifact
    for NTFS transaction-log forensics. By itself it is not
    evidentiary — it carries internal bookkeeping metadata. For
    investigators the main value is acquisition-hygiene: when
    capturing $LogFile for log-analysis replay, include $T so the
    parser can correctly interpret restart areas and LSN bookmarks.
    Omitting $T can produce parser warnings or incorrect timeline
    reconstruction from the main log data.'
  qualifier-map:
    setting.file: "<volume>\\$LogFile:$T"
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: NTFS internals
  survival-signals:
  - Any image missing $T when $LogFile is present = incomplete acquisition
provenance: [libyal-libfsntfs-libfsntfs-ntfs-extended-attrib]
---

# NTFS $LogFile:$T Companion Stream

## Forensic value
`$LogFile` (MFT entry 2) has two streams:
- Default (unnamed) — the transaction log data itself (primary DFIR artifact — covered as LogFile)
- `$T` — companion metadata (this artifact)

$T carries NTFS-internal bookkeeping (restart-area references, LSN bookmarks). Not typically a direct evidentiary pivot, but required for complete acquisition — parsers need both streams for correct transaction-log replay.

## Why to author this as a distinct artifact
KAPE, MFTECmd, and libfsntfs all surface $T as a separate stream. Analysts who acquire only the default $LogFile stream miss $T and may get parser warnings on transaction-log replay. Listing this as a distinct artifact ensures acquisition procedures capture both.

## Concept reference
- None direct — metadata-only artifact.

## Cross-reference
- **LogFile** — the main $LogFile stream (primary artifact)
- **UsnJrnl** + **UsnJrnl-Max-Stream** — sibling NTFS journal pair

## Practice hint
Acquire $LogFile from a disk image using libfsntfs. Verify both streams are present: `fsntfsinfo` should show the default stream AND the `$T` named stream sizes. If only the default stream was captured, re-acquire with a tool that handles ADS.
