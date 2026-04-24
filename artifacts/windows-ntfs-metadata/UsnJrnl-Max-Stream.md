---
name: UsnJrnl-Max-Stream
title-description: "NTFS $UsnJrnl:$Max stream — Update Sequence Number journal header / sizing metadata"
aliases:
- $UsnJrnl $Max
- USN journal header
- UsnJrnl Max stream
link: file
tags:
- filesystem-metadata
- journal-sizing
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: UsnJrnl-Max-Stream
substrate-hub: Streams
platform:
  windows:
    min: NT5.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  path: "<volume>\\$Extend\\$UsnJrnl:$Max"
  companion: "<volume>\\$Extend\\$UsnJrnl:$J (the actual journal data — separate artifact UsnJrnl)"
  addressing: file-path + NTFS alternate-data-stream
  note: "The $UsnJrnl NTFS system file has two streams: $J (the journal data — records of filesystem changes) and $Max (header / sizing metadata). This artifact covers $Max specifically because the sizing / rollover information it carries is distinct from the journal records themselves. $J is the primary DFIR pivot (and already covered as the UsnJrnl artifact); $Max supplies the context: how large the journal can grow, where it wraps, and what the logical vs physical boundaries are — critical for interpreting truncation patterns and rollover timing."
fields:
- name: maximum-size
  kind: counter
  location: "$Max header — MaximumSize field"
  encoding: uint64 le
  note: "Maximum journal size in bytes before Windows starts dropping the oldest records. Default varies by volume size but typically 32 MB (small volumes) to 128 MB (larger) to 1 GB (very large / server). Attacker-shrinking the journal (via fsutil usn createjournal with very small MaximumSize) forces rapid rollover and evidence loss without attracting the noise of a full journal delete."
- name: allocation-delta
  kind: counter
  location: "$Max header — AllocationDelta field"
  encoding: uint64 le
  note: "Increment added when the journal grows or rotates. Typically 8 MB. Controls granularity of rollover."
- name: usn-journal-id
  kind: identifier
  location: "$Max header — UsnJournalID field"
  encoding: filetime-le (64-bit)
  note: "Creation timestamp of the current journal instance. Changes ONLY when the journal is recreated (fsutil usn deletejournal followed by creation, or filesystem reformat). If UsnJournalID is significantly newer than the volume's $MFT creation time, the journal was reset post-volume-creation — possibly attacker action to wipe USN evidence."
- name: first-usn
  kind: counter
  location: "$Max header — FirstUsn / NextUsn fields"
  encoding: uint64 le
  note: "FirstUsn = the lowest USN still retrievable in $J (rollover boundary). NextUsn = the next USN to be written. Gap = records lost to rollover. Journal-size + activity-rate + FirstUsn gives a rough retention window for the journal."
- name: max-stream-size
  kind: counter
  location: "$Max stream total size"
  encoding: bytes
  note: "$Max is itself very small (~32 bytes for the header struct). The size is fixed; growth only occurs via header-structure changes across Windows versions."
observations:
- proposition: FILESYSTEM_SIZING
  ceiling: C2
  note: 'The $Max stream is a context / sizing artifact — not directly
    evidentiary on its own, but essential for interpreting the
    companion $J stream correctly. Forensic use: determine whether
    the journal has been tampered (fsutil deletejournal + create
    resets UsnJournalID), determine the retention window covered by
    the current $J, and detect attacker journal-shrink attempts
    (MaximumSize unusually low). Pair with the UsnJrnl ($J) artifact
    for complete journal forensics.'
  qualifier-map:
    setting.file: "<volume>\\$Extend\\$UsnJrnl:$Max"
    object.id: field:usn-journal-id
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: NTFS journaling
  known-cleaners:
  - tool: fsutil usn deletejournal /d <volume>
    typically-removes: both $Max and $J streams (new UsnJournalID on recreation)
  - tool: fsutil usn createjournal m=<small> a=<small> <volume>
    typically-removes: effective retention window (small MaximumSize = rapid rollover)
  survival-signals:
  - UsnJournalID timestamp much newer than volume MFT creation = journal was reset (evidence-destruction signal)
  - MaximumSize much smaller than Windows default for the volume size = attacker shrink
  - Gap between FirstUsn and earliest-expected-USN based on activity = rollover has discarded substantial recent history
provenance: [ms-change-journal-record-header-fsctl, libyal-libusnjrnl-usn-journal-format-max-header]
---

# UsnJrnl $Max Stream

## Forensic value
The NTFS USN journal (`$UsnJrnl` file in `$Extend`) has two streams:

- `$J` — the journal data (covered separately as UsnJrnl artifact)
- `$Max` — header / sizing metadata (this artifact)

`$Max` is a tiny fixed-size stream (~32 bytes) holding journal-level metadata:

- `MaximumSize` — configured upper bound before rollover
- `AllocationDelta` — growth increment
- `UsnJournalID` — creation timestamp of the current journal instance
- `FirstUsn` / `NextUsn` — rollover boundary + write pointer

Context for interpreting `$J`. Without `$Max`, you can read journal records but you can't confidently answer:
- "Is this the original journal or was it recreated?"
- "How far back does the journal go?"
- "Did rollover discard records in this window?"

## Concept reference
- None direct — metadata artifact supporting UsnJrnl.

## Parsing
Any NTFS-aware parser reading $Extend\$UsnJrnl exposes both streams. Tools: libusnjrnl, MFTECmd (EZTools), SleuthKit, FTK Imager.

## Cross-reference
- **UsnJrnl** ($J) — the actual change records
- **MFT** — creation time of the $UsnJrnl system file
- **LogFile** — NTFS log; independent journaling layer
- **Security-4688** — fsutil.exe process creation with deletejournal / createjournal arguments = tamper evidence

## Practice hint
On a lab NTFS volume: run `fsutil usn queryjournal C:` — the output fields correspond directly to $Max. Run `fsutil usn deletejournal /d C:` then `fsutil usn createjournal m=32768 a=32768 C:` — UsnJournalID updates to current time. The queryjournal vs historical $Max lets you detect this tamper.
