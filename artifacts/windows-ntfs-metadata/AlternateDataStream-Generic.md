---
name: AlternateDataStream-Generic
aliases: [NTFS ADS, Named Data Stream, colon-suffix stream]
link: file
tags: [system-wide, tamper-hard]
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: "NTFS :NamedStream"
substrate-hub: Streams
platform:
  windows: {min: XP, max: '11'}
location:
  path: "any NTFS file → :$DATA:<StreamName> attribute"
  addressing: mft-attribute-named-stream
fields:
- name: host-file-path
  kind: path
  location: parent $FILE_NAME on the MFT entry
  references-data:
  - {concept: MFTEntryReference, role: referencedFile}
- name: stream-name
  kind: label
  location: "$DATA attribute name field (UTF-16LE after colon)"
  note: "user-visible form: filename:streamname. Zone.Identifier is the best-known; arbitrary names allowed."
- name: stream-size
  kind: size
  location: $DATA attribute header
- name: stream-content
  kind: content
  location: $DATA stream body
  note: "up to resident-size threshold stored in MFT; larger streams get non-resident cluster runs"
observations:
- proposition: DATA_HIDDEN_IN_ADS
  ceiling: C3
  note: "Arbitrary data attached to a file via named stream. Invisible to default-arg `dir` / Explorer; enumerates only with `dir /r` or ADS-aware tools. Historical data-hiding primitive AND legitimate Windows mechanism (MotW, thumbnails)."
  qualifier-map:
    object.file: field:host-file-path
    object.stream.name: field:stream-name
    object.stream.size: field:stream-size
anti-forensic:
  write-privilege: user
  known-cleaners:
  - {tool: "Remove-Item -Stream", typically-removes: single-stream}
provenance: [libyal-libfsntfs-libfsntfs-ntfs-extended-attrib, carrier-2005-file-system-forensic-analysis]
---

# NTFS Alternate Data Stream (generic)

## Forensic value
Any named data stream attached via NTFS's `filename:streamname` syntax. Zone-Identifier is the canonical forensic example, but arbitrary streams are a classic data-hiding primitive — default `dir` / Explorer don't show them, `dir /r` and `Get-Item -Stream *` do.

## Cross-references
- **Zone-Identifier-ADS** — the sibling specific-ADS artifact (Mark-of-the-Web)
- **MFT** — ADS attributes live on the host file's MFT record; enumerate via MFTECmd
- **Sysmon-15** (FileCreateStreamHash) — real-time ADS-write detection event
