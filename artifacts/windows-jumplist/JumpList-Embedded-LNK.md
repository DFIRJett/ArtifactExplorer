---
name: JumpList-Embedded-LNK
aliases: [jump-list LNK stream, embedded LNK inside AutomaticDestinations]
link: file
tags: [per-user]
volatility: persistent
interaction-required: user-action
substrate: windows-jumplist
substrate-instance: AutomaticDestinations-LNK-stream
substrate-hub: User scope
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\<AppID>.automaticDestinations-ms → per-entry LNK streams"
  note: "each DestList entry has a sibling stream named by the hex of the entry-number, holding a full ShellLNK blob"
  addressing: OLE2-CFB-stream
fields:
- name: lnk-blob
  kind: content
  location: CFB stream per entry
  note: "full ShellLNK structure — every field of the LNK substrate applies: target path, volume IDs, TrackerDataBlock, etc."
  references-data:
  - {concept: MFTEntryReference, role: referencedFile}
- name: target-machine
  kind: identifier
  location: embedded LNK → TrackerDataBlock → MachineID
  references-data:
  - {concept: MachineNetBIOS, role: trackerMachineId}
- name: target-volume
  kind: identifier
  location: embedded LNK → LinkInfo.VolumeID + VolumeSerialNumber
  references-data:
  - {concept: VolumeGUID, role: accessedVolume}
- name: target-volume-serial
  kind: identifier
  location: embedded LNK → LinkInfo.VolumeID.VolumeSerialNumber
  references-data:
  - {concept: FilesystemVolumeSerial, role: accessedAtSerial}
- name: target-volume-label
  kind: label
  location: embedded LNK → LinkInfo.VolumeID.VolumeLabel
  references-data:
  - {concept: VolumeLabel, role: accessedAtLabel}
observations:
- proposition: USER_OPENED_FILE_ON_VOLUME
  ceiling: C3
  note: "Each embedded LNK inside a jump list is a full ShellLNK. Carries all the LNK cross-host / cross-volume metadata including TrackerDataBlock MachineID and VolumeID chain."
  qualifier-map:
    object.file.mft: field:lnk-blob
    object.volume.guid: field:target-volume
    object.host.netbios: field:target-machine
anti-forensic:
  write-privilege: user
provenance:
  - libyal-libolecf
  - ms-cfb
---

# JumpList-Embedded-LNK

## Forensic value
Each DestList entry in an AutomaticDestinations file has a companion CFB stream containing a full ShellLNK blob. Embedded LNKs survive Explorer's "Clear Recent" (which only targets %APPDATA%\...\Recent\*.lnk) and carry all the cross-host / cross-volume attribution data.

## Cross-references
- **ShellLNK** — format spec; same structure
- **JumpList-DestList-Entry** — index entry referring to this stream
- **Recent-LNK** — parallel file-system LNK (often gets cleaned while this survives)
