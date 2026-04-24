---
name: OfficeRecent-LNK
aliases: [Office Recent folder shortcuts]
link: file
tags: [per-user, office-scope]
volatility: persistent
interaction-required: user-action
substrate: windows-lnk
substrate-instance: Office-Recent-folder
substrate-hub: User scope
platform:
  windows: {min: XP, max: '11'}
location:
  path: "%APPDATA%\\Microsoft\\Office\\Recent\\*.lnk"
  addressing: filesystem-path
fields:
- name: target-path
  kind: path
  location: LNK LinkTargetIDList + LinkInfo LocalBasePath
  note: "document path opened through Office apps"
  references-data:
  - {concept: ExecutablePath, role: shellReference}
- name: tracker-machine-id
  kind: identifier
  location: LNK TrackerDataBlock → MachineID
  references-data:
  - {concept: MachineNetBIOS, role: trackerMachineId}
- name: target-volume
  kind: identifier
  location: LNK LinkInfo.VolumeID
  references-data:
  - {concept: VolumeGUID, role: accessedVolume}
- name: lnk-file-mac
  kind: timestamps
  location: $MFT of the .lnk file
  encoding: filetime-le
- name: volume-serial
  kind: identifier
  location: embedded ShellLNK → LinkInfo\VolumeID\VolumeSerialNumber
  encoding: uint32-le (hex display)
  references-data:
  - concept: FilesystemVolumeSerial
    role: accessedAtSerial
  note: inherited from the embedded ShellLNK structure — attributes the LNK to a specific volume VSN at the moment of link creation
observations:
- proposition: OFFICE_FILE_OPENED
  ceiling: C3
  note: "Office maintains its own Recent folder separate from the system Recent. These LNKs survive Explorer 'Clear Recent' and persist regardless of Office's own MRU-clear settings."
  qualifier-map:
    actor.user: profile owner
    object.file.path: field:target-path
    time.last_open: field:lnk-file-mac
anti-forensic:
  write-privilege: user
  known-cleaners:
  - {tool: Office 'Clear unpinned recent documents', typically-removes: partial — targets OfficeMRU registry, not these LNK files}
provenance: []
---

# OfficeRecent-LNK

## Forensic value
Office apps maintain a separate Recent folder at `%APPDATA%\Microsoft\Office\Recent\`. Each recently-opened document gets a LNK here, independent of the system Recent folder. Survives Explorer cleanups and Office's own MRU-clear (which targets the OfficeMRU registry, not these LNK files).

## Cross-references
- **OfficeMRU** — registry-side MRU list with per-entry timestamps
- **Recent-LNK** — system-wide Recent; overlap for files opened via default handler
- **RecentDocs** — per-extension MRU
