---
name: Desktop-LNK
aliases: [Desktop shortcuts, user-placed LNK]
link: file
tags: [per-user, user-intent]
volatility: persistent
interaction-required: user-action
substrate: windows-lnk
substrate-instance: Desktop-folder
substrate-hub: User scope
platform:
  windows: {min: XP, max: '11'}
location:
  path-user: "%USERPROFILE%\\Desktop\\*.lnk"
  path-public: "%PUBLIC%\\Desktop\\*.lnk"
  addressing: filesystem-path
fields:
- name: target-path
  kind: path
  location: LNK LinkTargetIDList + LinkInfo LocalBasePath
  references-data:
  - {concept: ExecutablePath, role: configuredPersistence}
- name: arguments
  kind: command
  location: LNK StringData.CommandLineArguments
- name: tracker-machine-id
  kind: identifier
  location: LNK TrackerDataBlock → MachineID
  references-data:
  - {concept: MachineNetBIOS, role: trackerMachineId}
- name: lnk-file-mac
  kind: timestamps
  location: $MFT record of the .lnk file
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: volume-serial
  kind: identifier
  location: embedded ShellLNK → LinkInfo\VolumeID\VolumeSerialNumber
  encoding: uint32-le (hex display)
  references-data:
  - concept: FilesystemVolumeSerial
    role: accessedAtSerial
  note: inherited from the embedded ShellLNK structure — attributes the LNK to a specific volume VSN at the moment of link creation
observations:
- proposition: USER_PLACED_SHORTCUT
  ceiling: C3
  note: "Shortcuts users place on their own Desktop are high-intent — they represent targets the user wants one-click access to. Legitimate user shortcuts + attacker-dropped shortcuts with suspicious targets."
  qualifier-map:
    actor.user: owning profile
    object.target: field:target-path
    time.created: field:lnk-file-mac
anti-forensic:
  write-privilege: user
provenance: []
---

# Desktop-LNK

## Forensic value
Shortcuts that live on the user's Desktop. Generally user-placed intentionally — the target is something the user wants immediate access to. Attackers sometimes drop Desktop LNKs for social engineering (fake "Install" icons, fake document shortcuts pointing at LOLBins).

## Cross-references
- **Startup-LNK** — persistence-relevant sibling folder
- **Recent-LNK** — auto-populated file-access history
- **BrowserDownload-LNK** — downloaded-from-web counterpart
