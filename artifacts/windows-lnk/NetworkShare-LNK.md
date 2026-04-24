---
name: NetworkShare-LNK
aliases: [UNC-target LNK, network-share shortcut]
link: network
tags: [per-user, lateral-movement-indicator]
volatility: persistent
interaction-required: user-action
substrate: windows-lnk
substrate-instance: UNC-target-LNK
substrate-hub: User scope
platform:
  windows: {min: XP, max: '11'}
location:
  path: "any *.lnk whose LinkInfo.LocalBasePath is empty and NetworkPath is populated"
  addressing: filesystem-path
fields:
- name: unc-target
  kind: path
  location: LNK LinkInfo.CommonNetworkRelativeLink.NetName + NetworkPath
  note: "\\\\server\\share\\path — UNC target. Survives target-server disappearance."
- name: tracker-machine-id
  kind: identifier
  location: LNK TrackerDataBlock → MachineID
  note: "MachineID of the HOST that CREATED the LNK, not the target server. Reveals cross-host LNK movement."
  references-data:
  - {concept: MachineNetBIOS, role: trackerMachineId}
- name: droid-volume-id
  kind: identifier
  location: LNK TrackerDataBlock → DroidVolumeIdentifier
  note: "NTFS ObjectID of the target's parent volume — joins with $ObjId artifact if the target server is in scope"
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
- proposition: USER_ACCESSED_SHARE
  ceiling: C3
  note: "LNK with UNC target preserves cross-host file-access intent. Attacker-created LNK pointing at attacker-controlled share is a classic persistence/phishing vector."
  qualifier-map:
    object.share.path: field:unc-target
    actor.machine.netbios: field:tracker-machine-id
anti-forensic:
  write-privilege: user
provenance: []
---

# NetworkShare-LNK

## Forensic value
Any LNK file whose target is a UNC path rather than a local drive. Strong lateral-movement / remote-share indicator. The LNK persists even after the server is gone — historical record of UNC access intent.

## Cross-references
- **Security-5140** — target-side share-access audit
- **MountPoints2** — user-scope mapping of network shares
- **TypedPaths** — UNC typed into Explorer address bar
