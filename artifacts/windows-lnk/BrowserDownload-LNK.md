---
name: BrowserDownload-LNK
aliases: [downloaded LNK, LNK in Downloads folder]
link: file
tags: [per-user, phishing-indicator]
volatility: persistent
interaction-required: user-action
substrate: windows-lnk
substrate-instance: Downloads-folder
substrate-hub: User scope
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%USERPROFILE%\\Downloads\\*.lnk (and other user-selected download dirs)"
  addressing: filesystem-path
fields:
- name: target-path
  kind: path
  location: LNK LinkTargetIDList / LinkInfo LocalBasePath
  references-data:
  - {concept: ExecutablePath, role: configuredPersistence}
- name: arguments
  kind: command
  location: LNK StringData.CommandLineArguments
  note: "arguments — key phishing indicator. A downloaded .lnk whose target is a LOLBin (powershell.exe, mshta.exe, cmd.exe) with a long argument string is a near-certain malicious-LNK"
- name: icon-path
  kind: path
  location: LNK StringData.IconLocation
  note: "attackers mismatch icon vs target (PDF icon + powershell.exe target) to deceive users"
- name: tracker-machine-id
  kind: identifier
  location: LNK TrackerDataBlock → MachineID
  references-data:
  - {concept: MachineNetBIOS, role: trackerMachineId}
- name: zone-identifier
  kind: ads
  location: "Zone.Identifier:$DATA stream on the .lnk file itself"
  note: "MotW stamped by the browser at download time; ZoneId=3 = Internet"
- name: volume-serial
  kind: identifier
  location: embedded ShellLNK → LinkInfo\VolumeID\VolumeSerialNumber
  encoding: uint32-le (hex display)
  references-data:
  - concept: FilesystemVolumeSerial
    role: accessedAtSerial
  note: inherited from the embedded ShellLNK structure — attributes the LNK to a specific volume VSN at the moment of link creation
observations:
- proposition: PHISHING_ARTIFACT
  ceiling: C3
  note: "A .lnk file in a download location is almost always delivered via phishing — LNK is not a natural download artifact."
  qualifier-map:
    object.file.path: field:target-path
    object.command: field:arguments
anti-forensic:
  write-privilege: user
provenance: []
---

# BrowserDownload-LNK

## Forensic value
LNK files arriving via download are a malicious-delivery signature. Users rarely download shortcuts; attackers do because LNK supports arbitrary command execution with a custom icon. Pair with Zone-Identifier-ADS for origin URL.

## Cross-references
- **Zone-Identifier-ADS** — Mark-of-the-Web on the .lnk confirms download origin
- **Chrome-Downloads** / **Edge-History** — browser record of the download event
- **Defender-1116** — SmartScreen may have flagged the LNK at download
- **Recent-LNK** — if the user opened it, Recent-LNK records the target access
