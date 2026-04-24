---
name: JumpList-AppID-Mapping
aliases: [AppID to human-name resolver]
link: application
tags: [per-user, name-resolution]
volatility: persistent
interaction-required: user-action
substrate: windows-jumplist
substrate-instance: AppID-mapping
substrate-hub: User scope
platform:
  windows: {min: '7', max: '11'}
location:
  path-registry: "NTUSER.DAT\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache — also HKLM\\SOFTWARE\\Classes\\Applications — also hardcoded Microsoft AppID list"
  addressing: indirect-registry-plus-static-map
fields:
- name: appid
  kind: identifier
  location: "value name in MuiCache / AutomaticDestinations filename / TaskbarLayout"
  encoding: "16-char uppercase hex (CRC64 of AppUserModelID)"
  references-data:
  - {concept: AppID, role: muiCachedApp}
- name: friendly-name
  kind: label
  location: MuiCache value data (FriendlyAppName_<appid>)
  type: REG_SZ
  note: "human-readable app name rendered by Windows — resolves otherwise-opaque hex AppIDs"
observations:
- proposition: APPID_HUMAN_NAME
  ceiling: C3
  note: "Jump list filenames are anonymous 16-char hex AppIDs. This mapping resolves them to human-readable app names. Without it, jump-list forensics reads 'F01B4D95CF55D32A had activity' instead of 'Microsoft Word had activity'."
  qualifier-map:
    object.appid: field:appid
    object.app.name: field:friendly-name
anti-forensic:
  write-privilege: user
provenance: []
---

# JumpList AppID → Name Mapping

## Forensic value
Jump-list filenames are 16-char hex AppIDs — CRC64 of the app's AppUserModelID. Reading jump-list forensics productively requires resolving those hex strings to human app names. Sources consulted in order:
1. Hardcoded Microsoft AppID list (for system-shipped apps)
2. `NTUSER.DAT\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache` values prefixed `FriendlyAppName_`
3. `HKLM\SOFTWARE\Classes\Applications\<exe>\FriendlyAppName`

## Cross-references
- **AutomaticDestinations** / **CustomDestinations** — the jump-list files themselves
- **TaskbarLayout** — pinned-app AppID list
- **MUICache** — complementary per-app display-name store
