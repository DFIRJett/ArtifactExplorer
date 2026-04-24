---
name: DAM
aliases:
- Desktop Activity Moderator
- dam\State\UserSettings
link: application
tags:
- timestamp-carrying
- per-user
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: '8'
    max: '11'
    note: "DAM shipped with Connected Standby support in Windows 8 (per MS Learn Desktop Activity Moderator cookbook). Scope is desktop (Win32) apps — UWP apps are explicitly out of scope (they have their own PLM suspension). Forensically most common on Win10+ tablets/convertibles but the registry key can appear on any Connected-Standby-capable system back to Win8."
location:
  hive: SYSTEM
  path: ControlSet00x\Services\dam\State\UserSettings\<SID>
  addressing: hive+key-path
  variant-paths:
    legacy: SYSTEM\CurrentControlSet\Services\dam\UserSettings\<SID>\<path>
    current: SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\<SID>\<path>
  lookup-rule: "union query both paths; same migration pattern as BAM"
  presence-note: "DAM is typically EMPTY on non-Connected-Standby devices (most desktops / non-hybrid laptops). Populates on tablets, 2-in-1s, ARM devices."
fields:
- name: user-sid
  kind: identifier
  location: "per-SID subkey name under UserSettings"
  encoding: S-1-5-string
  references-data:
  - concept: UserSID
    role: actingUser
- name: executable-path
  kind: path
  location: "values named by full EXE path under each SID subkey"
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: ranProcess
- name: last-executed-time
  kind: timestamp
  location: value data (first 8 bytes)
  type: REG_BINARY
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: on each tracked foreground execution under Connected-Standby
observations:
- proposition: EXECUTED
  ceiling: C3
  note: "Desktop Activity Moderator — BAM's sibling subsystem for Connected-Standby / tablet state. Records per-user executable foreground time + last-run timestamp."
  qualifier-map:
    actor.user.sid: field:user-sid
    object.process.path: field:executable-path
    time.last: field:last-executed-time
anti-forensic:
  write-privilege: unknown
provenance: []
---

# DAM (Desktop Activity Moderator)

## Forensic value
BAM's tablet / modern-standby sibling. Same schema: per-SID subkey under the dam service's UserSettings, values named by executable path, value data carrying a FILETIME. Present only on systems that support Connected Standby (most modern laptops / tablets). DAM captures execution events that BAM misses during S0-low-power states.

## Cross-references
Corroborates with BAM: same (SID, ExecutablePath) pair appearing in both is independent confirmation of foreground use. Registry ImagePath tampering in one can be detected if the other disagrees.
