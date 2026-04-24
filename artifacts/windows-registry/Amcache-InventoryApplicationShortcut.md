---
name: Amcache-InventoryApplicationShortcut
aliases:
- Amcache shortcut inventory
- Amcache Start Menu shortcuts
link: application
tags:
- timestamp-carrying
- persistence-adjacent
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: Amcache.hve
platform:
  windows:
    min: '10'
    max: '11'
location:
  hive: Amcache.hve
  path: Root\InventoryApplicationShortcut\<ShortcutID>
  addressing: hive+key-path
fields:
- name: shortcut-id
  kind: identifier
  location: subkey name
  note: hash of the shortcut's resolved target path
- name: ShortcutPath
  kind: path
  location: ShortcutPath value
  type: REG_SZ
  note: full filesystem path of the .lnk file itself
  references-data:
  - concept: ExecutablePath
    role: shellReference
- name: ShortcutTargetPath
  kind: path
  location: ShortcutTargetPath value
  type: REG_SZ
  note: resolved target of the shortcut — the executable the shortcut points at
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
- name: ShortcutName
  kind: label
  location: ShortcutName value
  type: REG_SZ
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: when the shortcut was inventoried (creation or modification observed)
observations:
- proposition: SHORTCUT_EXISTED
  ceiling: C2
  note: Evidence that a shortcut existed (or exists) at the listed path pointing at the listed target. Survives shortcut deletion in this registry-cached form. Complements windows-lnk container for shortcut forensics.
  qualifier-map:
    object.shortcut.path: field:ShortcutPath
    object.shortcut.target: field:ShortcutTargetPath
    time.observed: field:key-last-write
anti-forensic:
  write-privilege: admin
  known-cleaners:
  - tool: manual delete of shortcut + hive cleanup
    typically-removes: full (both needed)
  detection-signals:
  - shortcuts in Startup folders pointing at LOLBins (powershell.exe with args) — persistence drop
  - shortcut targets in %TEMP% / %APPDATA% / %PROGRAMDATA% root — malware drop
provenance: []
provenance: [libyal-libregf, regripper-plugins]
---

# Amcache-InventoryApplicationShortcut

## Forensic value
Amcache's catalog of every shortcut the OS inventoried. Because Amcache persists shortcut references in a registry-cached form, it retains **evidence of shortcuts that no longer exist** — an attacker who dropped a malicious Startup-folder .lnk, let it autorun, then deleted it may leave no .lnk on disk but an InventoryApplicationShortcut entry recording the shortcut's former target path.

## Cross-container pivot
This is the cleanest registry-to-filesystem shortcut cross-reference. Combine with the `windows-lnk` container's `Startup-LNK` / `Recent-LNK` artifacts:
- If shortcut still exists on disk → both artifacts corroborate
- If shortcut is gone but InventoryApplicationShortcut entry remains → cleaner missed the registry side

## Triage questions answered
- "What shortcuts were in the Startup folders historically?" — filter ShortcutPath by Startup paths
- "Where did a removed shortcut point?" — ShortcutTargetPath field
- "Any LOLBin targets with arguments?" — needs cross-reference to actual LNK parsing; InventoryApplicationShortcut has path + target but not command-line args

## Cross-references
- **Startup-LNK** / **Recent-LNK** (windows-lnk container) — the shortcuts themselves
- **Amcache-InventoryApplicationFile** — the target executable; joins via ShortcutTargetPath = LowerCaseLongPath
- **Run-Keys** — complementary registry-side persistence indicators

## Practice hint
AmcacheParser output file `*_InventoryApplicationShortcut.csv`. Filter for ShortcutPath containing "Startup" to surface logon-persistence candidates.
