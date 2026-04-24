---
name: ShellBags
aliases:
- Shell bags
- BagMRU
- Shell view-state history
link: file
tags:
- timestamp-carrying
- tamper-easy
- per-user
- recency-presence
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: UsrClass.dat
substrate-hub: User scope
platform:
  windows:
    min: XP
    max: '11'
  windows-server:
    min: '2003'
    max: '2022'
location:
  hive: UsrClass.dat
  path: Local Settings\Software\Microsoft\Windows\Shell\BagMRU  +  Local Settings\Software\Microsoft\Windows\Shell\Bags
  addressing: hive+key-path
  also-present-in:
    legacy: NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU (and \Bags)  — pre-Win7 primary; retained on Win7+ for compat
fields:
- name: bag-tree-hierarchy
  kind: path
  location: BagMRU subkey tree — each subkey = one folder level, numbered-value children = that folder's subfolders ordered
    by first-browse
  encoding: registry-subkey-hierarchy
  note: reconstructing the full browse path requires walking BagMRU from root and decoding each shell-item
- name: shell-item-binary
  kind: path
  location: BagMRU\<path>\<value-name-number>
  type: REG_BINARY
  encoding: shell-item-binary
  note: one shell item per value (numbered 0, 1, 2...); type byte at offset 2 determines which further fields are present
  references-data:
  - concept: VolumeGUID
    role: accessedVolume
  - concept: VolumeLabel
    role: accessedAtLabel
  - concept: FilesystemVolumeSerial
    role: accessedAtSerial
  - concept: MFTEntryReference
    role: referencedFile
  - concept: PIDL
    role: browsedItem
- name: shell-item-type
  kind: enum
  location: shell-item-binary byte offset 2
  encoding: uint8
  note: 0x1F=root, 0x20-2F=drive/volume, 0x30-3F=folder/file, 0x40-4F=network, 0x70=control panel
- name: folder-short-name
  kind: identifier
  location: shell-item (type 0x31) — 8.3 name field
  encoding: ASCII or UTF-16LE per item flags
  note: legacy 8.3 name; see folder-long-name for full filename from ExtensionBlock
- name: folder-long-name
  kind: identifier
  location: shell-item (type 0x31) ExtensionBlock v3+
  encoding: utf-16le
- name: folder-mft-reference
  kind: identifier
  location: shell-item (type 0x31) — MFT entry + sequence fields
  encoding: entry:sequence (6B entry + 2B sequence from shell-item body)
  references-data:
  - concept: MFTEntryReference
    role: referencedFile
  note: NTFS only; FAT-formatted volumes produce shell items without this field
- name: folder-created-time
  kind: timestamp
  location: shell-item (type 0x31) ExtensionBlock — $SI Created
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: frozen snapshot of folder's creation time at the moment the user first browsed into it
- name: folder-accessed-time
  kind: timestamp
  location: shell-item (type 0x31) ExtensionBlock — $SI Accessed
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: folder-modified-time
  kind: timestamp
  location: shell-item (type 0x31) ExtensionBlock — $SI Modified
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: drive-letter
  kind: identifier
  location: shell-item (type 0x20-0x2F) — drive letter segment
  encoding: ascii
- name: volume-label
  kind: identifier
  location: shell-item (drive/volume type) — volume label
  encoding: ASCII or UTF-16LE per item flags
  references-data:
  - concept: VolumeLabel
    role: accessedAtLabel
- name: volume-fs-serial
  kind: identifier
  location: shell-item (drive type) — 32-bit serial
  encoding: uint32-le
  references-data:
  - concept: FilesystemVolumeSerial
    role: accessedAtSerial
- name: volume-guid
  kind: identifier
  location: shell-item (volume-type) — Mount-Manager GUID
  encoding: guid-string
  references-data:
  - concept: VolumeGUID
    role: accessedVolume
  note: present for volume-scoped shell items; distinguishes removable/network volumes
- name: network-unc-path
  kind: path
  location: shell-item (type 0x40-0x4F) — UNC path to network resource
  encoding: utf-16le OR ascii
- name: node-slot
  kind: identifier
  location: BagMRU\<path>\NodeSlot value
  type: REG_DWORD
  note: index into Bags\<N> key that holds this folder's view-state preferences
- name: mru-list-ex
  kind: counter
  location: BagMRU\<path>\MRUListEx value
  type: REG_BINARY
  encoding: array of uint32-le — children sorted most-recent-first
  note: defines the order children were most recently accessed; first entry = most recent subfolder browsed
- name: key-last-write
  kind: timestamp
  location: BagMRU\<path> key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: updated when a new child is added under this BagMRU key (user browsed a new subfolder)
  note: approximates 'time user last explored a new subfolder here' — not 'time user opened this folder'
observations:
- proposition: ACCESSED
  ceiling: C3
  note: 'Per-user folder-browse history. Each BagMRU branch proves the owning

    user navigated Explorer into that folder at least once. Frozen folder

    MAC times at the moment of first browse. Cross-volume (USB, network)

    browses are captured here with volume identity — often the strongest

    evidence for access to folders on removable/network media.

    '
  qualifier-map:
    object.path: reconstructed from shell-item chain (drive → folder → ... → folder)
    object.volume-guid: field:volume-guid
    object.volume-label: field:volume-label
    object.volume-serial: field:volume-fs-serial
    object.mft-reference: field:folder-mft-reference
    actor.user: derived from NTUSER/UsrClass hive owner via ProfileList
    time.start: field:key-last-write
  preconditions:
  - UsrClass.dat transaction logs replayed
  - Hive is original (not transplanted) — verify via ProfileList SID match
  - For removable/network path claims, corroborate with MountPoints2 or the removable-media convergence chain
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: CCleaner
    typically-removes: partial
    note: may clear some BagMRU entries; often misses UsrClass.dat vs NTUSER.DAT distinction
  - tool: manual reg-delete
    typically-removes: surgical
  - tool: Explorer "Reset folders" in Folder Options
    typically-removes: full
    note: clears Bags view-state but not BagMRU navigation history
  survival-signals:
  - ShellBags references a volume-GUID absent from MountedDevices = user browsed a removable volume whose registry trail was
    cleaned, but the bag survived
  - ShellBags MFT entry reference points to $MFT record with higher sequence number = the folder was deleted and the slot
    reused
  - ShellBags volume-fs-serial ≠ current volume-fs-serial for same volume-label = the volume was reformatted since the browse
provenance:
  - libyal-libfwsi
  - matrix-dt020-shellbags-usb
  - matrix-dt086-shellbags-network
  - winreg-kb-most-recently-used
  - regripper-plugins
  - artefacts-help-repo
  - sans-lo-2014-shellbag-forensics-in-depth
  - sans-tilbury-2011-windows-7-shellbags
---

# ShellBags

## Forensic value
The single richest per-user folder-navigation record on Windows. Whenever a user opens Explorer and navigates into a folder — local, removable, or network — Windows creates a BagMRU entry capturing the folder's identity, MAC times at that moment, and its position in the navigation chain. The Bags\<N> side separately stores the user's view preferences for that folder (icon size, sort order, column widths).

ShellBags uniquely captures:
- **Folder browses that don't leave other traces** — user clicks into E:\Payroll\2024 but never opens a file inside, no LNK is created, no Office MRU, no jump list entry. ShellBags records it.
- **Removable and network path histories** — volume GUIDs, labels, UNC paths all preserved with the shell-item chain.
- **MFT entries of browsed folders** — direct pivot to $MFT records (current or historical via sequence-number mismatch).
- **Frozen MAC times of folders at browse time** — folder was created/modified/accessed *then*, timestamps don't refresh.

## Four concept references
- VolumeGUID — from volume-type shell items (removable / network volumes)
- VolumeLabel — from drive/volume shell items
- FilesystemVolumeSerial — from drive-type shell items
- MFTEntryReference — from folder-type shell items on NTFS volumes

## Known quirks / silent-failure modes
- **Two locations on Win7+.** UsrClass.dat is primary; NTUSER.DAT retains a legacy copy for compatibility. Forensic tools should parse both. NTUSER.DAT shellbags are often *older* data than UsrClass.dat on modern systems — historical navigation preserved.
- **`key-last-write` is NOT "user opened this folder."** It's updated when a NEW child is added to this BagMRU key. Opening an already-browsed subfolder again doesn't update the parent's LastWrite.
- **MRUListEx ordering != browse order.** It's most-recent-child-first among the parent's children, but "most recent" means "most recently added as a new child" not "most recently browsed."
- **Parser version matters for shell-item extensions.** Different Windows versions introduced different ExtensionBlock signatures (v3 for Win7, v7+ for Win8+, v9 for Win10+). Old parsers miss extension data on newer systems.
- **CPC namespace keys under MountPoints2** (mentioned in other context) are separate — don't conflate with shellbags proper.
- **ShellBag for a folder on a USB that was safely removed** stays alive after the device is unplugged. The bag outlives the mount.

## Anti-forensic caveats
User-writable with no native audit. Registry-level cleaners can wipe BagMRU entries, but *selective* cleanup is hard because BagMRU is hierarchical — deleting one folder's entries orphans the tree, which is itself a detectable pattern. Most cleaners do full-wipe or nothing.

Deleting BagMRU does NOT clean Bags\<N> view-state keys. The N values persist until garbage-collected. Orphan Bags keys after BagMRU wipe are a cleanup artifact.

## Practice hint
- Clean Win10 VM: browse Explorer into several folders across C:, a USB drive, and a network share. Open UsrClass.dat with Registry Explorer's Shellbags plugin. Confirm full path reconstruction and identify volume-GUID/label references.
- Delete one folder that appeared in ShellBags. Re-parse — the bag entry survives, but the MFT reference now points to a deleted or reused slot. Correlate with $MFT to confirm deletion.
- Reformat the USB, browse the same folder name again. Confirm the new ShellBag has a different FilesystemVolumeSerial but possibly the same VolumeLabel and definitely a different VolumeGUID.
- Run CCleaner's registry cleaner and re-acquire. Identify which bag entries were removed vs. preserved; count orphan Bags\<N> keys.
