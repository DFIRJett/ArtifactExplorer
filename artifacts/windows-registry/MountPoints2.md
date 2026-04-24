---
name: MountPoints2
aliases:
- Explorer Mount Points
- per-user volume mount history
link: device
tags:
- timestamp-carrying
- tamper-easy
- per-user
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  hive: NTUSER.DAT
  path: Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
  addressing: hive+key-path
fields:
- name: volume-guid
  kind: identifier
  location: '{GUID} subkey name'
  encoding: guid-string
  references-data:
  - concept: VolumeGUID
    role: accessedVolume
- name: base-class
  kind: identifier
  location: BaseClass value
  type: REG_SZ
  encoding: utf-16le
- name: label-from-reg
  kind: identifier
  location: _LabelFromReg value
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: VolumeLabel
    role: accessedAtLabel
- name: autoplay-command
  kind: identifier
  location: "<{GUID}>\\Shell\\AutoRun\\command default value"
  type: REG_SZ
  note: |
    Command line Explorer would invoke if this device were re-mounted with
    AutoRun enabled. On modern Windows AutoRun is suppressed for most
    removable-storage scenarios, BUT the registered command persists from
    whenever it was last set. Forensic IOCs:
    - Command pointing at a non-standard path (%TEMP%, %APPDATA%, a cmd/.bat
      in an unusual location) = malware that registered AutoRun at mount time
    - Command pointing at `autorun.inf`-derived executable = classic
      autorun-malware family (Conficker-era), still encountered on isolated
      networks and older machines
- name: namespace-type
  kind: enum
  location: "derived from subkey name pattern"
  encoding: enum
  note: |
    MountPoints2 has THREE distinct subkey namespaces with different forensic semantics:
      (1) `{<VolumeGUID>}` — removable/fixed volume mount (the USB-tracking case)
      (2) `CPC\Volume\{<GUID>}` — Computed Path Cache, "volumes this user BROWSED
          TO" but did not necessarily mount. Present when shell traversed the
          volume path (shellbag-adjacent). NOT a mount event.
      (3) `#<server>#<share>` — SMB network share; UNC-path access, not
          removable storage
    Always filter by namespace before reasoning about mount events.
- name: user-scope-sid
  kind: identifier
  location: derived from NTUSER.DAT owner via ProfileList
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: profileOwner
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "CAVEAT (Carvey / Hedley / libyal): LastWriteTime is NOT reliably first-connection time. Reflects 'some Explorer-shell interaction with this user's mount-point entry' — often the first connect, but can be a later interaction. Entries may be MISSED entirely if the user was not logged in at insertion, and may be attributed to a prior logged-in user after unlocked auto-relogin. Corroborate with USBSTOR Properties\\{83da6326-...}\\0064/0066 or Partition/Diagnostic 1006 before treating as authoritative."
observations:
- proposition: POSSESSED
  ceiling: C3
  qualifier-map:
    entity.volume-guid: field:volume-guid
    actor.user: field:user-scope-sid
    time.start: field:key-last-write
- proposition: CONNECTED
  ceiling: C2
  note: key write implies Explorer saw the volume; does not prove physical connection to THIS host (roaming caveat)
  qualifier-map:
    peer.volume-guid: field:volume-guid
    time.start: field:key-last-write
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  audit-trail: "NTUSER.DAT transaction logs (NTUSER.DAT.LOG1, LOG2) retain evidence of recently-deleted MountPoints2 subkeys. Profile-hive transaction logs roll more frequently than SYSTEM/SOFTWARE due to higher write volume."
  known-cleaners:
  - tool: USBOblivion
    typically-removes: true
  - tool: CCleaner-registry-module
    typically-removes: partial
  - tool: Privazer
    typically-removes: true
  - tool: BleachBit
    typically-removes: partial
  survival-signals:
  - "MountPoints2 subkey absent + CPC\\Volume\\{same-GUID} present = user BROWSED the volume (shell traversal) but no mount-event entry exists OR the mount-entry was selectively cleaned while leaving CPC intact. Suggests a cleaner or manual edit targeting only mount entries."
  - "MountPoints2 entry for {GUID} present + MountedDevices binding for same GUID absent = SYSTEM hive cleaned but NTUSER missed. Asymmetric."
provenance:
  - aboutdfir-nd-usb-devices-windows-artifact-r
  - matrix-dt087-usb-mountpoints2
  - winreg-kb-mountpoints2
  - regripper-plugins
---

# MountPoints2

## Forensic value
The user-attribution link in the removable-media convergence chain. Without MountPoints2 (or equivalent per-user artifact like shellbags referencing the volume), device-to-user attribution collapses to session-window inference — weaker, contestable, frequently defeated by multi-user boxes.

## Known quirks
- **Last-write-only memory:** no mount history. Jump lists and shellbags preserve historical mounts MountPoints2 loses.
- **Network share entries** (`#<server>#<share>`) are SMB, not removable storage. Same schema, different investigative proposition.
- **CPC namespace keys** represent browsed-to volumes, not mounts. Treat separately — they're shell-traversal evidence (BagMRU-adjacent), not mount evidence.
- **Roaming profiles** may reflect mounts on a different host. Check `ProfileList\<SID>\ProfileType`.
- **`_LabelFromReg` vs FS label**: `_LabelFromReg` stores the volume label as cached by Explorer from the filesystem. FAT labels are cached; NTFS labels can differ between the volume's `$VOLUME_NAME` attribute and this cache. Disagreement is expected — investigate only if pursuing tamper analysis.
- **`BaseClass` value** identifies the device class as observed by Explorer: `Drive` (mass storage), `Shell`, `Network Share`. Filter on `BaseClass=Drive` for USB-flash analysis.

## Cross-references

| Joined to | Via | How |
|---|---|---|
| **USBSTOR** | VolumeGUID via MountedDevices | Two-hop: MountPoints2 `{GUID}` → MountedDevices `\??\Volume{GUID}` binding-data → USBSTOR InstanceID |
| **MountedDevices** | VolumeGUID direct | Value `\??\Volume{GUID}` directly matches MountPoints2 subkey name |
| **BagMRU (shellbags)** | VolumeGUID + shell-item | Shell-item lists in BagMRU encode the VolumeGUID; browsed-to volumes appear in both |
| **ShellLNK** | shell-item serial | LNK target-chain includes shell-items with VolumeGUID; joins MountPoints2 for same volume |
| **Partition/Diagnostic-1006** | VolumeGUID (GPT case) | `EventData\Gpt\Partitions[].PartitionId` matches MountPoints2 VolumeGUID on GPT removables |

## Anti-forensic caveats
User-writable with no native audit. Combined with admin-scoped USBOblivion cleanup of the SYSTEM-hive artifacts, the entire USB chain can be scrubbed without triggering Security events. Survivors: Partition/Diagnostic 1006, jump lists, prefetch for executables run from removable volume, EMDMgmt (SOFTWARE hive, frequently missed).

The per-user scope of MountPoints2 means multi-user systems have MULTIPLE MountPoints2 locations — one per loaded NTUSER.DAT. Examine every user profile's hive; single-hive analysis is incomplete.

## Practice hint
Mount test USB on Win10 VM as User A, safely remove, log in as User B, mount same USB, diff NTUSER hives. Run USBOblivion and re-acquire — observe which artifacts survive. Pay attention to the CPC namespace: browse into the USB root in Explorer but don't mount — observe whether a `CPC\Volume\{GUID}` key appears without a sibling `{GUID}` mount key.
