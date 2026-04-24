---
name: ShellLNK
aliases:
- LNK file
- Windows shortcut
- .lnk
- Shell Link
link: file
tags:
- timestamp-carrying
- tamper-easy
- per-user
volatility: persistent
interaction-required: user-action
substrate: windows-lnk
substrate-instance: '%APPDATA%\Microsoft\Windows\Recent'
substrate-hub: User scope
platform:
  windows:
    min: NT
    max: '11'
  windows-server:
    min: '2003'
    max: '2022'
location:
  container: windows-lnk
  path: <user-profile>\AppData\Roaming\Microsoft\Windows\Recent\<name>.lnk
  addressing: filesystem-path
  other-locations:
  - '%USERPROFILE%\Desktop\*.lnk'
  - '%APPDATA%\Microsoft\Windows\Start Menu\*.lnk'
  - '%APPDATA%\Microsoft\Office\Recent\*.lnk'
fields:
- name: link-flags
  kind: flags
  location: header offset 0x14
  encoding: uint32-bitfield
  note: declares which optional sections follow (LinkInfo, Strings, ExtraData, etc.) — parser must honor these bits
- name: file-attributes
  kind: flags
  location: header offset 0x18
  encoding: uint32-bitfield
- name: target-creation-time
  kind: timestamp
  location: header offset 0x1C
  encoding: filetime-le
  clock: system (target-file $SI at time of LNK creation)
  resolution: 100ns
  note: frozen snapshot of target's CreationTime — not updated on LNK re-access
- name: target-access-time
  kind: timestamp
  location: header offset 0x24
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: frozen snapshot of target's AccessTime — not updated on LNK re-access
- name: target-write-time
  kind: timestamp
  location: header offset 0x2C
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: frozen snapshot of target's WriteTime — not updated on LNK re-access
- name: target-file-size
  kind: counter
  location: header offset 0x34
  encoding: uint32
  note: low 32 bits of target size at LNK creation; truncates for >4 GB files
- name: link-target-idlist
  kind: path
  location: optional — follows header when HasLinkTargetIDList bit set
  encoding: shell-item-list-binary
  note: full shell-namespace chain to target; embeds volume-GUID when target is on a removable volume; embeds MFT entry+sequence
    when target is a file or folder on NTFS (from shell-item extension blocks)
  references-data:
  - concept: VolumeGUID
    role: accessedVolume
  - concept: MFTEntryReference
    role: referencedFile
  - concept: PIDL
    role: linkedItem
- name: local-base-path
  kind: path
  location: LinkInfo\LocalBasePath
  encoding: utf-16le OR ascii (per IsUnicode flag)
  note: canonical filesystem path to target
- name: common-path-suffix
  kind: path
  location: LinkInfo\CommonPathSuffix
  encoding: utf-16le OR ascii
- name: drive-type
  kind: enum
  location: LinkInfo\VolumeIDAndLocalBasePath\DriveType
  encoding: uint32
  note: DRIVE_UNKNOWN|DRIVE_NO_ROOT_DIR|DRIVE_REMOVABLE|DRIVE_FIXED|DRIVE_REMOTE|DRIVE_CDROM|DRIVE_RAMDISK
- name: fs-volume-serial
  kind: identifier
  location: LinkInfo\VolumeIDAndLocalBasePath\DriveSerialNumber
  encoding: uint32-le
  references-data:
  - concept: FilesystemVolumeSerial
    role: accessedAtSerial
  note: 32-bit FS serial; regenerated on reformat — see FilesystemVolumeSerial concept
- name: volume-label
  kind: identifier
  location: LinkInfo\VolumeIDAndLocalBasePath\VolumeLabel
  encoding: utf-16le OR ascii (per IsUnicode flag)
  references-data:
  - concept: VolumeLabel
    role: accessedAtLabel
- name: network-share-name
  kind: path
  location: LinkInfo\CommonNetworkRelativeLink\NetName
  encoding: utf-16le OR ascii
  note: present when target was on a network share (\\server\share\...)
- name: network-device-name
  kind: identifier
  location: LinkInfo\CommonNetworkRelativeLink\DeviceName
  encoding: utf-16le OR ascii
- name: name-string
  kind: identifier
  location: StringData\NAME_STRING
  encoding: utf-16le OR ascii
  note: human-readable description; often the target's display name
- name: relative-path
  kind: path
  location: StringData\RELATIVE_PATH
  encoding: utf-16le OR ascii
  note: relative path from LNK location to target — survives target-path changes that absolute path doesn't
- name: working-dir
  kind: path
  location: StringData\WORKING_DIR
  encoding: utf-16le OR ascii
- name: command-line-arguments
  kind: identifier
  location: StringData\COMMAND_LINE_ARGUMENTS
  encoding: utf-16le OR ascii
  note: arguments that would be passed to the target executable; attackers stage LNK-based lures here
- name: icon-location
  kind: path
  location: StringData\ICON_LOCATION
  encoding: utf-16le OR ascii
- name: tracker-machine-id
  kind: identifier
  location: ExtraData\TrackerDataBlock\MachineID
  encoding: ascii (15 chars, NUL-padded to 16)
  references-data:
  - concept: MachineNetBIOS
    role: trackerMachineId
  note: NetBIOS name of the host whose DLT service stamped this LNK — travels with the file
- name: tracker-droid
  kind: identifier
  location: ExtraData\TrackerDataBlock\Droid
  encoding: guid-pair (32 bytes — two GUIDs)
  note: DLT object identifier — second GUID is the volume identifier, first is the object identifier
- name: tracker-droid-birth
  kind: identifier
  location: ExtraData\TrackerDataBlock\DroidBirth
  encoding: guid-pair (32 bytes)
  note: original DLT identifier at creation; differs from tracker-droid if the object was copied/moved through DLT-aware hops
observations:
- proposition: ACCESSED
  ceiling: C3
  note: LNK's existence in Recent proves the target was opened by the user whose profile owns this folder; the frozen MAC
    times timestamp that access
  qualifier-map:
    object.path: field:local-base-path
    object.volume-serial: field:fs-volume-serial
    object.volume-label: field:volume-label
    actor.user: derived from NTUSER profile owner
    time.start: LNK file own $SI creation time (not a field here; filesystem metadata)
    time.end: LNK file own $SI write time
  preconditions:
  - LNK was auto-created by Explorer (location in Recent, not user-placed)
  - LNK MachineID matches this host (else the LNK was transplanted)
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: Explorer "Clear recent items" UI
    typically-removes: '%APPDATA%\Microsoft\Windows\Recent contents'
    note: leaves jump list .automaticDestinations-ms files intact
  - tool: CCleaner
    typically-removes: partial
  - tool: manual delete
    typically-removes: surgical
  survival-signals:
  - LNK target references deleted USBSTOR serial = the deleted USB was opened from, via this LNK's volume-GUID chain
  - LNK MachineID ≠ current host = LNK was created elsewhere and copied in
  - LNK volume-serial ≠ current volume-serial for same volume-GUID = the volume was reformatted since the LNK was created
provenance: []
---

# Shell Link (LNK) File

## Forensic value
The primary per-user file-access evidence on Windows. Every time Explorer opens a file, a .lnk gets written into `%APPDATA%\Microsoft\Windows\Recent` — no opt-in, no toggle, just happens. That directory is a time-ordered history of file access for the user, one LNK per recently-opened target.

What makes LNK files uniquely rich:

1. **Frozen snapshot of target metadata** — MAC times, size, attributes at the moment of the LNK's creation. Later changes to the target don't update the LNK.
2. **Volume identity at the moment of access** — LinkInfo captures drive type, serial, and label. Proves the target lived on a specific (possibly removable) volume.
3. **Cross-host attribution via TrackerDataBlock** — the MachineID identifies the host whose DLT service stamped the LNK. Copying a LNK between machines preserves this evidence.
4. **Path to a file that may no longer exist** — LNK is often the last surviving evidence that a deleted file existed.

## Four concept references in one artifact
- VolumeGUID (via LinkTargetIDList shell items, when target is on a removable volume)
- VolumeLabel (LinkInfo.VolumeLabel)
- FilesystemVolumeSerial (LinkInfo.DriveSerialNumber — 32-bit FS-level serial)
- MachineNetBIOS (TrackerDataBlock.MachineID)

## Known quirks / silent-failure modes
- **MAC times are frozen snapshots.** A LNK for a file opened 3 years ago will carry that file's 3-year-old MAC times forever — those are target-at-capture timestamps, not current timestamps.
- **IsUnicode flag matters.** Parsers that don't honor it produce garbled paths for non-ASCII filenames.
- **Volume serial regeneration.** FilesystemVolumeSerial is regenerated on reformat. Same DeviceSerial + different FilesystemVolumeSerial across two LNKs for the same physical device = the device was reformatted between accesses.
- **MachineID can be stale.** If a user carries LNK files from an old computer, MachineID persists. This is a feature forensically (proves provenance) but confuses naive "current machine" assumptions.
- **FileSize truncates at 4 GB** because the header field is 32-bit. For larger targets, check the optional ExtendedBlock structures or resolve via the target path.
- **Explorer's "Clear Recent" leaves jump lists intact.** Users who clear Recent to hide activity often forget to clear `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations` — same evidence, different file.

## Anti-forensic caveats
LNK files are ordinary files — trivially deletable, editable with a hex editor, or replaceable with a crafted decoy. Three things make them difficult to *thoroughly* sanitize:
1. **Jump lists duplicate most of the LNK content** — clearing Recent without clearing AutomaticDestinations leaves half the trail intact.
2. **$MFT resident LNK records** can carve from unallocated after deletion.
3. **MachineID tampering requires knowing the correct NetBIOS name of the host** — a crafted decoy LNK with a wrong MachineID is detectable if the examiner has any ground truth about the host.

## Practice hint
- On a clean Win10 VM, open a known test file from a USB drive. Parse the resulting LNK in Recent\ with LECmd. Identify the four concept references in the output.
- Copy that LNK to a second VM, then parse it there. The TrackerDataBlock MachineID should still point to the first VM.
- Reformat the USB and open another file on it. The new LNK should have a different FilesystemVolumeSerial but the same USBSTOR DeviceSerial — demonstrate the format-vs-identity distinction.
