---
name: VolumeLabel
kind: value-type
lifetime: persistent
link-affinity: device
description: |
  Filesystem volume label — the user-visible string written at format time
  or by label.exe. Frequently survives cleaner tooling that targets device-
  history registry keys (particularly Windows Portable Devices, which most
  cleaners miss).
canonical-format: "utf-16le string, up to 32 chars for NTFS, 11 for FAT"
aliases: [VolumeName, _LabelFromReg, volume-friendly-name, FAT-label, NTFS-label]
roles:
  - id: accessedAtLabel
    description: "Volume label captured at a moment of per-user access (shell artifacts)"
  - id: deviceLabel
    description: "Volume label as known to device-enumeration layer (WPD, legacy ReadyBoost)"

known-containers:
  - MountPoints2
  - WindowsPortableDevices
  - ShellLNK
  - ShellBags
  - EMDMgmt
---

# Volume Label

## What it is
The human-readable name of a filesystem volume. Written at format time or by the `label.exe` command. Strings like `BACKUPS`, `USB DRIVE`, `Kingston_32GB` — whatever the user or factory named the volume.

## Forensic value
- **Victim-identification aid.** Users describe devices by label ("my E: drive named BACKUPS"). The label bridges user recollection to forensic identifiers.
- **Anti-forensic survivor.** Windows Portable Devices preserves FriendlyName (the volume label) in HKLM\SOFTWARE. Most USB-history cleaners target HKLM\SYSTEM and miss SOFTWARE — so the label often survives when USBSTOR/MountedDevices do not.

## Encoding variations

| Artifact | Where |
|---|---|
| MountPoints2 | `_LabelFromReg` value under the volume-GUID subkey |
| WindowsPortableDevices | `FriendlyName` value under the device subkey |
| ShellLNK | embedded in shell-item lists (drive node) |
| EMDMgmt | legacy ReadyBoost key — volume label is part of the entry |
