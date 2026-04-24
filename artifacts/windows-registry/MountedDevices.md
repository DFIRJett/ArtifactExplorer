---
name: MountedDevices
aliases:
- Mount Manager database
link: device
tags:
- timestamp-carrying
- tamper-easy
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: XP
    max: '11'
  windows-server:
    min: '2003'
    max: '2022'
location:
  hive: SYSTEM
  path: MountedDevices
  addressing: hive+key-path
fields:
- name: dos-device-letter
  kind: identifier
  location: 'value name of form \DosDevices\<letter>:'
  encoding: utf-16le-value-name
- name: volume-guid
  kind: identifier
  location: value name of form \??\Volume{<GUID>}
  encoding: utf-16le-value-name
  references-data:
  - concept: VolumeGUID
    role: mountedVolume
- name: binding-data
  kind: identifier
  location: value data
  type: REG_BINARY
  encoding: |
    Three documented formats (libyal/winreg-kb reference):
    (1) DEVICE-STRING — variable-length UTF-16LE; format: DeviceID#InstanceID#{interface-class-GUID}. The middle #...# segment IS the USBSTOR serial (direct string-join to USBSTOR\\<Ven&Prod>\\<InstanceID>).
    (2) MBR — EXACTLY 12 bytes. Offset 0: 4-byte DiskSignature (little-endian; identical to bytes at MBR sector 0 offset 0x1B8). Offset 4: 8-byte partition-byte-offset (little-endian; Vista+ default 0x00100000 = 1 MiB).
    (3) GPT — EXACTLY 24 bytes. Starts with ASCII literal "DMIO:ID:" (8 bytes), followed by 16-byte GPT Unique Partition GUID (NOT the disk GUID).
  references-data:
  - concept: DeviceSerial
    role: usbDevice
  - concept: MBRDiskSignature
    role: volumeBinding
  - concept: GPTPartitionGUID
    role: volumeBinding
  note: "DeviceSerial only extractable from Format (1) device-string. Formats (2) MBR (via DiskSignature) and (3) GPT (via Partition GUID) encode volume identity without a device serial — pivot via DiskSignature → MBR sector or via PartitionGUID → GPT Partition Entry Array on the captured image."
- name: key-last-write
  kind: timestamp
  location: MountedDevices key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: aggregate — updates on any value change; NOT per-device
observations:
- proposition: CONNECTED
  ceiling: C2
  qualifier-map:
    peer.volume-guid: field:volume-guid
    peer.drive-letter: field:dos-device-letter
    peer.usb-serial: extracted from binding-data (USB-case)
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  known-cleaners:
  - tool: USBOblivion
    typically-removes: true
  - tool: CCleaner-registry-module
    typically-removes: partial
provenance:
  - aboutdfir-nd-usb-devices-windows-artifact-r
  - matrix-dt023-mounteddevices-registry-key
  - winreg-kb-mounted-devices
  - regripper-plugins
  - forensicartifacts-repo
  - artefacts-help-repo
---

# MountedDevices

## Forensic value
The bridge artifact in the USB-attribution chain. For removable USB storage, `binding-data` is a UTF-16LE symbolic-link string that literally contains the USBSTOR instance-id (serial) — making MountedDevices the textual pivot between SYSTEM-scope device identity and NTUSER-scope user attribution via the volume-GUID.

Without MountedDevices, the `USBSTOR.serial → volume-GUID → MountPoints2.subkey → user` chain cannot be closed. The serial and the volume-GUID are different identifiers until MountedDevices joins them.

## Known quirks
- Value-data encoding varies by disk type (MBR / GPT / USB). Don't assume uniformity.
- `key-last-write` is aggregate over all values — not per-device.
- Stale values persist; removing a USB doesn't delete its `\??\Volume{GUID}` entry.
- GPT partition GUIDs are NOT volume GUIDs. Don't conflate.

## Anti-forensic caveats
Admin-editable, no audit. USBOblivion targets it directly. Partial cleanup (USB entries gone, MBR bindings intact) is a high-confidence cleanup signal — no legitimate operation produces that pattern.

## Practice hint
Dump before/after plugging unknown USB on test VM. Observe two new values (`\DosDevices\X:` and `\??\Volume{GUID}`) with identical data. Decode the binding-data in hex; verify the serial substring matches USBSTOR instance-id.
