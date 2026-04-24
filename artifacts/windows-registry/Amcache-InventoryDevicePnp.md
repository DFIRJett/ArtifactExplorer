---
name: Amcache-InventoryDevicePnp
aliases:
- Amcache PnP device inventory
- Amcache connected-device history
link: device
tags:
- timestamp-carrying
- device-history
- usb-history
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
  path: Root\InventoryDevicePnp\<DeviceInstanceID>
  addressing: hive+key-path
fields:
- name: device-instance-id
  kind: identifier
  location: subkey name
  encoding: PnP DeviceInstanceID (e.g., USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler&Rev_1.00\08606E6D000A8F4...)
  references-data:
  - concept: DeviceSerial
    role: usbDevice
- name: Class
  kind: label
  location: Class value
  type: REG_SZ
  note: 'DiskDrive | USB | HIDClass | PrintQueue | Net | Bluetooth | ...'
- name: ClassGuid
  kind: identifier
  location: ClassGuid value
  type: REG_SZ
  note: device setup class GUID
- name: Model
  kind: label
  location: Model value
  type: REG_SZ
  note: human-readable device model name
- name: Manufacturer
  kind: label
  location: Manufacturer value
  type: REG_SZ
- name: ContainerId
  kind: identifier
  location: ContainerId value
  type: REG_SZ
  note: cross-device pivot — same physical device gets the same ContainerId across its logical interfaces
  references-data:
  - concept: ContainerID
    role: deviceIdentity
- name: DeviceState
  kind: flag
  location: DeviceState value
  type: REG_DWORD
- name: DeviceInterfaceClasses
  kind: identifier
  location: DeviceInterfaceClasses value (multi-SZ)
  type: REG_MULTI_SZ
- name: Parent
  kind: identifier
  location: Parent value
  type: REG_SZ
  note: parent device instance path — enables PnP tree reconstruction
- name: Service
  kind: label
  location: Service value
  type: REG_SZ
  note: driver service name (usbstor, disk, volume, nlaapi, ...)
- name: FirstInstallDate
  kind: timestamp
  location: FirstInstallDate value
  type: REG_QWORD
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: InstallDate
  kind: timestamp
  location: InstallDate value
  type: REG_QWORD
  encoding: filetime-le
  note: most-recent driver install or device-configure timestamp
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: DEVICE_ATTACHED
  ceiling: C3
  note: Evidence that a device was attached and enumerated by PnP. Alternate/complementary source to USBSTOR — often richer, often retains entries after USBSTOR cleanup.
  qualifier-map:
    object.device.instance: field:device-instance-id
    object.device.container: field:ContainerId
    time.first_install: field:FirstInstallDate
    time.last_install: field:InstallDate
anti-forensic:
  write-privilege: admin
  known-cleaners:
  - tool: USBOblivion
    typically-removes: partial (often misses Amcache)
  - tool: manual hive edit
    typically-removes: surgical
provenance:
  - aboutdfir-nd-usb-devices-windows-artifact-r
---

# Amcache-InventoryDevicePnp

## Forensic value
An alternate, often-richer USB/device history artifact **complementary to USBSTOR**. While USBSTOR lives in the SYSTEM hive and is the primary device-history substrate, Amcache's InventoryDevicePnp:

- Includes ALL PnP device classes, not just USB storage — printers, Bluetooth, NICs, HIDs, audio — everything.
- Often survives USBSTOR-targeted cleaners (USBOblivion, CCleaner) that don't know to touch Amcache.
- Records FirstInstallDate in a structured REG_QWORD field — more reliable than inferring from key last-write.

## Cross-references
- **USBSTOR** — primary USB-storage device history; joins via serial number embedded in DeviceInstanceID
- **MountedDevices** — volume-to-device mapping; joins via ContainerID or DeviceInstanceID
- **MountPoints2** — per-user volume access history; joins via ContainerID
- **WindowsPortableDevices** — MTP device history; joins via ContainerID
- **Amcache-InventoryDeviceContainer** — sibling artifact for container-level (whole-device) metadata
- **PartitionDiagnostic-1006** — volume-mount evtx events; same ContainerID/VolumeGUID chain

## ContainerID as the universal pivot
The `ContainerId` value is THE pivot across Amcache-InventoryDevicePnp, Amcache-InventoryDeviceContainer, MountedDevices, MountPoints2, WindowsPortableDevices, and Partition/Diagnostic events. When an investigator says "prove this specific USB drive touched this system," ContainerID is the anchor.

## Practice hint
```
AmcacheParser.exe -f Amcache.hve --csv .\out
# look at: Amcache_InventoryDevicePnP.csv
```
Filter by Class=DiskDrive and join with Amcache_InventoryDeviceContainer.csv on ContainerId to rebuild per-device histories.
