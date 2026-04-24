---
name: Amcache-InventoryDeviceContainer
aliases:
- Amcache device-container inventory
- Amcache Bluetooth and device catalog
link: device
tags:
- timestamp-carrying
- device-history
- bluetooth
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
  path: Root\InventoryDeviceContainer\<ContainerID-GUID>
  addressing: hive+key-path
fields:
- name: container-id
  kind: identifier
  location: subkey name
  encoding: GUID
  note: the same ContainerID that appears in InventoryDevicePnp, MountedDevices, MountPoints2, and WPD
  references-data:
  - concept: ContainerID
    role: deviceIdentity
- name: FriendlyName
  kind: label
  location: FriendlyName value
  type: REG_SZ
  note: user-visible device name (e.g., 'Kingston DataTraveler', 'AirPods Pro', 'HP Color LaserJet')
- name: PrimaryCategory
  kind: label
  location: PrimaryCategory value
  type: REG_SZ
  note: category taxonomy (Computer.Desktop / PrintFax.Printer / Communications.Bluetooth / ... )
- name: ModelName
  kind: label
  location: ModelName value
  type: REG_SZ
- name: ModelNumber
  kind: identifier
  location: ModelNumber value
  type: REG_SZ
- name: Manufacturer
  kind: label
  location: Manufacturer value
  type: REG_SZ
- name: Categories
  kind: label
  location: Categories value
  type: REG_MULTI_SZ
- name: IsConnected
  kind: flag
  location: IsConnected value
  type: REG_DWORD
- name: IsPaired
  kind: flag
  location: IsPaired value
  type: REG_DWORD
  note: Bluetooth/WiFi-direct paired devices get IsPaired=1; paired-but-absent devices still have the record
- name: DiscoveryMethod
  kind: label
  location: DiscoveryMethod value
  type: REG_SZ
  note: USB | Bluetooth | WSD | SSDP | PnPX
- name: Icon
  kind: path
  location: Icon value
  type: REG_SZ
- name: InstallDate
  kind: timestamp
  location: InstallDate value
  type: REG_QWORD
  encoding: filetime-le
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: DEVICE_PAIRED_OR_PRESENT
  ceiling: C3
  note: Container-level device-history record. Unlike InventoryDevicePnp which captures per-logical-interface entries, InventoryDeviceContainer is one record per physical device. Preserves friendly name, model, and pairing state.
  qualifier-map:
    object.device.container: field:container-id
    object.device.name: field:FriendlyName
    object.device.model: field:ModelName
    time.install: field:InstallDate
anti-forensic:
  write-privilege: admin
  known-cleaners:
  - tool: USBOblivion
    typically-removes: partial (Bluetooth entries often missed)
  - tool: Windows Settings Bluetooth unpair
    typically-removes: flips IsPaired=0 but keeps record
provenance:
  - aboutdfir-nd-usb-devices-windows-artifact-r
---

# Amcache-InventoryDeviceContainer

## Forensic value
**Per-physical-device** record — one entry per real-world device, regardless of how many logical interfaces it exposed. This complements `Amcache-InventoryDevicePnp` which has one entry per logical interface (a USB flash drive with a MassStorage interface + a HID interface would have 2 PnP entries but 1 Container entry).

Rich for non-USB devices:
- **Bluetooth peripherals** — paired earbuds, keyboards, phones with their MAC-derived ContainerID
- **WSD printers** — network printers discovered via Web Services for Devices
- **Miracast displays**
- **Connected cars** (via Bluetooth phone pairing)

## ContainerID as universal pivot
Same ContainerID links:
- **Amcache-InventoryDeviceContainer** — this artifact (per-device metadata)
- **Amcache-InventoryDevicePnp** — per-interface records
- **MountedDevices** — volume bindings
- **MountPoints2** — per-user volume access
- **WindowsPortableDevices** — MTP device history
- **PartitionDiagnostic-1006** — volume-mount events

For Bluetooth devices, ContainerID in this artifact joins with:
- Bluetooth pairing keys in registry (SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys)
- Microsoft-Windows-Bluetooth-MTPEnum EVTX channel

## Cross-references
- **Amcache-InventoryDevicePnp** — sibling, per-interface records
- **MountedDevices / MountPoints2** — volume layer for storage devices
- **WindowsPortableDevices** — MTP layer
- **USBSTOR** — USB-storage only, does NOT cover Bluetooth

## Practice hint
```
AmcacheParser.exe -f Amcache.hve --csv .\out
```
Open `Amcache_InventoryDeviceContainer.csv`. Filter PrimaryCategory='Communications.Bluetooth' to audit paired devices — useful in cases where phone-based data transfer or unauthorized peripheral use is in scope.
