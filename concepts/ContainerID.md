---
name: ContainerID
kind: identifier
lifetime: permanent
link-affinity: device
description: |
  Windows-assigned GUID identifying a physical device across all of its
  logical views (disk, volume, partition, portable-device interfaces).
  Stable across reformatting and repartitioning of the same device. Does
  NOT survive controller replacement or cryptographic erase.
canonical-format: "{8-4-4-4-12 hex GUID}"
aliases: [ContainerId, device-container-id]
roles:
  - id: deviceIdentity
    description: "Stable Windows-assigned GUID uniquely identifying a physical device across its logical views"

known-containers:
  - USBSTOR
  - PartitionDiagnostic-1006
  - WindowsPortableDevices
  - Amcache-InventoryDevicePnp
  - Amcache-InventoryDeviceContainer
provenance:
  - matrix-dt021-usbstor-registry-key
  - aboutdfir-nd-usb-devices-windows-artifact-r
---

# Container ID

## What it is
A GUID that Windows assigns to a physical device to unify its various logical representations. A USB flash drive has one ContainerID that ties together its disk entry (USBSTOR), its volume entry, its partition, and any portable-device interface it exposes.

## Forensic value
The strongest single device-identity field on modern Windows when the device-reported serial is unreliable (OS-synthesized `&0` suffix) or absent. Survives reformats and repartitioning. Use as primary identity when USBSTOR's serial is ambiguous.

## Encoding variations

| Artifact | Where |
|---|---|
| USBSTOR | `ContainerID` REG_SZ value |
| Partition/Diagnostic 1006 | `ContainerId` event field |
| WindowsPortableDevices | present for some device classes in the per-device subkey metadata |
