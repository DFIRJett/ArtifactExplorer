---
name: DeviceSerial
kind: identifier
lifetime: permanent
link-affinity: device
description: |
  USB device serial number. Advertised by the device in its USB descriptor,
  or synthesized by the OS when the device declines to report one. On Windows,
  OS-synthesized serials are flagged by an '&' at character position 2 of the
  USBSTOR <instance-id>.
canonical-format: "ASCII string, device-defined length"
os-synthesized-signal: "char-pos 2 == '&' in Windows USBSTOR <instance-id>"
aliases: [usb-serial, device-serial-number, USB-descriptor-iSerial]
roles:
  - id: usbDevice
    description: "USB device serial — the primary identity of a USB storage device as advertised or OS-synthesized"

known-containers:
  - USBSTOR
  - MountedDevices
  - WindowsPortableDevices
  - setupapi-dev-log
  - PartitionDiagnostic-1006
  - DriverFrameworks-Operational
  - Amcache-InventoryDevicePnp
provenance:
  - hedley-2024-usbstor-install-first-install
  - matrix-dt021-usbstor-registry-key
---

# Device Serial

## What it is
The unique identifier string assigned to a USB storage device. Two sources:

1. **Device-reported**: the USB descriptor's `iSerial` field, written into the device's firmware by the manufacturer.
2. **OS-synthesized**: if the descriptor's `iSerial` is absent or declared unsupported, Windows generates one. These synthesized serials are NOT unique across same-model devices and MUST NOT be used as the sole device identifier.

## Encoding variations across artifacts

| Artifact | Where | Encoding |
|---|---|---|
| USBSTOR | `<instance-id>` path segment | ASCII |
| MountedDevices | embedded substring in `\??\Volume{}` binding-data value | UTF-16LE symbolic-link string containing the serial |
| WindowsPortableDevices | embedded substring in `<WPD-device-id>` subkey name | UTF-16LE |
| setupapi-dev-log | log line fields | ASCII plaintext |
| Partition/Diagnostic 1006 | event payload `SerialNumber` | unicode event field |

## Forensic value
Primary device-identity pivot for USB storage. When present and device-reported, it uniquely identifies the physical device across reformats, OS reinstalls, and cross-system movements. Corroborate with ContainerID whenever possible, especially when the `&0` suffix indicates OS-synthesis.
