---
name: USB-Enum
aliases:
- HKLM\SYSTEM\CurrentControlSet\Enum\USB
- USB device enumeration key
- PnP USB enumeration
link: device
tags:
- tamper-easy
- device-history
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
    max: '2025'
location:
  hive: SYSTEM
  path: ControlSet00x\Enum\USB\<VID_xxxx&PID_yyyy>\<instance-id>
  addressing: hive+key-path
  note: "parallel to \\Enum\\USBSTOR but covers ALL USB-protocol devices (HID, audio, printers, composite) — not just mass storage"
fields:
- name: vid-pid
  kind: identifier
  location: "first-level subkey under Enum\\USB"
  encoding: "VID_<4hex>&PID_<4hex> (e.g. VID_0951&PID_1665 = Kingston DataTraveler)"
  note: vendor + product identifier from the USB descriptor; common across all instances of the same device model
- name: instance-id
  kind: identifier
  location: second-level subkey under VID_/PID_ pair
  note: device-instance path; for devices that report a serial, this IS the serial — for others it's an OS-synthesized instance id
  references-data:
  - concept: DeviceSerial
    role: usbDevice
- name: container-id-property
  kind: identifier
  location: per-instance subkey → Properties → DEVPKEY_Device_ContainerId
  encoding: GUID
  note: "SAME ContainerID GUID that USBSTOR, WindowsPortableDevices, and Partition/Diagnostic events carry — primary forensic join across independent enumeration paths"
  references-data:
  - concept: ContainerID
    role: deviceIdentity
- name: FriendlyName
  kind: label
  location: per-instance subkey → FriendlyName value
  type: REG_SZ
  note: human-readable device name (e.g., 'USB Composite Device', 'Logitech USB Receiver')
- name: DeviceDesc
  kind: label
  location: per-instance subkey → DeviceDesc value
  type: REG_SZ
  note: typically an INF-provided descriptor with ampersand-prefix
- name: HardwareID
  kind: identifier
  location: per-instance subkey → HardwareID value
  type: REG_MULTI_SZ
  note: ordered list of hardware identifiers used by driver match (USB\VID_xxxx&PID_yyyy&REV_zzzz, etc.)
- name: Service
  kind: label
  location: per-instance subkey → Service value
  type: REG_SZ
  note: bound driver service name (HidUsb, usbccgp, usbaudio, ...)
- name: key-last-write
  kind: timestamp
  location: per-instance subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: driver install, reconfigure, or device first-enumeration
observations:
- proposition: CONNECTED
  ceiling: C3
  note: "Evidence that a USB-protocol device was attached and enumerated. Companion to USBSTOR (mass storage only) — USB-Enum covers the entire USB device tree including HID, audio, printers, webcams, dongles."
  qualifier-map:
    object.device.vidpid: field:vid-pid
    object.device.instance: field:instance-id
    object.device.container: field:container-id-property
    time.enumerated: field:key-last-write
anti-forensic:
  write-privilege: admin
  known-cleaners:
  - tool: USBOblivion
    typically-removes: partial — \\Enum\\USB often survives cleanup that targets \\Enum\\USBSTOR specifically
  - tool: manual reg delete
    typically-removes: full
provenance:
  - aboutdfir-nd-usb-devices-windows-artifact-r
  - matrix-dt022-usb-registry-key
  - regripper-plugins
---

# USB-Enum (HKLM\SYSTEM\CurrentControlSet\Enum\USB)

## Forensic value
The full PnP enumeration of every USB-protocol device ever attached to this host — not just mass storage. While **USBSTOR** covers USB disks/flash drives and **WindowsPortableDevices** covers MTP cameras/phones, **USB-Enum** covers the whole USB tree: HID devices, audio dongles, printers, webcams, composite devices, Bluetooth adapters, and yes, the USB-layer parent of every USBSTOR entry.

## Triple-join via ContainerID
The user's point: **one physical device can be confirmed across three independent enumeration paths** by matching Container ID:

| Path | What it says about the device |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\...` | "Windows saw a USB MASS-STORAGE device with this vendor/product/serial" |
| `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_xxxx&PID_yyyy\<instance>` | "Windows enumerated a USB-protocol device at this hardware address" |
| `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices\<WPD id>` | "This same device was seen by the WPD/shell subsystem for file browsing" |

All three carry the SAME ContainerID GUID. A forensic investigator can match those GUIDs across paths to confirm **a single physical device is represented consistently across independent enumeration paths** — Layer-3 identity confirmation.

## When USB-Enum wins over USBSTOR
- USB device is NOT mass storage — HID, audio, webcam, dongle — only USB-Enum records it
- USBSTOR cleaner (USBOblivion default target) ran — USB-Enum may survive
- Composite devices (a USB hub exposing multiple interfaces) — USB-Enum shows the composite parent + child interface records; USBSTOR only sees the storage child

## Cross-references
- **USBSTOR** — parallel mass-storage enumeration; shares DeviceSerial and ContainerID
- **WindowsPortableDevices** — MTP / shell-visible enumeration; shares ContainerID
- **MountedDevices / MountPoints2** — volume-level layer; connects device to mounted volume via deeper joins
- **setupapi-dev-log** — install-event text log for the same devices (dated + verbose)
- **Amcache-InventoryDevicePnp** — Amcache's own PnP mirror; shares DeviceSerial and ContainerID
- **PartitionDiagnostic-1006** — evtx layer; carries the same ContainerID at mount time

## Practice hint
On a live host with a USB stick inserted:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' -Recurse -EA 0 |
  ForEach-Object {
    $props = Get-ItemProperty $_.PSPath -EA 0
    if ($props.'DEVPKEY_Device_ContainerId') {
      [pscustomobject]@{
        InstanceId = $_.PSChildName
        ContainerId = $props.'DEVPKEY_Device_ContainerId'
        FriendlyName = $props.FriendlyName
      }
    }
  }
```
Then grep that ContainerId against Windows Portable Devices and USBSTOR Properties subkey content to verify the three-way match.
