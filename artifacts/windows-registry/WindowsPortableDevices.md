---
name: WindowsPortableDevices
aliases:
- WPD
link: device
tags:
- anti-forensic-resistant
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  hive: SOFTWARE
  path: Microsoft\Windows Portable Devices\Devices\<WPD-device-id>
  addressing: hive+key-path
fields:
- name: wpd-device-id
  kind: identifier
  location: <WPD-device-id> subkey name
  encoding: utf-16le
  references-data:
  - concept: DeviceSerial
    role: usbDevice
  note: |
    Long composite subkey name. Two common patterns:

    MASS-STORAGE (USB flash, external HDDs — the forensically common case):
      `SWD#WPDBUSENUMROOT#UMB#2&<hex>&0&STORAGE#VOLUME#_??_USBSTOR#Disk&Ven_<V>&Prod_<P>&Rev_<R>#<InstanceID>#{<storage-class-GUID>}`
      — contains USBSTOR InstanceID verbatim (the `<InstanceID>` segment)

    MTP/PTP (phones, cameras, media players):
      `WPDBUSENUMROOT#UMB#2&<hex>&0&_##_?{MTP/PTP-device-id}`
      — no USBSTOR serial; MTP devices bypass mass-storage enumeration

    Parser: split on `#` and search for `USBSTOR` segment; if present, the
    segment immediately after `#Disk&Ven_...&Prod_...&Rev_...#` IS the
    USBSTOR InstanceID. If `USBSTOR` absent, device is MTP — use alternate
    device-id decoder (Windows Portable Devices API), different identity
    guarantees.
- name: friendly-name
  kind: identifier
  location: FriendlyName value
  type: REG_SZ
  encoding: utf-16le
  note: volume label — survives most cleanups that hit USBSTOR
  references-data:
  - concept: VolumeLabel
    role: deviceLabel
- name: container-id-property
  kind: identifier
  location: per-device subkey → Properties → DEVPKEY_Device_ContainerId (GUID)
  encoding: GUID
  note: "same ContainerID GUID recorded in USBSTOR Properties and Microsoft-Windows-Partition/Diagnostic event 1006 — primary cross-artifact join for physical-device identity"
  references-data:
  - concept: ContainerID
    role: deviceIdentity
- name: instance-id-property
  kind: identifier
  location: "per-device subkey → Properties → DEVPKEY_Device_InstanceId"
  type: REG_SZ
  encoding: utf-16le
  note: "Device InstanceID as Property (mirror of the value embedded in the subkey name). Parser convenience — read this rather than parsing the long subkey name path when available."
- name: device-desc-property
  kind: identifier
  location: "per-device subkey → Properties → DEVPKEY_Device_DeviceDesc"
  type: REG_SZ
  encoding: utf-16le
  note: "Device description, typically 'USB Mass Storage Device' or vendor-supplied string. Cross-references USBSTOR's DeviceDesc value."
- name: class-guid-property
  kind: identifier
  location: "per-device subkey → Properties → DEVPKEY_Device_ClassGuid"
  type: REG_SZ
  encoding: guid-string
  note: "Device class: WPD-wrapper GUID (`{eec5ad98-8080-425f-922a-dabf3de3f69a}` for WPDBUSENUM) vs. DiskDrive (`{4d36e967-...}`). Distinguishes MTP from mass-storage devices."
- name: key-last-write
  kind: timestamp
  location: device-id subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: set-on-enumeration-or-FriendlyName-change
  note: "Not 'last connected' — only updates when Windows Portable Devices re-enumerates OR when FriendlyName changes (e.g., user renames the volume). First write corresponds to first WPD enumeration of the device."
observations:
- proposition: CONNECTED
  ceiling: C3
  qualifier-map:
    peer.usb-serial: field:wpd-device-id
    peer.volume-label: field:friendly-name
    peer.container-id: field:container-id-property
    time.start: field:key-last-write
  note: "Ceiling C3 because WPD carries THREE independent identity fields (serial-substring + ContainerID + volume-label), any two corroborating each other establish device identity with redundancy. Admin can still offline-edit the SOFTWARE hive."
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  audit-trail: "SOFTWARE hive transaction logs (SOFTWARE.LOG1, SOFTWARE.LOG2) retain evidence of deleted WPD subkeys."
  known-cleaners:
  - tool: USBOblivion
    typically-removes: partial
    note: "Some versions target WPD; others skip entirely. Verify per version in use."
  - tool: CCleaner-registry-module
    typically-removes: false
  - tool: Privazer
    typically-removes: partial
  - tool: manual reg.exe delete
    typically-removes: true
  survival-signals:
  - "WPD present + USBSTOR absent for same InstanceID = SYSTEM-hive cleaner hit USBSTOR but missed SOFTWARE-hive WPD. HIGH-confidence cleanup-attempt signal."
  - "WPD FriendlyName differs from current filesystem volume label = label changed after WPD enumeration (legitimate user rename OR post-cleanup label reset to hide historical name)"
survival-edges:
- when: USBSTOR removed by cleaner
  survives: this-artifact
  reason: cleaners historically target HKLM\SYSTEM; HKLM\SOFTWARE\Windows Portable Devices frequently missed
provenance:
  - aboutdfir-nd-usb-devices-windows-artifact-r
---

# Windows Portable Devices

## Forensic value
The anti-forensic survivor in the USB-attribution chain. WPD lives in SOFTWARE, not SYSTEM — most USB-history cleaners ignore it. When USBSTOR, MountedDevices, and MountPoints2 are all scrubbed, WPD frequently remains with both the serial-embedded device-id path AND the volume label.

## Known quirks
- **Long device-id paths.** Parse on `#` delimiters. For mass-storage: USBSTOR InstanceID is the segment following `#Disk&Ven_*&Prod_*&Rev_*#`.
- **`friendly-name` is the VOLUME label**, not the USB-descriptor FriendlyName. Don't confuse with USBSTOR's `FriendlyName` value (which is the device description).
- **MTP/PTP devices** (cameras, phones, some media players) have WPD entries with different id formats — no USBSTOR substring. Identity guarantees weaker than mass-storage; MTP serials may be spoofed by the device.
- **`key-last-write` is event-driven** (enumeration or label change), not "last connected." Two devices plugged in back-to-back may show last-writes that don't reflect plug-order.
- **Per-user WPD on some Windows builds**: `HKCU\Software\Microsoft\Windows Portable Devices\Devices` exists in parallel on Win10+ with per-user device name overrides. Minor artifact — the HKLM path is the primary.
- **WPDNSE cross-reference**: `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices\<id>\Properties\{...}\WPDNSE` holds namespace-extension data (shell integration); not typically forensically load-bearing but may reveal which Explorer-integrated views were registered.

## Cross-references

| Joined to | Via | How |
|---|---|---|
| **USBSTOR** | InstanceID substring | wpd-device-id contains USBSTOR InstanceID verbatim (mass-storage case) |
| **EMDMgmt** | InstanceID + VolumeLabel | Both encode InstanceID substring; EMDMgmt adds VolumeSerial (decimal), WPD adds ContainerID |
| **MountedDevices** | InstanceID | Both reference USBSTOR InstanceID — two-hop join via USBSTOR |
| **Partition/Diagnostic-1006** | ContainerID | Both record ContainerID; WPD's Properties subtree is the registry mirror of event 1006's ContainerId field |
| **Amcache-InventoryDevicePnp** | InstanceID + ContainerID | Amcache device inventory overlaps WPD fields |

## Parsers

| Tool | Strengths |
|---|---|
| RegRipper (`port_dev.pl`, `wpdbusenum.pl` by Harlan Carvey) | Canonical — parses WPD entries + Properties subtree |
| Registry Explorer (Eric Zimmerman) | GUI; transaction-log replay for deleted WPD subkeys |
| `regipy` | Programmatic access; iterate Properties subtree for DEVPKEY values |
| KAPE `RegistryHives_Software` target | Offline SOFTWARE hive acquisition |

## Anti-forensic caveats
Single highest-survival artifact in the four-artifact USB-history scope. Scrubbed SYSTEM with intact WPD is the most common post-cleanup pattern. WPD survival itself is an affirmative finding — the cleanup attempt is evidence of intent to destroy USB history.

For analysts: **check WPD first on a USB-history case**. If WPD is absent, you're looking at either a pristine system (unlikely on any daily-driver) or a thorough cleanup. If WPD is present and USBSTOR is absent, you've found your evidence of tampering.

## Practice hint
Run USBOblivion against VM with known USB history, dump `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`, identify survivors. Parse a device-id string by hand: split on `#`, extract USBSTOR segment, then extract InstanceID between the `#{GUID}#` delimiters. Verify the InstanceID matches a subkey name under `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\<Ven&Prod>` (on a system where USBSTOR is still intact).
