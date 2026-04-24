---
name: USBSTOR
aliases:
- USB Storage Device Enumeration
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
  path: CurrentControlSet\Enum\USBSTOR\<class-id>\<instance-id>
  addressing: hive+key-path
fields:
- name: vendor
  kind: identifier
  location: <class-id> segment
  encoding: ascii
- name: product
  kind: identifier
  location: <class-id> segment
  encoding: ascii
- name: revision
  kind: identifier
  location: <class-id> segment
  encoding: ascii
- name: serial-number
  kind: identifier
  location: <instance-id> segment
  encoding: ascii
  note: char-pos 2 == '&' means OS-synthesized serial — not device-reported, not unique across same-model devices
  references-data:
  - concept: DeviceSerial
    role: usbDevice
- name: friendly-name
  kind: identifier
  location: FriendlyName value
  type: REG_SZ
  encoding: utf-16le
- name: container-id
  kind: identifier
  location: ContainerID value
  type: REG_SZ
  encoding: guid-string
  note: stable device identity; survives reformat; does NOT survive controller replacement
  references-data:
  - concept: ContainerID
    role: deviceIdentity
- name: device-desc
  kind: identifier
  location: DeviceDesc value
  type: REG_SZ
  encoding: utf-16le
- name: hardware-id
  kind: identifier
  location: HardwareID value
  type: REG_MULTI_SZ
  encoding: utf-16le
- name: compatible-ids
  kind: identifier
  location: CompatibleIDs value
  type: REG_MULTI_SZ
  encoding: utf-16le
- name: service
  kind: identifier
  location: Service value
  type: REG_SZ
- name: capabilities
  kind: flags
  location: Capabilities value
  type: REG_DWORD
- name: key-last-write
  kind: timestamp
  location: <instance-id> key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: first-install-time
  kind: timestamp
  location: "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064 (DEVPKEY_Device_InstallDate)"
  encoding: "Win7: FILETIME at <prop-key>\\00000000\\Data. Win8+: FILETIME as unnamed default value of the 00xx subkey."
  clock: system
  resolution: 100ns
  availability:
    min-windows: '8'
  note: "Hedley 2024 Win10 22H2 caveat: 0064 and 0065 frequently carry identical values. Treat as 'install observed at time X' rather than two independent observations."
- name: first-arrival-time
  kind: timestamp
  location: Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0065 (DEVPKEY_Device_FirstInstallDate)
  encoding: filetime-le
  clock: system
  resolution: 100ns
  availability:
    min-windows: '8'
- name: last-arrival-time
  kind: timestamp
  location: Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0066 (DEVPKEY_Device_LastArrivalDate)
  encoding: filetime-le
  clock: system
  resolution: 100ns
  availability:
    min-windows: '8'
- name: last-removal-time
  kind: timestamp
  location: Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0067 (DEVPKEY_Device_LastRemovalDate)
  encoding: filetime-le
  clock: system
  resolution: 100ns
  availability:
    min-windows: '8'
  note: "Hedley 2024 caveat: 0067 updates on DRIVER-UNINSTALL events, not only physical unplug. Do not equate 0067 with 'last physical disconnection' without corroborating Partition/Diagnostic 1006 and UserPnp events."
- name: disk-id
  kind: identifier
  location: "<instance-id>\\Device Parameters\\Partmgr\\DiskId"
  type: REG_SZ
  encoding: "GUID string. Partmgr-assigned disk identifier — per-device GUID the Partition Manager driver binds when the disk is first enumerated. NOT the filesystem VolumeGUID; those live in MountedDevices."
  note: "Join path to MountedDevices is via USBSTOR <instance-id> substring in MountedDevices binding-data (Format 1), NOT via this DiskId field directly."
- name: parent-id-prefix
  kind: identifier
  location: "<instance-id>\\ParentIdPrefix value"
  type: REG_SZ
  encoding: utf-16le
  note: "Device-tree position token assigned by PnP. Used by the USB controller to thread this device to its bus-relations chain. Forensically rare — useful when reconstructing hub-topology at time of connection."
- name: driver
  kind: identifier
  location: "<instance-id>\\Driver value"
  type: REG_SZ
  encoding: utf-16le
  note: "`{4d36e967-e325-11ce-bfc1-08002be10318}\\<N>` — DiskDrive class GUID + driver instance number. Cross-reference to `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e967-...}\\<N>` for driver binding details."
- name: class-guid
  kind: identifier
  location: "<instance-id>\\ClassGUID value"
  type: REG_SZ
  encoding: guid-string
  note: "Always `{4d36e967-e325-11ce-bfc1-08002be10318}` (GUID_DEVCLASS_DISKDRIVE) under USBSTOR. If different, not a USB-disk — USBSTOR only enumerates mass-storage disks; USB NICs/HIDs live under other Enum subkeys."
- name: service
  kind: identifier
  location: "<instance-id>\\Service value"
  type: REG_SZ
  note: "Always `disk` or `cdrom` on USBSTOR. `disk` = USB mass storage; `cdrom` = USB optical drive."
- name: mfg
  kind: identifier
  location: "<instance-id>\\Mfg value"
  type: REG_SZ
  encoding: utf-16le
  note: "Manufacturer as reported in INF (e.g., `(Standard disk drives)`). Generic — not device-reported. Don't confuse with `friendly-name`."
- name: location-information
  kind: identifier
  location: "<instance-id>\\LocationInformation value"
  type: REG_SZ
  encoding: utf-16le
  note: "Physical port location description, e.g., `Port_#0004.Hub_#0001`. Useful for distinguishing otherwise-identical devices connected to different USB ports."
observations:
- proposition: CONNECTED
  ceiling: C3
  qualifier-map:
    peer.vendor: field:vendor
    peer.product: field:product
    peer.serial: field:serial-number
    peer.container-id: field:container-id
    time.start: field:first-install-time
    time.end: field:last-arrival-time
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  audit-trail: "SYSTEM hive transaction logs (SYSTEM.LOG1, SYSTEM.LOG2) retain evidence of recent subkey deletions. yarp-print or Registry Explorer recovers."
  known-cleaners:
  - tool: USBOblivion
    typically-removes: true
  - tool: CCleaner-registry-module
    typically-removes: partial
  - tool: Privazer
    typically-removes: partial
  - tool: manual reg.exe delete
    typically-removes: true
  survival-signals:
  - "USBSTOR absent + EMDMgmt present for same InstanceID = SYSTEM-hive-targeted cleaner (USBOblivion classic) hit USBSTOR but missed SOFTWARE-hive EMDMgmt. High-confidence cleanup-attempt signal."
  - "USBSTOR absent + WindowsPortableDevices present = same pattern, different surviving artifact. SOFTWARE hive frequently survives SYSTEM-hive cleanup."
  - "Properties\\0067 (last-removal) equals Properties\\0066 (last-arrival) = driver-uninstall event, not a normal plug/unplug. Investigate: someone may have triggered device-uninstall to scrub arrival state."
provenance:
  - aboutdfir-nd-usb-devices-windows-artifact-r
  - hedley-2024-usbstor-install-first-install
  - regripper-plugins
  - matrix-dt021-usbstor-registry-key
---

# USBSTOR

## Forensic value
Canonical device-identity artifact for removable USB storage on Windows. Serial number (or ContainerID when the serial is OS-synthesized) is the primary pivot for cross-referencing MountedDevices, MountPoints2, WindowsPortableDevices, and setupapi.dev.log. For Win8+, the Properties subkey provides all four lifecycle timestamps without needing setupapi — but these timestamps are admin-editable, so cross-corroboration is non-negotiable for anything above C2 reporting.

## Known quirks
- **`&0` serial gotcha:** a `&` at position 2 means OS-synthesized serial. Not unique across same-model devices. Use ContainerID when present.
- **ContainerID survives reformat and repartition.** Does NOT survive controller replacement or crypto-erase.
- **Pre-Win8 has no Properties timestamps.** All timestamp evidence must come from setupapi.dev.log. Check for `setupapi.dev.log` at `%WINDIR%\INF\setupapi.dev.log` for first-install events.
- **Win10 22H2 0064/0065 parity** (Hedley 2024): `DEVPKEY_Device_InstallDate` (0064) and `DEVPKEY_Device_FirstInstallDate` (0065) frequently hold identical values. Treat as one observation, not two.
- **Surprise-removal gap:** `last-removal-time` (0067) only updates on Safely-Remove AND on driver-uninstall. Stale 0067 with recent 0066 = user yanked the drive (surprise-removal); 0067 == 0066 = driver-uninstall event.
- **`disk-id` IS NOT VolumeGUID.** Common confusion: `Device Parameters\Partmgr\DiskId` is a Partmgr-driver-assigned GUID for the disk, NOT the Mount-Manager VolumeGUID in MountedDevices. Joins between USBSTOR and MountedDevices happen via the InstanceID substring in binding-data, not via DiskId.
- **Optical drives also appear**: USBSTOR enumerates CD/DVD drives with `Service=cdrom`. If your analysis targets flash storage only, filter on `Service=disk`.

## Cross-references

| Joined to | Via | How |
|---|---|---|
| **EMDMgmt** | InstanceID substring | EMDMgmt subkey name contains the USBSTOR InstanceID verbatim — SOFTWARE-hive survivor when USBSTOR is cleaned |
| **MountedDevices** | InstanceID in binding-data | Format 1 (DEVICE-STRING) contains full InstanceID as UTF-16LE |
| **MountPoints2** | VolumeGUID via MountedDevices | Two-hop join: USBSTOR InstanceID → MountedDevices → VolumeGUID → MountPoints2 subkey |
| **WindowsPortableDevices** | InstanceID substring | WPD device-id path contains USBSTOR InstanceID |
| **Partition/Diagnostic-1006** | SerialNumber + ContainerID | Kernel event records both; the only cross-path with kernel-hardened integrity |
| **Amcache-InventoryDevicePnp** | InstanceID + ContainerID | Amcache's device inventory captures the same identity fields; survives USBSTOR deletion |
| **setupapi.dev.log** | InstanceID text match | Only source of first-install timestamp on pre-Win8 systems |
| **DriverFrameworks-Operational** | Device instance | EVTX channel records driver-level events keyed to the same InstanceID |

## Parsers

| Tool | Strengths |
|---|---|
| RegRipper (`usbstor.pl`, `usbdevices.pl` by Harlan Carvey) | Canonical. Parses InstanceIDs, timestamps, Properties subkeys. |
| Registry Explorer (Eric Zimmerman) | GUI + transaction-log replay for deleted-subkey recovery. |
| `regipy` (Python) | Programmatic; `regipy.plugins.system.usbstor` where available. |
| USBDeview (NirSoft) | Live-system or offline-hive view; decodes USBSTOR + MountedDevices together. |
| KAPE `RegistryHives_System` target | Bulk SYSTEM hive acquisition for offline USBSTOR parsing. |

## Anti-forensic caveats
Complete sanitization requires scrubbing all of: USBSTOR, MountedDevices, MountPoints2, setupapi.dev.log, EMDMgmt, DriverFrameworks-UserMode/Operational, WPDNSE, Amcache, and Partition/Diagnostic EVTX. No consumer cleaner hits all of these — asymmetric survival is an affirmative finding. The typical cleaning-tool coverage gap is the SOFTWARE hive (EMDMgmt, WindowsPortableDevices, Amcache) — tools targeting SYSTEM hive frequently miss these.

## Practice hint
13Cubed USB Forensics Parts 1–3; AboutDFIR Lone Wolf lab. Manual: plug unknown USB on clean Win10 VM, snapshot SYSTEM, unplug, replug, snapshot again. Diff Properties subkey against Partition/Diagnostic log. Then run USBOblivion; confirm USBSTOR cleared. Verify EMDMgmt and WindowsPortableDevices survived — that asymmetry IS the cleanup-attempt signal.
