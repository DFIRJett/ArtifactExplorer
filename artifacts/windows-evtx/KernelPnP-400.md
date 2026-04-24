---
name: KernelPnP-400
title-description: "Device configured"
aliases: [device node configured, PnP device configuration]
link: device
tags: [device-history, always-emitted]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Kernel-PnP/Configuration
platform:
  windows: {min: '7', max: '11'}
location:
  channel: Microsoft-Windows-Kernel-PnP/Configuration
  event-id: 400
  provider: Microsoft-Windows-Kernel-PnP
fields:
- name: DeviceInstanceId
  kind: identifier
  location: EventData → DeviceInstanceId
  note: "PnP device instance path, e.g. USB\\VID_0781&PID_5567\\4C530001... — the canonical device-identity string used across USBSTOR, Enum\\USB, Security-6416, and setupapi.dev.log."
  references-data:
  - {concept: DeviceSerial, role: usbDevice}
- name: DriverName
  kind: path
  location: EventData → DriverName
  note: "INF file name of the selected driver (e.g. usbstor.inf, wpdfs.inf). Package-level identification; combine with DriverVersion for exact driver build."
- name: ClassGuid
  kind: identifier
  location: EventData → ClassGuid
  encoding: guid-string
  note: "Setup class GUID — {4d36e967-e325-11ce-bfc1-08002be10318} = DiskDrive, {4d36e96b-e325-11ce-bfc1-08002be10318} = Keyboard, {6bdd1fc6-810f-11d0-bec7-08002be2092f} = Image, etc."
- name: DriverProvider
  kind: label
  location: EventData → DriverProvider
  note: "INF Provider string — 'Microsoft' for inbox drivers, vendor names for third-party. Hunt signal: unexpected third-party provider on standard-class devices."
- name: DriverInbox
  kind: flags
  location: EventData → DriverInbox
  encoding: boolean
  note: "True when the driver shipped with Windows (from %WINDIR%\\INF). False = installed from a third-party package; correlate with DeviceSetup-20003 for the service-install event."
- name: DriverSection
  kind: label
  location: EventData → DriverSection
  note: "INF [Install] section name used for binding. Differentiates among installer variants within the same INF (e.g. 32-bit vs 64-bit, different device models). (Corrected 2026-04-23 from DriverSectionName per repnz ETW manifest Win10 17134.)"
- name: DriverDate
  kind: timestamp
  location: EventData → DriverDate
  encoding: filetime-le
  note: "INF DriverVer date string (parsed to FILETIME). The driver-authored build date, NOT the install time — distinguishes kernel-PnP install events from driver build metadata."
- name: DriverVersion
  kind: label
  location: EventData → DriverVersion
  note: "INF DriverVer version string (e.g. '10.0.19041.1'). Exact driver build identifier."
- name: DriverRank
  kind: enum
  location: EventData → DriverRank
  encoding: hex-uint32
  note: "Driver-match ranking priority (lower numeric value = better match). Example live value: 0xfb2006. Forensic signal: flag unexpectedly-low rank — detects drive-by driver-swap where a forced lower-rank driver was installed. Added per repnz ETW manifest."
- name: MatchingDeviceId
  kind: identifier
  location: EventData → MatchingDeviceId
  encoding: unicode-string
  note: "The device-ID string the INF matched against — may be more generic than DeviceInstanceId (e.g. USB\\VID_0781&PID_5567 without the instance suffix). Distinguishes exact-match driver binding vs fallback/generic binding. Added per repnz ETW manifest."
- name: OutrankedDrivers
  kind: label
  location: EventData → OutrankedDrivers
  encoding: unicode-string
  note: "List of drivers that were considered but superseded by the selected one. Forensic signal: anomalous OutrankedDrivers population can indicate manual driver selection or installer-package injection. Added per repnz ETW manifest."
- name: FirmwareDate
  kind: timestamp
  location: EventData → FirmwareDate
  encoding: filetime-le
  note: "Optional — populated only for firmware-update-capable devices via FIRMWARE_ID. Absent on simple storage / HID devices. (Win11-era behavior unverified against a newer manifest — 17134-era confirmed.)"
- name: FirmwareVersion
  kind: label
  location: EventData → FirmwareVersion
  note: "Optional — firmware version string when the device exposes a Firmware ID. (Win11-era behavior unverified against a newer manifest.)"
- name: FirmwareRevision
  kind: label
  location: EventData → FirmwareRevision
  note: "Optional — firmware revision identifier. Correlates with IOCTL_STORAGE_QUERY_PROPERTY → StorageDeviceIdProperty on the same device. (Win11-era behavior unverified against a newer manifest.)"
- name: DeviceUpdated
  kind: flags
  location: EventData → DeviceUpdated
  encoding: boolean
  note: "True when the device's driver was UPDATED during this configuration (vs first-time configuration). Critical for distinguishing FIRST-CONNECT events from driver-update reconfigurations — first connect is more precisely 'first 400 with DeviceUpdated=false' than 'first 400 for a given DeviceInstanceId' alone. Added per repnz ETW manifest."
- name: Status
  kind: enum
  location: EventData → Status
  encoding: hex-uint32
  note: "Configuration completion status (NTSTATUS). 0x0 = success; non-zero = kernel-level configuration error. Replaces the prior DeviceStatus / ProblemStatus entries that were incorrectly conflated from event 410. Added per repnz ETW manifest."
- name: ParentDeviceInstanceId
  kind: identifier
  location: EventData → ParentDeviceInstanceId
  note: "Parent device in the PnP tree (hub or controller). For USBSTOR devices, ParentDeviceInstanceId resolves to the USB\\ROOT_HUB / hub instance above — essential for reconstructing the physical port path."
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1us
  note: "Kernel-timestamped at configuration. First 400 WITH DeviceUpdated=false for a given DeviceInstanceId = first-ever device configuration on this host (the DeviceUpdated flag disambiguates first-connect from driver-update reconfiguration — refined 2026-04-23 per repnz ETW manifest)."
observations:
- proposition: DEVICE_CONFIGURED
  ceiling: C3
  note: "Kernel-level PnP device configuration event. Complements DeviceSetup-20001 at a different layer — kernel-PnP fires EARLIER (before driver install), giving a tighter first-seen timestamp for device connection."
  qualifier-map:
    object.device.instance: field:DeviceInstanceId
    time.configured: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance: [hedley-2024-usbstor-install-first-install, libyal-libfwevt-libfwevt-windows-xml-event-log, repnz-etw-providers-docs-kernel-pnp-manifest, nsacyber-event-forwarding-usb-detection]
---

# KernelPnP-400

## Forensic value
Kernel-level device-configuration event. Emits when the PnP manager configures a device node — often BEFORE driver install events (DeviceSetup-20001). Gives the earliest authoritative connect timestamp for a device that reports PnP. Harder to disable than user-mode logs because it comes from kernel-PnP code.

## Cross-references
- **DeviceSetup-20001** — later driver-install event; same DeviceInstanceId
- **USBSTOR** / **USB-Enum** — registry persistence for the same device
- **KernelPnP-410** — device started; `ServiceName` + `Problem` + `ProblemStatus` fields belong here, NOT 400 (corrected 2026-04-23)

## Field-block provenance
Field list verified 2026-04-23 against the repnz ETW manifest dump (Win10 17134). ServiceName + Problem + ProblemStatus removed from 400 — they belong to event 410 (device started) and were incorrectly conflated. DriverSectionName renamed to DriverSection. Added: DriverRank, MatchingDeviceId, OutrankedDrivers, DeviceUpdated, Status. The corpus fields for FirmwareDate / FirmwareVersion / FirmwareRevision are confirmed against 17134 but Win11-era additions have not been checked against a newer manifest. Sibling events 410 / 411 / 430 / 441 / 442 share significant field overlap and are queued for authoring in a future Kernel-PnP family sprint.
