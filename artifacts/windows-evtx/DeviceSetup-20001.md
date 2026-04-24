---
name: DeviceSetup-20001
title-description: "Driver Management concluded the process to install driver"
aliases:
- Device install event
- DeviceSetup-Manager driver install
link: device
tags:
- device-history
- always-emitted
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-DeviceSetupManager/Admin
platform:
  windows:
    min: '7'
    max: '11'
location:
  channel: System
  event-id: 20001
  provider: Microsoft-Windows-UserPnp
  log-file: '%WINDIR%\System32\winevt\Logs\System.evtx'
  addressing: channel+event-id+provider
  note: "Also historically mis-attributed to Microsoft-Windows-DeviceSetupManager — the authoritative producer on modern Windows (10+) is Microsoft-Windows-UserPnp writing to the System log. Some older references and the project's own filename (DeviceSetup-*) reflect the older naming."
fields:
- name: SubscriberContext
  kind: identifier
  location: EventData → SubscriberContext
  note: "PnP install-session identifier. Groups a multi-event install sequence (20003 service-install → 20001 driver-install-end → KernelPnP-400 → KernelPnP-410) — join on SubscriberContext to reconstruct a single install transaction."
- name: DeviceInstanceId
  kind: identifier
  location: EventData → DeviceInstanceId
  note: "Matches the USBSTOR / USB / WPD instance path — the same string used as registry subkey names."
  references-data:
  - concept: DeviceSerial
    role: usbDevice
- name: DriverName
  kind: path
  location: EventData → DriverName
  note: "Selected INF filename for the install (e.g. usbstor.inf_amd64_<hash>). The actual INF used, not the device-class default."
  references-data:
  - concept: ExecutablePath
    role: loadedModule
- name: ClassGuid
  kind: identifier
  location: EventData → ClassGuid
  encoding: guid-string
  note: "Setup class GUID — DiskDrive, USB, Image, Keyboard, etc."
- name: DriverProvider
  kind: label
  location: EventData → DriverProvider
- name: DriverInbox
  kind: flags
  location: EventData → DriverInbox
  encoding: boolean
  note: "True when the driver shipped with Windows (%WINDIR%\\INF). False = installed from a third-party package via setupapi."
- name: DriverSectionName
  kind: label
  location: EventData → DriverSectionName
  note: "INF [Install] section name — matches DriverSectionName on the KernelPnP-400 for the same install."
- name: DriverVersion
  kind: label
  location: EventData → DriverVersion
- name: DriverDate
  kind: timestamp
  location: EventData → DriverDate
  encoding: filetime-le
  note: "INF DriverVer date — driver-authored build date, NOT install time."
- name: DriverPackageId
  kind: identifier
  location: EventData → DriverPackageId
  note: "Full driver-package form <inf>.inf_<arch>_<hash> — identifies the exact DriverStore entry used for the install. Joins to %WINDIR%\\System32\\DriverStore\\FileRepository\\<package> for file-level verification."
- name: BuildFilePath
  kind: path
  location: EventData → BuildFilePath
  note: "DriverStore path from which the install ran (C:\\Windows\\System32\\DriverStore\\FileRepository\\<package>\\...). Confirms the install source — non-DriverStore paths are anomalous."
- name: ServerName
  kind: identifier
  location: EventData → ServerName
  note: "Server name when the driver was pulled via Windows Update / WSUS. Empty for local/offline installs. Non-empty value = online-driver-install signal."
- name: Status
  kind: status
  location: EventData → Status
  encoding: hex-uint32
  note: "Win32/NTSTATUS of install. 0x0 = success; non-zero = partial-install (the device enumerated but setup phase failed)."
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1us
  note: "Authoritative first-install timestamp. 20001 fires ONLY on first install of a driver package for that device instance on that machine — reinsertions do NOT re-log it. That makes 20001's presence a high-confidence 'first time this device was seen here' indicator."
observations:
- proposition: DEVICE_INSTALLED
  ceiling: C3
  note: "Device install audit with DeviceInstanceId + driver identity + precise timestamp. Preferred source for first-connect time; USBSTOR LastWrite is subkey-level and less precise."
  qualifier-map:
    object.device.instance: field:DeviceInstanceId
    object.driver.name: field:DriverName
    time.installed: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance: [hedley-2024-usbstor-install-first-install, uws-event-20001, aboutdfir-nd-usb-devices-windows-artifact-r]
---

# DeviceSetup-20001

## Forensic value
Device-install timestamp from the DeviceSetupManager subsystem. PnP install events carry the DeviceInstanceId — the same identifier that names USBSTOR / USB / WPD registry subkeys. Join on DeviceInstanceId to precisely date first-connect, corroborating or supplementing the USBSTOR subkey LastWrite time (which can be imprecise due to registry hive write-buffering).

## Join-key use
DeviceInstanceId is the primary USB-device identifier join. For a suspicious USBSTOR entry, find the matching DeviceSetup-20001 and you have an authoritative install timestamp from an independent recording system.
