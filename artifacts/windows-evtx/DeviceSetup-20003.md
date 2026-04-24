---
name: DeviceSetup-20003
title-description: "The driver service was successfully installed"
aliases:
- Device driver upgrade / reconfigure
link: device
tags:
- device-history
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
  event-id: 20003
  provider: Microsoft-Windows-UserPnp
  log-file: '%WINDIR%\System32\winevt\Logs\System.evtx'
  addressing: channel+event-id+provider
  note: "Authoritative producer is Microsoft-Windows-UserPnp writing to the System log. Template: UserpnpServiceInstall. Fires once per service creation during PnP-driven driver install, typically immediately preceding the matching 20001 (Driver Management concluded) for the same SubscriberContext."
fields:
- name: SubscriberContext
  kind: identifier
  location: EventData → SubscriberContext
  note: "PnP install-session identifier. Groups 20003 with the following 20001 and the surrounding KernelPnP-400/410 into a single install transaction."
- name: ServiceName
  kind: identifier
  location: EventData → ServiceName
  note: "SCM service name created by the install (e.g. WUDFRd, USBSTOR, WpdBusEnumRoot). Subsequently enumerable under HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>."
- name: DriverName
  kind: path
  location: EventData → DriverName
  note: "INF filename driving the service install (e.g. usbstor.inf)."
  references-data:
  - concept: ExecutablePath
    role: loadedModule
- name: ClassGuid
  kind: identifier
  location: EventData → ClassGuid
  encoding: guid-string
  note: "Setup class GUID for the device whose service is being created."
- name: DeviceInstanceId
  kind: identifier
  location: EventData → DeviceInstanceId
  note: "Target device node for which the service is being created."
  references-data:
  - concept: DeviceSerial
    role: usbDevice
- name: DriverPackageId
  kind: identifier
  location: EventData → DriverPackageId
  note: "Full driver-package form <inf>.inf_<arch>_<hash>. Matches DriverPackageId on the paired 20001."
- name: Status
  kind: status
  location: EventData → Status
  encoding: hex-uint32
  note: "Win32/NTSTATUS of the service-install operation. 0x0 = success."
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1us
  note: "Service-creation timestamp. Absent on driver updates that reuse an existing service — 20003 is per-new-service, not per-driver-install."
observations:
- proposition: DEVICE_RECONFIGURED
  ceiling: C3
  note: "Device driver upgrade or reconfiguration. Subsequent to an initial 20001 install — marks the moment a device's driver binding changed."
  qualifier-map:
    object.device.instance: field:DeviceInstanceId
    time.modified: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance:
  - uws-event-20003
---

# DeviceSetup-20003

## Forensic value
Device driver upgrade / reconfiguration event. Companion to 20001 (initial install). A host with 20001 followed by one or more 20003s on the same DeviceInstanceId shows a device whose driver was subsequently updated — natural on Windows Update cycles, suspicious if the driver provider changed unexpectedly.

## Join-key use
Same DeviceInstanceId anchor as 20001. The pair reveals first-install time + latest reconfigure time for a device; both are more precise than USBSTOR LastWrite.
