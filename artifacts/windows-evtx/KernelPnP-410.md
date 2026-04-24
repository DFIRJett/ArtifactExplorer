---
name: KernelPnP-410
title-description: "Device started"
aliases: [device node started, PnP device started]
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
  event-id: 410
  provider: Microsoft-Windows-Kernel-PnP
fields:
- name: DeviceInstanceId
  kind: identifier
  location: EventData → DeviceInstanceId
  note: "PnP device instance path — same canonical identifier as 400, USBSTOR, setupapi.dev.log, Security-6416."
  references-data:
  - {concept: DeviceSerial, role: usbDevice}
- name: ServiceName
  kind: identifier
  location: EventData → ServiceName
  note: "Function driver that handled IRP_MN_START_DEVICE (e.g. USBSTOR, disk). This is the driver that brought the device to the Started state — joins to Services registry for the ImagePath."
- name: DriverName
  kind: path
  location: EventData → DriverName
  note: "INF binding used for the successful start. Matches the DriverName in the preceding KernelPnP-400."
- name: ClassGuid
  kind: identifier
  location: EventData → ClassGuid
  encoding: guid-string
- name: DriverProvider
  kind: label
  location: EventData → DriverProvider
- name: DriverInbox
  kind: flags
  location: EventData → DriverInbox
  encoding: boolean
- name: DriverSectionName
  kind: label
  location: EventData → DriverSectionName
- name: DriverDate
  kind: timestamp
  location: EventData → DriverDate
  encoding: filetime-le
- name: DriverVersion
  kind: label
  location: EventData → DriverVersion
- name: Problem
  kind: enum
  location: EventData → Problem
  encoding: uint32
  note: "0 on successful start. CM_PROB_FAILED_START (10) on IRP failure — the device enumerated and configured but couldn't start. Classic 'Code 10' in Device Manager."
- name: ProblemStatus
  kind: identifier
  location: EventData → ProblemStatus
  encoding: hex-uint32
  note: "NTSTATUS of the failing START IRP. 0x00000000 on success; driver-specific otherwise."
- name: ParentDeviceInstanceId
  kind: identifier
  location: EventData → ParentDeviceInstanceId
  note: "Parent device in the PnP tree. For USBSTOR devices, the USB hub the device is attached through."
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1us
  note: "Written when the function driver returns from START. 400 without a following 410 for the same DeviceInstanceId = device enumerated but never came online (bad driver match, wrong bus, failed firmware)."
observations:
- proposition: DEVICE_STARTED
  ceiling: C3
  note: "Device moved to Started state after driver binding. 400 (configured) → 410 (started) sequence bounds the device-attachment window precisely."
  qualifier-map:
    object.device.instance: field:DeviceInstanceId
    time.started: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance:
  - hedley-2024-usbstor-install-first-install
  - libyal-libfwevt-libfwevt-windows-xml-event-log
---

# KernelPnP-410

## Forensic value
Device-started event. Paired with 400 (configured) via same DeviceInstanceId to bound the install-to-ready window. For USB mass-storage, the 410 is the moment a drive letter appears to the user.

## Cross-references
- **KernelPnP-400** — paired configure event
- **PartitionDiagnostic-1006** — volume mount event for storage devices
