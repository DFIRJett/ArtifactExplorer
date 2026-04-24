---
name: Security-6416
title-description: "A new external device was recognized by the System"
aliases: [external device recognized, PnP audit]
link: device
tags: [device-history, audit-policy-dependent]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: {min: '10.1511', max: '11'}
location:
  channel: Security
  event-id: 6416
  provider: Microsoft-Windows-Security-Auditing
  requirement: "auditpol /set /subcategory:\"Plug and Play Events\" /success:enable — OFF by default"
fields:
- name: SubjectUserSid
  kind: identifier
  location: EventData → SubjectUserSid
  note: "always SYSTEM / S-1-5-18 — PnP runs in kernel context; real attribution comes from correlating timestamp with user-context events"
  references-data:
  - {concept: UserSID, role: actingUser}
- name: SubjectUserName
  kind: identifier
  location: EventData → SubjectUserName
  note: "always the machine account — computer name with trailing $ — reflecting that PnP runs as SYSTEM not an interactive user"
- name: SubjectDomainName
  kind: identifier
  location: EventData → SubjectDomainName
  note: "domain / workgroup name; in local contexts equals computer name"
- name: SubjectLogonId
  kind: identifier
  location: EventData → SubjectLogonId
  note: "always 0x3e7 (SYSTEM logon) — same caveat"
  references-data:
  - {concept: LogonSessionId, role: sessionContext}
- name: DeviceId
  kind: identifier
  location: EventData → DeviceId
  note: "PnP instance path — casing trap: DeviceId (not DeviceInstanceId as used by Kernel-PnP)"
  references-data:
  - {concept: DeviceSerial, role: usbDevice}
- name: DeviceDescription
  kind: label
  location: EventData → DeviceDescription
- name: ClassId
  kind: identifier
  location: EventData → ClassId
- name: ClassName
  kind: label
  location: EventData → ClassName
- name: VendorIds
  kind: label
  location: EventData → VendorIds
- name: CompatibleIds
  kind: label
  location: EventData → CompatibleIds
- name: LocationInformation
  kind: label
  location: EventData → LocationInformation
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: DEVICE_RECOGNIZED
  ceiling: C3
  note: "Fires on EVERY connection (not only first). A single USB flash drive generates ~6 events — one per stack node (hub, USBSTOR, Disk, Volume, WPD). Filter on DeviceId uniqueness for unique-device-per-connect counts."
  qualifier-map:
    object.device.id: field:DeviceId
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: service
  requirement: "Audit PNP Activity = Success (subcategory of Detailed Tracking) must be enabled"
provenance: [ms-event-6416, uws-event-6416]
---

# Security-6416

## Forensic value
Plug-and-Play audit event — fires when any external device is recognized. Distinct from first-install events (DeviceSetup-20001) because 6416 fires on EVERY connect, giving the full reconnect timeline.

Required subcategory is OFF by default — common gap. When present, provides the cleanest audited device-connect log with full device identification.

## Casing trap
This event uses `DeviceId` (capital D, lowercase d). Kernel-PnP 400/410 use `DeviceInstanceId`. UserPnp 20001/20003 use `DeviceInstanceID` (uppercase ID). All refer to the same PnP path but SIEM queries must match the exact casing per source.

## Cross-references
- **DeviceSetup-20001** — driver install (subset of 6416)
- **KernelPnP-400/410** — kernel configure/start events
- **USBSTOR** / **USB-Enum** — registry persistence
- **Partition/Diagnostic-1006** — volume mount companion
