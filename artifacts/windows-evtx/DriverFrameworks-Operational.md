---
name: DriverFrameworks-Operational
title-description: "UMDF driver operational events (per-event subdivisions)"
aliases:
- UMDF events
- User-Mode Driver Framework Operational
- WUDFPlatform events
link: device
tags:
- timestamp-carrying
- tamper-hard
volatility: runtime
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-DriverFrameworks-UserMode/Operational
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
    note: often disabled by default on Server SKUs
location:
  channel: Microsoft-Windows-DriverFrameworks-UserMode/Operational
  event-ids:
  - 2003
  - 2004
  - 2100
  - 2101
  - 2102
  - 2105
  log-file: '%WINDIR%\System32\winevt\Logs\Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx'
  addressing: channel+event-id
fields:
- name: time-created
  kind: timestamp
  location: System\TimeCreated SystemTime
  encoding: iso8601-utc
  clock: system
  resolution: 1us
- name: event-id
  kind: enum
  location: System\EventID
  encoding: uint16
  note: 2003=reflector-device-load, 2004=device-load, 2100=device-arrival, 2101=pnp-stop, 2102=lifetime-start, 2105=device-disabled
- name: device-instance-id
  kind: identifier
  location: UserData\UMDFHostDeviceRequest\InstanceId (schema varies by event id)
  encoding: ascii
  references-data:
  - concept: DeviceSerial
    role: usbDevice
  note: '''USB\VID_xxxx&PID_xxxx\<SERIAL>'' or ''USBSTOR\...\<SERIAL>'' form'
- name: lifetime
  kind: identifier
  location: UserData\UMDFHostDeviceRequest\lifetime (evt 2100/2101)
  encoding: ascii
  note: a GUID that identifies a single Device-Manager lifetime session — paired across arrive/depart
- name: operation-code
  kind: enum
  location: UserData fields per event
  encoding: integer-or-string
  note: maps to device-state transitions; specific semantics depend on event-id
observations:
- proposition: CONNECTED
  ceiling: C3
  note: 'Event 2003 fires when the User-Mode Driver Framework reflector loads

    a driver for a device — a strong signal that the device was present

    and enumerated. Paired 2100/2101 events bracket the connection''s

    start/end.

    '
  qualifier-map:
    peer.serial: field:device-instance-id
    time.start: field:time-created
  preconditions:
  - UMDF-Operational channel is enabled (on by default on client Windows; server SKU may need explicit enable)
  - channel retention covers target window
corroborates:
- with: USBSTOR
  proposition: CONNECTED
  via: device-instance-id substring match with USBSTOR <instance-id>
- with: PartitionDiagnostic-1006
  proposition: CONNECTED
  via: same device serial + close timestamp
- with: setupapi-dev-log
  proposition: CONNECTED
  via: same device serial string, setupapi records driver install, this records driver load
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX record/chunk checksums
  known-cleaners:
  - tool: USBOblivion
    typically-removes: false
    note: does not target EVTX channels
  - tool: wevtutil clear-log
    typically-removes: full
    note: emits Security 1102 for Security; for other channels, clearance is less tracked — check channel-clear events under
      different audit policies
  survival-signals:
  - DriverFrameworks-Operational channel populated + USBSTOR empty = targeted registry cleanup, EVTX missed
provenance:
  - matrix-dt024-driverframeworks-um
---

# Driver Frameworks Operational (UMDF)

## Forensic value
Kernel-adjacent evtx channel logging USB/PnP driver activity. Several event IDs carry device instance paths (with serial numbers embedded); together they document driver load, device arrival, pnp stop, and device disable events.

A forensically-rich secondary corroborator for USB-history claims. Event 2003 in particular fires on driver-load for each device attach and preserves enough identifier material to match back to USBSTOR without relying on the registry.

## Known quirks
- **UserData payload schema differs across event IDs.** Each event's XML layout is different; parsers must branch on event-id to extract fields correctly.
- **Not every USB attach produces every event in the sequence.** The 2100 arrive → 2003 load → 2101 depart pattern is the canonical full lifecycle but can be interrupted (surprise removal skips 2101, etc.).
- **Channel can be disabled on Server SKUs.** Check `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-DriverFrameworks-UserMode/Operational\Enabled` to confirm the channel is recording.

## Practice hint
Plug a USB on a live Win10 VM. Within seconds, run `wevtutil qe "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /c:5 /rd:true /f:text` — observe the ~2003 load event. Extract the device instance ID from its UserData block; confirm substring match against USBSTOR.
