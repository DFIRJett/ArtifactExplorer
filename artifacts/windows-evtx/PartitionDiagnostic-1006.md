---
name: PartitionDiagnostic-1006
title-description: "Partition-Diagnostic — disk and partition table capture"
aliases:
- Partition Diagnostic 1006
- kernel disk mount event
- Partmgr diagnostic event
link: device
tags:
- timestamp-carrying
- tamper-hard
- anti-forensic-resistant
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Partition/Diagnostic
platform:
  windows:
    min: '10.1803'
    max: '11'
  windows-server:
    min: '2019'
    max: '2022'
location:
  channel: Microsoft-Windows-Partition/Diagnostic
  event-id: 1006
  log-file: '%WINDIR%\System32\winevt\Logs\Microsoft-Windows-Partition%4Diagnostic.evtx'
  addressing: channel+event-id
fields:
- name: time-created
  kind: timestamp
  location: System\TimeCreated SystemTime attribute
  encoding: iso8601-utc
  clock: system
  resolution: 1us
  update-rule: set-at-event-emission
  note: kernel-timestamped at the moment of disk enumeration
- name: capacity
  kind: counter
  location: EventData\Capacity
  encoding: uint64
  note: device capacity in bytes — distinguishing factor between physically similar devices
- name: manufacturer
  kind: identifier
  location: EventData\Manufacturer
  encoding: utf-16le
- name: model
  kind: identifier
  location: EventData\Model
  encoding: utf-16le
- name: revision
  kind: identifier
  location: EventData\Revision
  encoding: utf-16le
- name: serial-number
  kind: identifier
  location: EventData\SerialNumber
  encoding: utf-16le
  references-data:
  - concept: DeviceSerial
    role: usbDevice
- name: parent-id
  kind: identifier
  location: EventData\ParentId
  encoding: utf-16le
  note: parent device instance path; resolves back to USBSTOR instance hierarchy
- name: container-id
  kind: identifier
  location: EventData\ContainerId
  encoding: guid-string
  references-data:
  - concept: ContainerID
    role: deviceIdentity
- name: registry-id
  kind: identifier
  location: EventData\RegistryId
  encoding: utf-16le
  note: maps directly to the USBSTOR <instance-id> for this device
- name: adapter-id
  kind: identifier
  location: EventData\AdapterId
  encoding: guid-string
  note: storage adapter GUID; identifies the host controller the device attached through
- name: partition-style
  kind: enum
  location: EventData\PartitionStyle
  encoding: uint8
  note: 0 = MBR, 1 = GPT, 2 = RAW
- name: mbr-disk-signature
  kind: identifier
  location: EventData\Mbr\Signature
  encoding: uint32
  references-data:
  - concept: MBRDiskSignature
    role: kernelMountRecord
  note: present when partition-style == MBR; 4-byte disk signature matching MountedDevices binding-data MBR-case encoding
- name: mbr-raw
  kind: content
  location: EventData\Mbr
  encoding: "raw first 512 bytes of the device's Master Boot Record (hex-encoded in the evtx). Disk signature at offset 0x1b8 (4 bytes LE), Master Partition Table follows."
  references-data:
  - concept: MBRDiskSignature
    role: kernelMountRecord
  note: "Full MBR dump — allows independent recomputation of disk signature and partition layout even if the signature field is stripped."
- name: vbr0-raw
  kind: content
  location: EventData\Vbr0
  encoding: "raw Volume Boot Record of device's 1st partition (hex-encoded). Filesystem-specific VSN offset: NTFS 0x48, FAT32 0x43, exFAT 0x64 (all 4 bytes LE). Identify FS via jump-instruction + OEM-ID bytes at offset 0."
  references-data:
  - concept: FilesystemVolumeSerial
    role: runtimeSerial
  note: "Vasilaras / Dragonas / Katsoulis 2021 (DFIR Review, doi 10.21428/b0ac9c28.de3816b0): Vbr0 carries the VSN of the device's FIRST partition AT CONNECTION TIME. Persists even after user reformats — provides historical VSN attribution."
- name: vbr1-raw
  kind: content
  location: EventData\Vbr1
  encoding: "raw VBR of device's 2nd partition (same offset rules as Vbr0)"
  references-data:
  - concept: FilesystemVolumeSerial
    role: runtimeSerial
  note: "Second VSN if device has 2+ partitions. Only present on multi-partition MBR devices."
- name: vbr2-raw
  kind: content
  location: EventData\Vbr2
  encoding: "raw VBR of device's 3rd partition (same offset rules as Vbr0)"
  references-data:
  - concept: FilesystemVolumeSerial
    role: runtimeSerial
  note: "Third VSN. Vbr3+ fields are NOT populated even on 4+ partition devices — the event schema is capped at three VBRs."
- name: gpt-disk-id
  kind: identifier
  location: EventData\Gpt\DiskId
  encoding: guid-string
  note: present when partition-style == GPT; disk-level GUID
- name: gpt-partition-ids
  kind: identifier
  location: EventData\Gpt\Partitions[]\PartitionId
  encoding: guid-string-array
  references-data:
  - concept: VolumeGUID
    role: mountedVolume
  - concept: GPTPartitionGUID
    role: kernelMountRecord
  note: GPT partition GUIDs; for GPT-formatted removables, one of these matches the VolumeGUID used by MountPoints2 and the 16-byte tail of MountedDevices' Format-3 binding-data (after the 'DMIO:ID:' prefix)
- name: vbr0
  kind: hash
  location: EventData\Vbr0
  encoding: hex-binary
  note: hash of the first 512 bytes of the VBR — can distinguish two devices that share a disk signature (rare but possible
    on cloned USBs)
- name: user-sid
  kind: identifier
  location: EventData\UserSid
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: actingUser
  note: user context at mount time — this is the single biggest reason this event is more forensically powerful than USBSTOR
    alone
observations:
- proposition: CONNECTED
  ceiling: C4
  note: kernel-logged, tamper-hard, carries user SID and volume GUID simultaneously
  qualifier-map:
    peer.serial: field:serial-number
    peer.container-id: field:container-id
    peer.capacity: field:capacity
    peer.manufacturer: field:manufacturer
    peer.model: field:model
    actor.user: field:user-sid
    time.start: field:time-created
    time.end: field:time-created
  preconditions:
  - EVTX file not cleared (check Security 1102 for clear events)
  - channel retained window overlaps target timeframe
anti-forensic:
  write-privilege: user
  integrity-mechanism: event record checksum + chunk CRC
  audit-trail: channel-clear events emit Security 1102 (if auditing is configured)
  known-cleaners:
  - tool: USBOblivion
    typically-removes: false
    note: does not target EVTX channels at all
  - tool: CCleaner
    typically-removes: false
  - tool: manual wevtutil clear-log
    typically-removes: true
    note: clears the entire channel and emits Security 1102
  - tool: log-evict (flood to force rotation)
    typically-removes: partial
  survival-signals:
  - PartitionDiagnostic-1006 present + USBSTOR absent = strong cleanup signal; USB cleaners almost never touch this channel
  - SerialNumber matches deleted USBSTOR entry's instance-id = device history reconstructible from EVTX alone
provenance:
  - vasilaras-2021-leveraging-the-microsoft-windo
  - hale-2018-partition-diagnostic-p1
  - hale-2018-partition-diagnostic-p2
  - carvey-2022-usb-devices-redux
exit-node:
  is-terminus: false
  terminates:
    - USED
  sources:
    - vasilaras-2021-leveraging-the-microsoft-windo
    - hale-2018-partition-diagnostic-p1
    - hale-2018-partition-diagnostic-p2
  reasoning: >-
    Event 1006 is kernel-written and carries UserSID, DeviceSerial,
    FilesystemVolumeSerial, GPTPartitionGUID/MBRDiskSignature, and VolumeGUID
    inline in a single record — satisfying all three USED inputs (user,
    device, time) without requiring a correlation step through MountPoints2.
    When the usual per-user NTUSER artifacts (MountPoints2, USBSTOR) have
    been wiped, this event alone still closes USED.
  implications: >-
    Canonical anti-forensic-survival anchor for USB exfiltration cases.
    Analysts can prove user-device attribution on systems where attacker
    wiped the registry USB-chain; pairs with USBSTOR-absent survival signal
    to detect and compensate for USB-trail cleanup. PartitionMgr channel
    is rarely targeted by off-the-shelf USB cleaners.
  preconditions: "UserSid != S-1-5-18 (system-account events exclude real-user attribution)"
  identifier-terminals-referenced:
    - UserSID
    - DeviceSerial
    - FilesystemVolumeSerial
    - VolumeGUID
    - GPTPartitionGUID
    - MBRDiskSignature
---

# Microsoft-Windows-Partition/Diagnostic Event 1006

## Forensic value
The single most evidentiarily powerful removable-storage artifact on modern Windows (10 1803+). Kernel-written, user-SID-embedded, tamper-hard, and largely untouched by consumer USB-history cleaners. A single event 1006 payload independently proves *who* connected *what device* at *what time*, with enough cross-reference material (serial, container-id, GPT partition-ids, VBR hash) to survive partial evidence destruction elsewhere.

Ceiling is C4 because it is kernel-logged and carries its own user attribution. Corroboration with MountPoints2 or USBSTOR pushes it to C5 via redundant tamper-independent sources.

## Cross-concept coverage
This one artifact carries fields that reference four shared concepts:
- **DeviceSerial** — from `SerialNumber`
- **ContainerID** — from `ContainerId`
- **VolumeGUID** — from `Gpt.Partitions[].PartitionId` (for GPT volumes)
- **UserSID** — from `UserSid`

That quadruple-reference is why it was the top crawl recommendation — authoring this single file closes four dangling concept-edges at once.

## Known quirks / silent-failure modes
- **Event was introduced in Windows 10 1803.** Earlier versions have no equivalent; don't search for it on 1709 or older.
- **UserSid field sometimes reports S-1-5-18** (SYSTEM) for service-triggered mounts. This is not "the user didn't do anything" — it means the mount happened outside an interactive session context. Correlate with Security 4624 to establish session overlap.
- **Vbr0 hash is a hash of the first 512 bytes of the Volume Boot Record**, not the whole filesystem. Two identically-formatted devices will produce the same hash; it distinguishes *physical copies* of a volume, not the volume's content.
- **GPT partition-ids are present only for GPT volumes** (modern, > 2TB, most USB-C storage). MBR volumes (legacy, small FAT drives) populate `Mbr.Signature` instead.
- **Channel rotates** — default max size is ~1MB on many builds. A busy system can roll PartitionDiagnostic in days. Acquire early.

## Anti-forensic caveats
The key signature: this event's absence-or-presence decouples from USBSTOR's. Consumer cleaners (USBOblivion, CCleaner) do not scrub EVTX channels. Finding an intact Partition/Diagnostic record for a device whose USBSTOR entry has been wiped is one of the highest-confidence "USB history cleanup was attempted" signals available.

The one cleanup path that does remove these events: `wevtutil clear-log Microsoft-Windows-Partition/Diagnostic`, which requires admin + emits Security event 1102 (if auditing for channel-clear is enabled). Absence of the Partition/Diagnostic channel combined with a Security 1102 for that channel is an affirmative forensic finding.

## Practice hint
- On a clean Win10 VM, plug a known USB. Use `wevtutil qe "Microsoft-Windows-Partition/Diagnostic" /c:5 /rd:true /f:text` to view the most recent events. Identify event 1006 and map its fields to the concept references above.
- Compare the event's `SerialNumber` to the USBSTOR instance-id — confirm the substring match.
- Run USBOblivion, re-query the channel — the events survive. This is the demonstration that defines this artifact's forensic value.
- Clear the channel with `wevtutil cl Microsoft-Windows-Partition/Diagnostic` (as admin). Check Security.evtx for event 1102. Observe that the clear itself leaves evidence.
