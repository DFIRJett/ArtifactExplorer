---
name: DEVICE_CONNECTED
summary: "Per-session device-attachment proposition. Joins USB-class artifact cluster (USBSTOR + MountPoints2 + WindowsPortableDevices + setupapi-dev-log + friends) with upgrade-window device enumeration (Setupapi-Upgrade-Log) via DeviceSerial + ContainerID pivots. Exit-node cluster anchors on USBSTOR + setupapi-dev-log."
yields:
  mode: new-proposition
  proposition: DEVICE_CONNECTED
  ceiling: C3
inputs:
  - CONNECTED
  - EXECUTED_DURING_UPGRADE
input-sources:
  - proposition: CONNECTED
    artifacts:
      - USBSTOR
      - USB-Enum
      - MountedDevices
      - MountPoints2
      - WindowsPortableDevices
      - EMDMgmt
      - setupapi-dev-log
      - DriverFrameworks-Operational
      - PartitionDiagnostic-1006
  - proposition: EXECUTED_DURING_UPGRADE
    artifacts:
      - Setupapi-Upgrade-Log
join-chain:
  - concept: DeviceSerial
    join-strength: strong
    sources:
      - carvey-2022-usb-devices-redux
      - hedley-2024-usbstor-install-first-install
      - matrix-dt021-usbstor-registry-key
    description: |
      Device-identity pivot. USBSTOR records the vendor/product/
      revision/serial of every USB mass-storage class device that has
      ever enumerated on the host, indexed on serial. setupapi-dev-log
      records the same serial as a string inside its device-install
      entries with a precise timestamp. USB-Enum at
      Enum\USB\VID_xxxx&PID_yyyy\<instance-id> mirrors the serial for
      non-storage classes (HID, CCID, phones in MTP mode). Joining on
      DeviceSerial binds a specific physical device to a specific
      timestamped install event — the "this exact USB stick, first
      seen at 14:23:17 UTC" claim.
    artifacts-and-roles:
      - artifact: USBSTOR
        role: deviceIdentity
      - artifact: setupapi-dev-log
        role: installEvent
      - artifact: USB-Enum
        role: deviceIdentity
  - concept: ContainerID
    join-strength: strong
    sources:
      - matrix-dt021-usbstor-registry-key
      - hedley-2024-usbstor-install-first-install
    description: |
      Logical-device pivot. ContainerID is a GUID the PnP manager
      assigns per physical device and propagates across every
      registry surface that describes that device — USBSTOR,
      WindowsPortableDevices (MTP devices), MountPoints2 (mounted
      volumes), DriverFrameworks Operational (kernel-mode driver
      load events). Joining on ContainerID reconciles the
      USB-mass-storage view with the MTP-portable-device view with
      the volume-mount view — critical when a single phone plugs
      in as both an MTP device AND a mass-storage volume, where
      DeviceSerial alone would see them as separate devices.
    artifacts-and-roles:
      - artifact: USBSTOR
        role: deviceIdentity
      - artifact: WindowsPortableDevices
        role: deviceIdentity
      - artifact: MountPoints2
        role: deviceIdentity
      - artifact: DriverFrameworks-Operational
        role: deviceIdentity
  - concept: VolumeGuid
    join-strength: strong
    sources:
      - matrix-dt021-usbstor-registry-key
      - carvey-2022-usb-devices-redux
    description: |
      Volume-to-device pivot. MountedDevices stores a
      \DosDevices\<drive-letter> → volume-GUID mapping at the moment
      of mount; MountPoints2 stores the per-user volume-GUID the
      user "saw"; EMDMgmt binds volume serial + volume label to the
      same device instance. Joining on VolumeGuid establishes
      "this exact mounted volume was assigned drive letter E: for
      this user at this time" — connecting the device-identity
      chain to the user-perspective file-system evidence needed
      to locate artifacts like RecentDocs and Shellbags that
      reference drive-letter paths.
    artifacts-and-roles:
      - artifact: MountedDevices
        role: volumeMount
      - artifact: MountPoints2
        role: volumeMount
      - artifact: EMDMgmt
        role: volumeMount
  - concept: TimeWindow
    join-strength: moderate
    sources:
      - hedley-2024-usbstor-install-first-install
      - kobzar-2021-windows-updates-anti-forensics-usb
    description: |
      Temporal-bracketing pivot. setupapi-dev-log carries the
      precise install timestamp; DriverFrameworks Operational /
      PartitionDiagnostic-1006 carry per-event timestamps for
      driver-load + partition-enumerate events; Setupapi-Upgrade-Log
      carries upgrade-window timestamps. Joining on TimeWindow
      lets an analyst correlate the FIRST-SEEN moment
      (setupapi-dev-log first install) against steady-state
      USBSTOR re-mount events and the Setupapi-Upgrade-Log rescue
      view for devices that were enumerated ONLY during a feature
      upgrade (a common anti-forensic pattern where attackers
      attach removable media only for the upgrade window and
      remove it before steady-state logs capture it).
    artifacts-and-roles:
      - artifact: setupapi-dev-log
        role: timeAnchor
      - artifact: DriverFrameworks-Operational
        role: timeAnchor
      - artifact: PartitionDiagnostic-1006
        role: timeAnchor
      - artifact: Setupapi-Upgrade-Log
        role: timeAnchor
exit-node:
  - USBSTOR
  - setupapi-dev-log
notes:
  - 'USBSTOR: canonical device-identity record — VID/PID/Serial + ContainerID + first-seen LastWrite timestamps on sub-keys. Exit-node: every other USB artifact can be re-derived from here given a DeviceSerial.'
  - 'setupapi-dev-log: timestamped plain-text install log — authoritative FIRST-SEEN timestamp for every enumerated device. Exit-node paired with USBSTOR: identity + time.'
  - 'USB-Enum: non-storage USB classes (HID, CCID, MTP pre-mount). Covers devices that never manifest in USBSTOR.'
  - 'MountedDevices: \DosDevices\ → volume-GUID mapping at mount time. Bridges device → drive-letter.'
  - 'MountPoints2: per-user volume-GUID record — reflects which volumes a specific user saw. Binds DEVICE_CONNECTED to user attribution.'
  - 'WindowsPortableDevices: MTP device identities (phones, cameras). Captures the non-mass-storage view.'
  - 'EMDMgmt: ReadyBoost enumeration record — carries volume serial + label. Corroborates MountedDevices.'
  - 'DriverFrameworks-Operational: kernel-mode driver-load events per device. Close-to-PnP-layer evidence.'
  - 'PartitionDiagnostic-1006: partition-enumeration evidence. Confirms actual disk-geometry read, not just PnP surface registration.'
  - 'Setupapi-Upgrade-Log: upgrade-window device-enumeration rescue view — catches devices that never landed in steady-state logs. Anti-forensic counter: a device attached ONLY during a Windows feature upgrade will be absent from setupapi-dev-log / USBSTOR but present here.'
provenance:
  - ms-setupapi-logging-file-locations-and
  - matrix-dt021-usbstor-registry-key
  - carvey-2022-usb-devices-redux
  - hedley-2024-usbstor-install-first-install
  - kobzar-2021-windows-updates-anti-forensics-usb
  - 13cubed-2020-print-job-forensics-recovering
  - project-2023-windowsbitsqueuemanagerdatabas
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — DEVICE_CONNECTED

Tier-2 convergence yielding proposition `DEVICE_CONNECTED`.

Binds ten artifacts across the USB-class device cluster. Device identity is anchored by USBSTOR + setupapi-dev-log (exit-nodes); containerization pivots bridge USB mass-storage / MTP / volume views; temporal bracketing resolves upgrade-window-only device attachments.

Participating artifacts: USBSTOR, USB-Enum, MountedDevices, MountPoints2, WindowsPortableDevices, EMDMgmt, setupapi-dev-log, DriverFrameworks-Operational, PartitionDiagnostic-1006, Setupapi-Upgrade-Log.
