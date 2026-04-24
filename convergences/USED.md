---
name: USED
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: USED
  ceiling: C3
inputs:
  - ACCESSED
  - CONNECTED
  - POSSESSED
input-sources:
  - proposition: ACCESSED
    artifacts:
      - AutomaticDestinations
      - CustomDestinations
      - ShellBags
      - ShellLNK
  - proposition: CONNECTED
    artifacts:
      - EMDMgmt
      - MountPoints2
      - MountedDevices
      - PartitionDiagnostic-1006
      - USBSTOR
      - WindowsPortableDevices
  - proposition: POSSESSED
    artifacts:
      - MountPoints2
join-chain:
  - concept: DeviceSerial
    join-strength: strong
    sources:
      - hedley-2024-usbstor-install-first-install
      - aboutdfir-nd-usb-devices-windows-artifact-r
      - vasilaras-2021-leveraging-the-microsoft-windo
      - hale-2018-partition-diagnostic-p1
      - libyal-libregf
    primary-source: aboutdfir-nd-usb-devices-windows-artifact-r
    attribution-sentence: "USBSTOR contains an entry for every USB device connected to the system, keyed on the device's instance ID which includes the vendor-assigned serial number — this serial is what threads the device identity across MountedDevices, EMDMgmt, WindowsPortableDevices, and PartitionDiagnostic-1006."
    description: |
      Device-identity pivot threading the CONNECTED input artifacts.
      USBSTOR subkey names encode DeviceSerial; EMDMgmt subkey names
      include the serial as the composite-key suffix; MountedDevices
      binary binding-data embeds the serial in the DEVICE-STRING form;
      PartitionDiagnostic-1006 logs DeviceSerial in the EVTX event;
      WindowsPortableDevices carries it in the WPDBUSENUM subkey;
      MountPoints2 references it via the VolumeGUID→DeviceSerial chain.
      Strong pivot — globally unique per vendor-cooperative devices.
      Without it, device-identity claims rely on USBSTOR alone, which
      is attacker-clearable.
    artifacts-and-roles:
      - artifact: USBSTOR
        role: usbDevice
      - artifact: EMDMgmt
        role: usbDevice
      - artifact: MountedDevices
        role: usbDevice
      - artifact: PartitionDiagnostic-1006
        role: usbDevice
      - artifact: WindowsPortableDevices
        role: usbDevice
      - artifact: MountPoints2
        role: usbDevice
  - concept: VolumeGUID
    join-strength: moderate
    sources:
      - libyal-liblnk
      - ms-shllink
      - libyal-libolecf
      - libyal-libfwsi
      - aboutdfir-nd-usb-devices-windows-artifact-r
    primary-source: ms-shllink
    attribution-sentence: "A LinkTargetIDList structure carries a VolumeID shell item that encodes the volume's drive type, serial number, and label — this is the cross-artifact binding the Shell Link (.LNK) format uses to identify the volume from which a referenced object was opened."
    description: |
      Volume-level pivot bridging device-identity to filesystem artifacts.
      MountedDevices binds VolumeGUID to device-instance; MountPoints2
      per-user entries key on VolumeGUID; AutomaticDestinations /
      CustomDestinations / ShellBags / ShellLNK embed VolumeGUID (or its
      FilesystemVolumeSerial derivative) in the shell-item chain /
      LNK header. VolumeGUID is moderate-strength because it's
      regenerated on volume reformat, but globally unique otherwise —
      the pivot that ties "a user opened file X" (ACCESSED input) to
      "device D was connected" (CONNECTED input).
    artifacts-and-roles:
      - artifact: MountedDevices
        role: accessedVolume
      - artifact: MountPoints2
        role: accessedVolume
      - artifact: AutomaticDestinations
        role: accessedVolume
      - artifact: CustomDestinations
        role: accessedVolume
      - artifact: ShellBags
        role: accessedVolume
      - artifact: ShellLNK
        role: accessedVolume
  - concept: UserSID
    join-strength: strong
    sources:
      - libyal-libregf
      - online-2021-registry-hive-file-format-prim
      - hale-2018-partition-diagnostic-p1
      - libyal-liblnk
    primary-source: libyal-libregf
    attribution-sentence: "Each Windows user profile carries its own NTUSER.DAT registry hive whose path embeds the account's SID — artifacts rooted under HKCU (MountPoints2, ShellBags, AutomaticDestinations, CustomDestinations) therefore attribute their contents to a specific UserSID by filesystem location alone, independent of any in-hive field."
    description: |
      User-attribution pivot closing the USED claim. MountPoints2 lives
      per-user in NTUSER (POSSESSED input proves THIS user recognized
      the device); ShellBags / ShellLNK / AutomaticDestinations /
      CustomDestinations are per-user artifacts. PartitionDiagnostic-1006
      uniquely carries a user-sid field inline — CAN close USED without
      MountPoints2 when the per-user registry is cleaned. Full
      convergence: DeviceSerial identifies the device, VolumeGUID
      identifies the volume presented, UserSID attributes the interaction
      to a specific account. Missing any one → degradation path.
    artifacts-and-roles:
      - artifact: MountPoints2
        role: identitySubject
      - artifact: ShellBags
        role: identitySubject
      - artifact: ShellLNK
        role: identitySubject
      - artifact: AutomaticDestinations
        role: identitySubject
      - artifact: CustomDestinations
        role: identitySubject
      - artifact: PartitionDiagnostic-1006
        role: actingUser
exit-node:
  - PartitionDiagnostic-1006
  - ProfileList
via-artifacts:
  - EMDMgmt
  - MountPoints2
  - MountedDevices
  - USBSTOR
notes:
  - 'PartitionDiagnostic-1006: uniquely, this artifact can close USED without needing MountPoints2 — the user-sid field is captured inline'
  - 'ShellLNK: when the LNK''s volume-label / volume-GUID matches a MountPoints2 entry under the same user, this closes USED(user, removable-device) via the file that was opened from it'
  - 'EMDMgmt: EMDMgmt doesn''t carry user SID itself (HKLM hive, not user-scoped). USED chain: EMDMgmt provides CONNECTED(device=D, time=T) → correlate with MountPoints2 under NTUSER.DAT for user U → derives USED(U, D). When USBSTOR has been cleaned but EMDMgmt survives, EMDMgmt IS the CONNECTED anchor for the chain.'
  - 'MountPoints2: MountPoints2 supplies the POSSESSED input (device in user scope). CONNECTED comes from USBSTOR (primary) or MountedDevices (VolumeGUID join). When MountPoints2 has been cleaned per-user but SYSTEM-hive artifacts survived, USED collapses to session-window inference.'
  - 'ShellBags: closing USED(user, removable-device) via ShellBags requires the volume identity in the shell-item chain to match a volume-GUID/serial tracked in MountPoints2'
  - 'USBSTOR: POSSESSED input is per-user (NTUSER.DAT MountPoints2). When MountPoints2 has been cleaned, fall back to EMDMgmt (SOFTWARE hive — typically survives) for CONNECTED corroboration, then session-window-infer the user.'
  - 'WindowsPortableDevices: WPD is HKLM-scoped (no user context). USED chain: WPD provides CONNECTED → MountPoints2 provides POSSESSED via NTUSER-profile ownership → USED derived. When USBSTOR is cleaned, WPD frequently becomes the primary CONNECTED anchor.'
provenance:
  - libyal-liblnk
  - libyal-libolecf
  - ms-shllink
  - ms-cfb
  - online-2021-registry-hive-file-format-prim
  - libyal-libfwsi
  - libyal-libregf
  - aboutdfir-nd-usb-devices-windows-artifact-r
  - vasilaras-2021-leveraging-the-microsoft-windo
  - libyal-libfwevt-libfwevt-windows-xml-event-log
  - hale-2018-partition-diagnostic-p1
  - hedley-2024-usbstor-install-first-install
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - ms-advanced-audit-policy
  - regripper-plugins
---

# Convergence — USED

Tier-2 convergence yielding proposition `USED`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: AutomaticDestinations, CustomDestinations, EMDMgmt, MountPoints2, MountedDevices, PartitionDiagnostic-1006, ShellBags, ShellLNK, USBSTOR, WindowsPortableDevices.
