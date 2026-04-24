---
name: Departing employee — USB exfiltration with cleanup
anchors:
  entry: UserSID
  conclusions:
  - LogonSessionId
  - DeviceSerial
  - ContainerID
  - VolumeGUID
  - FilesystemVolumeSerial
severity: case-study
summary: 'Insider-threat scenario: an employee on notice copies sensitive files

  to an external USB drive on their last day, modifies the Windows

  Firewall to allow a staging egress path, then attempts cleanup by

  clearing USBSTOR before returning the device.

  '
narrative: "Tier-3 analyst is handed a corporate laptop belonging to a recently\ndeparted employee. Suspected data theft via removable media. The\nfollowing chain needs to be established end-to-end:\n\n\
  1. User logged on interactively (Security-4624, logon type 2) —\n   establishes LogonSessionId for the session window.\n2. Within that session, explorer.exe / PowerShell processes ran\n   (Security-4688)\
  \ — each 4688 carries SubjectLogonId matching the\n   4624, and NewProcessId becomes the acting-process key.\n3. Files on the C:\\ drive accessed (Security-4663 if Object-Access\n   SACL enabled, OR Recent-LNK\
  \ entries, OR ShellBags traversal).\n   4663 carries both SubjectLogonId and ProcessId for full chain.\n4. External USB device connected (USBSTOR + MountedDevices +\n   EMDMgmt + PartitionDiagnostic-1006\
  \ + MountPoints2 per-user).\n5. Files copied TO the USB — Recent-LNK on USB's FilesystemVolumeSerial;\n   jump-list entries for Explorer showing the USB's VolumeGUID;\n   Prefetch for any copy utility\
  \ used.\n6. Windows Firewall rule added/modified for the cleanup egress path\n   (Firewall-2004 or Firewall-2005) with ModifyingUser SID matching\n   the session + ModifyingApplication path matching a\
  \ 4688 process.\n7. Rule deleted before departure (Firewall-2006) — present in EVTX\n   but absent from current registry state.\n8. Attempted cleanup: USBSTOR subkeys deleted. But EMDMgmt,\n   WindowsPortableDevices\
  \ (HKLM\\SOFTWARE), and PartitionDiagnostic-1006\n   (EVTX) survive — providing the device-identity trail.\n\nEvery step joins to the next via a shared concept. Walking the\njoin-key graph from the session\
  \ LUID forward reconstructs the\nuser's complete activity window — including the cleanup attempt\nitself, which becomes an affirmative finding once asymmetric\nartifact survival is confirmed.\n"
join-keys:
- concept: UserSID
  role: authenticatingUser
- concept: LogonSessionId
  role: sessionContext
- concept: ProcessId
  role: actingProcess
- concept: DeviceSerial
  role: usbDevice
- concept: ContainerID
  role: deviceIdentity
- concept: VolumeGUID
  role: accessedVolume
- concept: FilesystemVolumeSerial
  role: runtimeSerial
- concept: VolumeLabel
  role: accessedAtLabel
- concept: ExecutablePath
  role: actingProcess
artifacts:
  primary:
  - Security-4624
  - Security-4688
  - Security-4663
  - USBSTOR
  - EMDMgmt
  - PartitionDiagnostic-1006
  - MountedDevices
  - MountPoints2
  - Recent-LNK
  - ShellBags
  - Firewall-2004
  - Firewall-2005
  - Firewall-2006
  corroborating:
  - WindowsPortableDevices
  - Amcache-InventoryDevicePnp
  - AutomaticDestinations
  - JumpList-Embedded-LNK
  - Prefetch
  - Security-4634
provenance:
- ms-event-4624
- uws-event-4624
- ms-event-4688
- ms-include-command-line-in-process-cre
- uws-event-4688
- ms-event-4663
- uws-event-4663
- aboutdfir-nd-usb-devices-windows-artifact-r
- hedley-2024-usbstor-install-first-install
- libyal-libregf
- vasilaras-2021-leveraging-the-microsoft-windo
- libyal-libfwevt-libfwevt-windows-xml-event-log
- hale-2018-partition-diagnostic-p1
- libyal-liblnk
- ms-shllink
- online-2021-registry-hive-file-format-prim
- libyal-libfwsi
- ms-windows-defender-firewall-registry
- mitre-t1562-004
- libyal-libevtx
- rathbun-2023-program-compatibility-assistan
- libyal-libolecf
- ms-cfb
- carvey-2022-windows-forensic-analysis-tool
- libyal-libscca
- ms-event-4634
- uws-event-4634
- casey-2002-error-uncertainty-loss-digital-evidence
- casey-2020-standardization-evaluative-opinions
- forensicartifacts-repo
- kape-files-repo
- insiderthreatmatrix-repo
- thedfirreport
- ms-advanced-audit-policy
- regripper-plugins
steps:
- n: 1
  question: What user logon defines the session window of interest?
  artifacts:
  - Security-4624
  join-key:
    concept: LogonSessionId
    role: sessionContext
  primary-source: ms-event-4624
  attribution-sentence: Event 4624 records a successful account logon and emits TargetLogonId, a hex LUID that uniquely identifies the session until the matching 4634 logoff closes it, threading every in-session
    event through a single session scope (Microsoft, n.d.).
  conclusion: Security-4624 Type-2 (interactive-console) logon establishes the TargetLogonId LUID. All subsequent process-creation and object-access events within this session join here. Anchors the entire
    chain — without this, every downstream join is uncorroborated.
  attribution: User → Session
  casey: C4
- n: 2
  question: What processes ran inside the session window?
  artifacts:
  - Security-4688
  join-key:
    concept: LogonSessionId
    role: sessionContext
  primary-source: ms-event-4624
  attribution-sentence: Event 4624 records a successful account logon and emits TargetLogonId, a hex LUID that uniquely identifies the session until the matching 4634 logoff closes it, threading every in-session
    event through a single session scope (Microsoft, n.d.).
  conclusion: Security-4688 with SubjectLogonId == Step 1's LUID names every process the session spawned (explorer.exe, PowerShell, copy utilities). NewProcessId becomes the per-process join key for subsequent
    object-access events. Anomalous parents (explorer → powershell → cmd → robocopy) are the cleanup-scripting signal.
  attribution: Session → Process
  casey: C4
- n: 3
  question: 'Which files on the C: drive did those processes access?'
  artifacts:
  - Security-4663
  - Recent-LNK
  - ShellBags
  join-key:
    concept: ProcessId
    role: actingProcess
  primary-source: ms-event-4688
  attribution-sentence: Event 4688 records every successful process creation with NewProcessId (a system-wide unique PID for the lifetime of the process) and SubjectLogonId, threading the process back to
    a specific user session (Microsoft, n.d.).
  conclusion: Security-4663 (SACL-audited object access, if enabled) joins SubjectLogonId AND ProcessId to exact file paths — strongest evidence. Recent-LNK shows user-driven file opens with timestamps;
    ShellBags shows folder navigation. Together they reconstruct the pre-exfil staging browse.
  attribution: Process → File access
  casey: C4
- n: 4
  question: Was an external USB device connected during the session?
  artifacts:
  - USBSTOR
  - MountedDevices
  - EMDMgmt
  - PartitionDiagnostic-1006
  - MountPoints2
  join-key:
    concept: DeviceSerial
    role: usbDevice
  primary-source: hedley-2024-usbstor-install-first-install
  attribution-sentence: USBSTOR contains an entry for every USB device connected to the system keyed on the device's instance ID (which includes the vendor-assigned serial number), threading device identity
    across MountedDevices, EMDMgmt, WindowsPortableDevices, and PartitionDiagnostic-1006 (AboutDFIR, n.d.).
  conclusion: USB mass-storage device attached within session window. USBSTOR names vendor/product/serial; EMDMgmt names the volume label + serial combo; PartitionDiagnostic-1006 gives EVTX-precision connect
    timestamp. MountPoints2 under the user's NTUSER ties the device's VolumeGUID to THIS user specifically — not a shared machine-level mount.
  attribution: Session → Device
  casey: C4
- n: 5
  question: Were files copied FROM the local machine TO the USB?
  artifacts:
  - Recent-LNK
  - AutomaticDestinations
  - JumpList-Embedded-LNK
  - Prefetch
  join-key:
    concept: FilesystemVolumeSerial
    role: runtimeSerial
  primary-source: ms-shllink
  attribution-sentence: A Shell Link (.LNK) file's VolumeID shell item encodes the Volume Serial Number read from the VBR (NTFS offset 0x43, FAT32 offset 0x27), binding the referenced file to the specific
    filesystem instance it was opened from (Microsoft, 2024).
  conclusion: Recent-LNK files created on the local machine that point back to the USB's FilesystemVolumeSerial (LNK DriveSerialNumber field) prove the user opened files FROM the USB path — a copy-TO usually
    leaves a complementary source-side LNK. AutomaticDestinations jump-list entries for Explorer show the USB drive-letter as a frequently-accessed location during the session. Prefetch of robocopy.exe
    / xcopy.exe / powershell.exe during the session window indicates a bulk-copy utility invocation.
  attribution: Device → Data transfer
  casey: C4
- n: 6
  question: Did the user modify the Windows Firewall to enable an egress path?
  artifacts:
  - Firewall-2004
  - Firewall-2005
  join-key:
    concept: UserSID
    role: actingUser
  primary-source: ms-event-4624
  attribution-sentence: Event 4624 records TargetUserSid alongside TargetDomainName and TargetUserName; the SID is the persistent machine-unique account identifier that threads session events to ProfileList,
    SAM, and NTDS-dit records for the same account (Microsoft, n.d.).
  conclusion: 'Firewall-2004 (rule added) or Firewall-2005 (rule modified) with ModifyingUser SID matching Step 1''s TargetUserSid, AND ModifyingApplication path matching one of Step 2''s NewProcessName
    values. Rule details (outbound, specific port, specific remote IP) reveal the intended egress target. Anomalous: firewall rule additions by non-admin tooling during a user session.'
  attribution: Session → Firewall modification
  casey: C4
- n: 7
  question: Was the firewall rule deleted before session close (cleanup intent)?
  artifacts:
  - Firewall-2006
  join-key:
    concept: UserSID
    role: actingUser
  primary-source: ms-event-4624
  attribution-sentence: Event 4624 records TargetUserSid alongside TargetDomainName and TargetUserName; the SID is the persistent machine-unique account identifier that threads session events to ProfileList,
    SAM, and NTDS-dit records for the same account (Microsoft, n.d.).
  conclusion: Firewall-2006 (rule deleted) with matching ModifyingUser SID, firing AFTER the add/modify in Step 6 but BEFORE Security-4634 session close. Deletion demonstrates awareness of the audit trail
    — the attacker tried to remove the evidence. The combination of 2004/2005 + 2006 within one session is a stronger indicator of malicious intent than either alone.
  attribution: Session → Cleanup intent
  casey: C4
- n: 8
  question: Is there asymmetric artifact survival that reveals USBSTOR cleanup?
  artifacts:
  - USBSTOR
  - EMDMgmt
  - WindowsPortableDevices
  - PartitionDiagnostic-1006
  join-key:
    concept: DeviceSerial
    role: usbDevice
  primary-source: hedley-2024-usbstor-install-first-install
  attribution-sentence: USBSTOR contains an entry for every USB device connected to the system keyed on the device's instance ID (which includes the vendor-assigned serial number), threading device identity
    across MountedDevices, EMDMgmt, WindowsPortableDevices, and PartitionDiagnostic-1006 (AboutDFIR, n.d.).
  conclusion: 'Asymmetric-survival test: if USBSTOR subkeys for the device (from Step 4) are ABSENT but EMDMgmt, WindowsPortableDevices, and PartitionDiagnostic-1006 all preserve the same device-identity,
    the user attempted USBSTOR cleanup but missed the parallel sources. The asymmetry IS the affirmative finding of cleanup attempt — even though USBSTOR itself is gone, its absence AGAINST the presence
    of the parallel artifacts is evidence of deliberate deletion. Combined with Step 7''s firewall-rule deletion, produces an affirmative anti-forensic-intent proposition.'
  attribution: Device → Cleanup detection (via asymmetric survival)
  casey: C4
---

# Departing Employee — USB Exfiltration with Cleanup

## Investigator walk-through

Start at the **LogonSessionId** concept node — it's the pivot around which the whole user-activity window rotates.

1. **Find the 4624** that defines LogonSessionId for the window of interest. Interactive logon type 2 is the departing-employee case. Note the TargetLogonId (LUID) and the logon start time.

2. **Filter 4688 and 4663** on `SubjectLogonId == LUID`. Every process created and every SACL-audited object touched during the session is now in scope.

3. **Overlay USB-device events** — filter Partition/Diagnostic-1006 and USBSTOR on the session time window. The DeviceSerial + ContainerID combination names the physical device; FilesystemVolumeSerial names the specific formatting.

4. **Confirm volume access** — MountPoints2 under the user's NTUSER has a `{VolumeGUID}` entry whose VolumeGUID matches MountedDevices binding-data for the same device. MountPoints2's `_LabelFromReg` should match the VolumeLabel from EMDMgmt's composite subkey name.

5. **Enumerate exfil evidence** — Recent-LNK files on the USB's VSN plus ShellBags traversal of the USB mount point plus jump-list entries in `AutomaticDestinations` for Explorer showing the USB path.

6. **Firewall lifecycle** — Firewall-2004 adds the egress rule with `ModifyingUser` == 4624's TargetUserSid and `ModifyingApplication` path matching a 4688 NewProcessName. Firewall-2006 deletes it before session close.

7. **Cleanup detection** — USBSTOR present/absent? If the attacker cleaned USBSTOR, confirm asymmetry: EMDMgmt (SOFTWARE hive) and WindowsPortableDevices and PartitionDiagnostic-1006 (EVTX) should all have survived. The asymmetry IS the cleanup evidence.

## Why this scenario needs multiple join keys simultaneously

Single-key correlation is brittle. Consider counterfactuals:

- **LUID alone:** any process during the session — doesn't isolate the USB-exfil processes.
- **DeviceSerial alone:** establishes device was plugged in — doesn't attribute to a user.
- **VolumeGUID alone:** naming a volume doesn't prove a specific user wrote to it.
- **UserSID alone:** doesn't distinguish sessions (same user may log on repeatedly over years).

The scenario demands the join-key set **{LogonSessionId, DeviceSerial, VolumeGUID, FilesystemVolumeSerial}** simultaneously: session-window limits the claim to one specific logon, DeviceSerial names the physical device, VolumeGUID plus FilesystemVolumeSerial name the volume as-formatted at that time. Remove any one, and the causal chain admits alternative explanations.

## Expected Casey strength
With all primary artifacts intact: **C4 composite** for the USED(user, device) + ACCESSED(files) chain.
With cleanup detected (asymmetric artifact survival): **C4** — unchanged strength for attribution, PLUS an affirmative finding of cleanup attempt as a separate proposition.
