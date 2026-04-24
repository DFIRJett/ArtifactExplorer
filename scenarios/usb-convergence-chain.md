---
name: USB convergence chain (10-step analyst walkthrough)
anchors:
  entry: DeviceSerial
  conclusions:
    - ContainerID
    - MBRDiskSignature
    - GPTPartitionGUID
    - VolumeGUID
    - FilesystemVolumeSerial
    - UserSID
    - LogonSessionId
    - MFTEntryReference
    - PIDL
severity: reference
summary: |
  Stepwise tier-3 analyst progression for a USB-device-user-activity case.
  Each step asks one investigative question, names the artifacts that
  answer it, identifies the join key that threads those artifacts to the
  prior step's conclusion, and records the Layer-3 forensic conclusion
  with its Casey C-scale strength. Walking the chain end-to-end raises
  the cumulative score from C3 (device connected) to C4–C5 (person
  attributed — with non-digital corroboration required for the final
  person-identity inference).
narrative: |
  Reference chain rather than a single incident. Use it as the checklist
  behind any USB-user-activity case: if a step's artifacts are missing,
  consult the Missed Convergences playbook for alternatives and
  documentation language. Hovering an artifact in any step lights it up
  on the graph so the analyst can see exactly where in the corpus that
  evidence sits.

# These are the UNION across all 10 steps. The per-step artifact lists
# live under `steps:` below — this block exists so the base scenario
# overlay still works without the stepwise UI.
artifacts:
  primary:
    # Step 1 — device connection
    - USBSTOR
    - KernelPnP-400
    - PartitionDiagnostic-1006
    # Step 2 — connection timestamps (USBSTOR already listed; add drivers)
    - DeviceSetup-20001
    - KernelPnP-410
    # Step 3 — volume presentation
    - MountedDevices
    # Step 4 — user-account-to-volume bridge
    - MountPoints2
    # Step 5 — user session within the device window
    - Security-4624
    # Step 6 — file access
    - Recent-LNK
    - OfficeRecent-LNK
    - AutomaticDestinations
    - RecentDocs
    - OpenSavePidlMRU
    # Step 7 — folder browsing
    - ShellBags
    - TypedPaths
    # Step 8 — program execution from device
    - BAM
    - DAM
    - Prefetch
    - ShimCache
    - Amcache-InventoryApplicationFile
    - Security-4688
    # Step 9 — files copied from device to local
    - MFT
    - UsnJrnl
  corroborating:
    # Device-side supporting
    - EMDMgmt
    - USB-Enum
    - WindowsPortableDevices
    - setupapi-dev-log
    - Security-6416
    # File-access supporting
    - LastVisitedPidlMRU
    - UserAssist
    # Session close
    - Security-4634
    # NTFS transaction (step 9 alt)
    - LogFile

join-keys:
  - concept: DeviceSerial
    role: usbDevice
  - concept: ContainerID
    role: deviceIdentity
  - concept: MBRDiskSignature
    role: volumeBinding
  - concept: GPTPartitionGUID
    role: volumeBinding
  - concept: VolumeGUID
    role: mountedVolume
  - concept: FilesystemVolumeSerial
    role: runtimeSerial
  - concept: UserSID
    role: authenticatingUser
  - concept: LogonSessionId
    role: sessionContext
  - concept: ExecutablePath
    role: actingProcess
  - concept: MFTEntryReference
    role: targetFile
  - concept: PIDL
    role: browsedItem

# 
provenance:
  - aboutdfir-nd-usb-devices-windows-artifact-r
  - hedley-2024-usbstor-install-first-install
  - libyal-libregf
  - libyal-libfwevt-libfwevt-windows-xml-event-log
  - vasilaras-2021-leveraging-the-microsoft-windo
  - hale-2018-partition-diagnostic-p1
  - uws-event-20001
  - ms-event-4624
  - uws-event-4624
  - libyal-liblnk
  - ms-shllink
  - libyal-libolecf
  - ms-cfb
  - libyal-libfwsi
  - online-2021-registry-hive-file-format-prim
  - koroshec-2021-user-access-logging-ual-a-uniq
  - carvey-2022-windows-forensic-analysis-tool
  - libyal-libscca
  - mandiant-2015-shim-me-the-way-application-co
  - ms-application-compatibility-toolkit-s
  - rathbun-2023-program-compatibility-assistan
  - ms-event-4688
  - ms-include-command-line-in-process-cre
  - uws-event-4688
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
  - libyal-libusnjrnl-usn-journal-format-max-header
  - ms-change-journal-record-header-fsctl
  - ms-setupapi-logging-file-locations-and
  - ms-event-6416
  - uws-event-6416
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

# ====================================================================
# STEPS — the 10-question analyst progression. Each step names the
# artifacts that answer the question and the single join key that
# threads the step to the prior conclusion. Rendered by the viewer
# as a scrollable list; hovering an artifact chip lights that node
# up in the graph overlay.
# --------------------------------------------------------------------
steps:
  - n: 1
    question: "Was a USB storage device connected to this system?"
    artifacts:
      - USBSTOR
      - KernelPnP-400
      - PartitionDiagnostic-1006
    join-key:
      concept: DeviceSerial
      role: usbDevice
    primary-source: aboutdfir-nd-usb-devices-windows-artifact-r
    attribution-sentence: "Every USB mass storage device connected to a Windows host is enumerated into the USBSTOR registry subkey tree keyed on vendor, product, revision, and serial, and the kernel PnP service emits independent event-log records corroborating enumeration (AboutDFIR, n.d.)."
    conclusion: "A USB mass storage device (specific vendor / product / revision / serial) was connected to this system. Registry PnP enumeration and kernel driver-load events independently confirm presence."
    attribution: "Device → System"
    casey: "C3–C4"

  - n: 2
    question: "When was it first connected? Last connected? Last removed?"
    artifacts:
      - USBSTOR
      - DeviceSetup-20001
      - KernelPnP-400
      - PartitionDiagnostic-1006
    join-key:
      concept: DeviceSerial
      role: usbDevice
    primary-source: hedley-2024-usbstor-install-first-install
    attribution-sentence: "USBSTOR Properties 0064 and 0065 record install and first-install timestamps, but driver uninstall plus reinstall of the same vendor-product-serial combination overwrites these on-disk values; UserPnp event 20001 fires exactly once per first-install and is therefore the canonical first-connection source when available (Hedley, 2024)."
    conclusion: "USBSTOR Properties 0064/0065 (install / first-install) + 0066 (last-arrival) + 0067 (last-removal) establish the device's temporal envelope. UserPnp 20001 gives the definitive first-install moment. Partition/Diagnostic 1006 provides per-event connect/disconnect timestamps at event-log precision. CAVEAT (Hedley/Khyrenz 2023): Properties 0064 + 0065 can be overwritten by driver uninstall+reinstall of the same device — the on-disk values may reflect a later re-install rather than the true first-ever connection. 0066 + 0067 only exist on Win8+ (Arshad et al. 2017). For defensible first-connection, corroborate with UserPnp 20001 (install event fires only once) OR setupapi.dev.log (first-install entry)."
    attribution: "Device → System (temporal)"
    casey: "C4 (with corroboration); C3 (USBSTOR 0064/0065 alone — overwrite-vulnerable)"

  - n: 3
    question: "What volume(s) did the device present?"
    artifacts:
      - MountedDevices
      - PartitionDiagnostic-1006
    join-key:
      concept: MBRDiskSignature
      role: volumeBinding
    primary-source: hale-2018-partition-diagnostic-p1
    attribution-sentence: "PartitionDiagnostic event 1006 captures the full partition-table byte layout at connection time, including the MBR DiskSignature and GPT partition GUIDs, establishing the device-to-volume binding authoritatively at the moment of connection (Hale, 2018)."
    conclusion: "Device presented a specific volume. MBR disks bind via {DiskSignature, partition-offset}; GPT disks bind via GPTPartitionGUID. Partition/Diagnostic 1006's PartitionTableBytes + MBR raw bytes independently corroborate the MountedDevices binding. FilesystemVolumeSerial recovered from the VBR (NTFS offset 0x43, FAT32 0x27, exFAT 0x64) becomes the join key to user-level evidence in later steps."
    attribution: "Device → System (volume-level)"
    casey: "C4"

  - n: 4
    question: "Did a specific user account interact with this device?"
    artifacts:
      - MountPoints2
    join-key:
      concept: VolumeGUID
      role: accessedVolume
    primary-source: ms-shllink
    attribution-sentence: "A Shell Link (.LNK) file's LinkTargetIDList carries a VolumeID shell item encoding the volume's drive-type, serial number, and label, preserving volume-identity-to-file binding across sessions (Microsoft, 2024)."
    conclusion: "User account (SID) has a MountPoints2 entry for the Volume{GUID} from Step 3. Combined with MountedDevices's volume→device mapping, this account's Explorer shell recognized this physical storage device. Account ≠ person (Casey certainty gap — Step 10 is required for that inference). CAVEAT (Fox 2013, Forensic Focus webinar): insertion of a USB device updates the MountPoints2 hive of EVERY concurrently logged-on user, not just the user who physically connected it. Fast User Switching + background sessions can therefore create entries under accounts that never interacted with the device. Before asserting single-user attribution, enumerate all Security-4624 sessions overlapping the device-connection window (Step 5) and confirm only ONE interactive (Type 2) session was active. LastWriteTime on the Volume{GUID} subkey reflects some Explorer shell write — not reliably first-mount — per libyal winreg-kb + Carvey + Hedley."
    attribution: "Device → Account (subject to Fox FUS caveat)"
    casey: "C3 (requires corroboration — BAM + ShellBags + sole-interactive-session to elevate)"

  - n: 5
    question: "Was the user authenticated during the device connection window?"
    artifacts:
      - Security-4624
    join-key:
      concept: LogonSessionId
      role: sessionContext
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records a successful account logon and emits TargetLogonId, a hex LUID that uniquely identifies the session until the matching 4634 logoff closes it, threading every in-session event through a single session scope (Microsoft, n.d.)."
    conclusion: "Account from Step 4 had an interactive logon session (Type 2 console, 10 RDP) active during the device-connection window from Step 2. 4624's TargetLogonId (LUID) becomes the session-scope join key for every 4688 / 4663 / 4657 that follows inside the window."
    attribution: "Device → Account → Session"
    casey: "C4"

  - n: 6
    question: "Were specific files on the device accessed?"
    artifacts:
      - Recent-LNK
      - OfficeRecent-LNK
      - AutomaticDestinations
      - RecentDocs
      - OpenSavePidlMRU
    join-key:
      concept: FilesystemVolumeSerial
      role: accessedVolume
    primary-source: ms-shllink
    attribution-sentence: "A Shell Link (.LNK) file's VolumeID shell item encodes the Volume Serial Number read from the VBR (NTFS offset 0x43, FAT32 offset 0x27), binding the referenced file to the specific filesystem instance it was opened from (Microsoft, 2024)."
    conclusion: "Files at specific paths on the device's volume (matched by DriveSerialNumber in LNK / Jump List entries = the VBR Volume Serial from Step 3) were opened by the account from Step 4 during the session window from Step 5. Jump List AppID names the application that opened each file. OpenSavePidlMRU captures file-dialog-based access specifically."
    attribution: "Device → Account → File Access"
    casey: "C4"

  - n: 7
    question: "Were specific folders on the device browsed?"
    artifacts:
      - ShellBags
      - TypedPaths
    join-key:
      concept: PIDL
      role: browsedItem
    primary-source: libyal-libfwsi
    attribution-sentence: "Windows Shell Items (PIDL segments) encode every step of a navigation path with ItemType, typed data, and a FILETIME; ShellBags persist these sequences keyed by folder so shell navigation history can be reconstructed (Metz, 2021)."
    conclusion: "Folder tree on the removable device was navigated via Explorer (ShellBags) or by typing the path in Explorer's address bar (TypedPaths = deliberate navigation). ShellBags' embedded PIDL data corroborates OpenSavePidlMRU from Step 6 on the same folder. Leaf-key LastWriteTime times the first interaction with each folder."
    attribution: "Device → Account → Folder Navigation"
    casey: "C4"

  - n: 8
    question: "Was any executable from the device run?"
    artifacts:
      - BAM
      - DAM
      - Prefetch
      - ShimCache
      - Amcache-InventoryApplicationFile
      - Security-4688
    join-key:
      concept: ExecutablePath
      role: actingProcess
    primary-source: ms-event-4688
    attribution-sentence: "Event 4688 records every successful process creation with NewProcessName (full executable path) and SubjectLogonId, chaining a program launch to both a specific account and a specific session (Microsoft, n.d.)."
    conclusion: "Executable on the device's drive letter was run by the account from Step 4. BAM ties (SID, path, last-run FILETIME). Prefetch proves execution with loaded-DLL list. Amcache adds the SHA-1 hash. 4688's NewProcessName carries the same path and chains via SubjectLogonId back to Step 5's session. Any one of these alone is weaker; the pile produces C4–C5. TIME-SENSITIVITY CAVEAT: BAM purges entries older than 7 days on boot — if acquisition is >7 days after the activity, BAM has likely lost the record. BAM paths use NT-style (\\Device\\HarddiskVolumeN\\exe.exe); must be cross-mapped to DOS drive letter via MountedDevices to correlate with the removable device. 4688 CommandLine requires audit-policy bit enabled — absent policy = no CommandLine even when 4688 fires."
    attribution: "Device → Account → Program Execution"
    casey: "C4–C5 (with Prefetch + Amcache corroboration); C3 (BAM alone + >7-day-old incident = likely absent)"

  - n: 9
    question: "Were files copied FROM the device TO the local system?"
    artifacts:
      - MFT
      - UsnJrnl
      - Recent-LNK
    join-key:
      concept: MFTEntryReference
      role: targetFile
    primary-source: ms-ntfs-on-disk-format-secure-system-f
    attribution-sentence: "Every NTFS file is uniquely addressed by a file reference combining a 48-bit MFT record number and a 16-bit sequence number, and the USN Journal and $LogFile record every lifecycle change keyed on this reference (Microsoft, 2025)."
    conclusion: "Files appeared on the local NTFS volume with $MFT $SI creation times inside the session window. $UsnJrnl recorded FILE_CREATE → DATA_EXTEND → CLOSE sequences. LNK files on the local volume point back to the removable-media sources with their DriveSerialNumber. If $UsnJrnl has wrapped, $LogFile may carry older NTFS transaction records."
    attribution: "Device → Account → Data Transfer"
    casey: "C4"

  - n: 10
    question: "Can activity be attributed to a specific PERSON (not just account)?"
    artifacts:
      - Security-4624
    join-key:
      concept: UserSID
      role: authenticatingUser
    primary-source: casey-2002-error-uncertainty-loss-digital-evidence
    attribution-sentence: "Digital evidence can at most attribute activity to an account; converting account-level attribution to person-level attribution requires evidence from outside the digital domain (physical access logs, video, biometrics, admissions), a boundary that cannot be closed by additional digital corroboration (Casey, 2002)."
    conclusion: "4624 LogonType restricts the attribution to the authentication modality — Type 2 / 10 (interactive) implies the authenticating party was at a keyboard; Type 3 does not. Absence of concurrent RDP sessions and credential-sharing indicators narrows the inference. FINAL STEP REQUIRES NON-DIGITAL CORROBORATION — physical badge logs, camera footage, biometric auth, MFA push response — to promote account-level evidence to person-level evidence. This boundary is the Casey certainty gap in its purest form."
    attribution: "Device → Person (requires non-digital corroboration)"
    casey: "C4–C5 (with corroboration); C3 (digital-only)"
---

# USB Convergence Chain — tier-3 analyst walkthrough

## Purpose

A stepwise reference for reconstructing USB-device-user-activity cases end-to-end. Each step escalates the Casey C-scale by one dimension:

1. Device connected (C3–C4)
2. + Timestamped (C4)
3. + Volume identified (C4)
4. + Account linked (C3)
5. + Session confirmed (C4)
6. + File access (C4)
7. + Folder navigation (C4)
8. + Program execution (C4–C5)
9. + Data transfer (C4)
10. + Person attribution (C4–C5 with corroboration; C3 digital-only)

## How to use

Load the scenario. The scenarios panel shows the 10 steps. Hover over any artifact chip to light it up on the graph overlay — the chip tells you which evidence class answers that step, the graph shows you where that evidence sits in the broader corpus and what other artifacts it corroborates.

## Expected Casey strength

With all primary artifacts intact AND step 10's non-digital corroboration: **C4–C5 composite** for the USED(person, device) + ACCESSED(files) + EXECUTED(programs) + COPIED(data) chain.

With digital artifacts only (no Step-10 corroboration): **C3**. The person-vs-account gap is legally significant and cannot be closed by digital evidence alone.

## When evidence is missing

If a step's primary artifacts are absent (audit policy off, ReadyBoost deprecated, BAM purged, $UsnJrnl wrapped, etc.), consult the Missed Convergences playbook for alternative sources and documentation language. Absence is a finding; unexplained absence is a gap.
