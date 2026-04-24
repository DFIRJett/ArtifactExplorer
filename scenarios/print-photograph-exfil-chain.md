---
name: Print + photograph exfil chain (paper + screen-capture exfil of sensitive documents)
anchors:
  entry: UserSID
  conclusions:
  - DeviceSerial
  - ContainerID
  - LogonSessionId
  - PIDL
  - MFTEntryReference
severity: reference
summary: 'Insider prints sensitive documents AND photographs / screen-records

  screens showing sensitive content, intending to bypass network DLP.

  Analyst ties document-access to print jobs + parallel screen capture,

  optionally correlating with a phone-as-MTP device plugged in at the

  same time.

  '
narrative: 'Grounded in ITM IF006 Unauthorized Printing + PR013 Testing Ability

  to Print + PR028 On-Screen Data Collection + IF003 Exfiltration via

  Media Capture. Paper and photographs sidestep every network DLP

  control. The chain reconstructs the physical-exfil pattern from on-

  host artifacts: document-access MRUs + print-spool files + Snipping

  Tool captures + clipboard + USB MTP/PTP device connection records.

  '
artifacts:
  primary:
  - RecentDocs
  - Recent-LNK
  - OfficeRecent-LNK
  - AutomaticDestinations
  - JumpList-DestList-Entry
  - Print-Spool-Files
  - Security-4688
  - Port-Monitors
  - PrintNightmare-PointAndPrint
  - Amcache-InventoryApplicationFile
  - UserAssist
  - Snipping-Tool-Captures
  - Windows-Clipboard
  - Thumbcache-Entry
  - IconCache
  - USBSTOR
  - USB-Enum
  - WindowsPortableDevices
  - DeviceSetup-20001
  - setupapi-dev-log
  - Security-5140
  - Security-4663
  - ShellBags
  corroborating:
  - Security-4624
  - Sysmon-1
join-keys:
- concept: UserSID
  role: profileOwner
- concept: AppID
  role: jumpListApp
- concept: ExecutablePath
  role: ranProcess
- concept: ExecutableHash
  role: contentHash
- concept: DeviceSerial
  role: usbDevice
- concept: ContainerID
  role: deviceIdentity
- concept: LogonSessionId
  role: sessionContext
- concept: PIDL
  role: browsedItem
- concept: MFTEntryReference
  role: targetFile
steps:
- n: 1
  question: Which documents were opened immediately before print events?
  artifacts:
  - RecentDocs
  - Recent-LNK
  - OfficeRecent-LNK
  - AutomaticDestinations
  - JumpList-DestList-Entry
  join-key:
    concept: AppID
    role: jumpListApp
  primary-source: mitre-t1204
  attribution-sentence: Windows AppIDs uniquely identify installed applications; Jump List entries, BAM records, and UserAssist are all keyed by AppID, enabling per-application execution evidence to be
    aggregated across artifacts (MITRE ATT&CK, n.d.).
  conclusion: 'RecentDocs registry + Recent-LNK + Office-specific AppID jump lists (Excel.15 / WINWORD.15 / POWERPNT.15) give per-application per-file last-opened timeline for the hour before printing.
    AutomaticDestinations / DestList entries record the precise file-path + application that opened it. Cross-reference open-time against Step 2''s submit-time: matching = the opened document was the printed
    document.'
  attribution: User → Document access sequence
  casey: C2
- n: 2
  question: What print jobs were submitted and to which printer / port?
  artifacts:
  - Print-Spool-Files
  - Security-4688
  - Port-Monitors
  - PrintNightmare-PointAndPrint
  join-key:
    concept: ExecutablePath
    role: ranProcess
  primary-source: ms-event-4688
  attribution-sentence: Event 4688 records every successful process creation with NewProcessName (full executable path) and SubjectLogonId, chaining a program launch to both a specific account and a specific
    session (Microsoft, n.d.).
  conclusion: Print-Spool-Files (SPL + SHD pairs) in %SystemRoot%\System32\spool\PRINTERS\ preserve job metadata (user, document name, printer, submit time) and often the rendered content bytes. Security-4688
    for spoolsv.exe child processes (winspool.drv handlers) brackets the job. Port-Monitors registry shows the printer port configured — home-office / public / non-enterprise printer = higher exfil concern.
    PrintNightmare-PointAndPrint registry state documents whether print-driver install was recently tampered (adjacent persistence).
  attribution: User → Print submission
  casey: C3
- n: 3
  question: Did the user test print capability earlier (PR013 signal)?
  artifacts:
  - Print-Spool-Files
  - Amcache-InventoryApplicationFile
  - UserAssist
  join-key:
    concept: UserSID
    role: profileOwner
  primary-source: ms-event-4624
  attribution-sentence: Event 4624 records TargetUserSid alongside TargetDomainName and TargetUserName; the SID is the persistent machine-unique account identifier that threads session events to ProfileList,
    SAM, and NTDS-dit records for the same account (Microsoft, n.d.).
  conclusion: Multiple small / test-document SPL+SHD pairs hours-to-days BEFORE the big print volume = ITM PR013 (Testing Ability to Print) — insider verifying the printer still works before the real exfil.
    UserAssist counts for print-dialog launchers and printer-related apps document repeated pre-exfil testing. Amcache entries for any custom printing utility introduced by the user.
  attribution: User → Test-print behavior (pre-exfil)
  casey: C2
- n: 4
  question: Are there snipping / screenshot artifacts indicating parallel on-screen capture?
  artifacts:
  - Snipping-Tool-Captures
  - Windows-Clipboard
  - Thumbcache-Entry
  - IconCache
  join-key:
    concept: MFTEntryReference
    role: targetFile
  primary-source: ms-ntfs-on-disk-format-secure-system-f
  attribution-sentence: Every NTFS file is uniquely addressed by a file reference combining a 48-bit MFT record number and a 16-bit sequence number, and the USN Journal and $LogFile record every lifecycle
    change keyed on this reference (Microsoft, 2025).
  conclusion: Snipping-Tool-Captures PNGs + MP4s in TempState or saved-Screenshots / Screen Recordings directories with mtimes overlapping the print window = parallel screen-capture exfil. Windows-Clipboard
    pinned images reveal ctrl-printscreen history. Thumbcache entries for the saved captures confirm the user viewed them back (second-level confirmation). Clipboard FileDrop entries may list the exfil
    files staged.
  attribution: User → Parallel on-screen capture
  casey: C3
- n: 5
  question: Was a phone or camera mounted as MTP/PTP device around the same window?
  artifacts:
  - USBSTOR
  - USB-Enum
  - WindowsPortableDevices
  - DeviceSetup-20001
  - setupapi-dev-log
  join-key:
    concept: DeviceSerial
    role: usbDevice
  primary-source: hedley-2024-usbstor-install-first-install
  attribution-sentence: USBSTOR contains an entry for every USB device connected to the system keyed on the device's instance ID (which includes the vendor-assigned serial number), threading device identity
    across MountedDevices, EMDMgmt, WindowsPortableDevices, and PartitionDiagnostic-1006 (AboutDFIR, n.d.).
  conclusion: USBSTOR / USB-Enum entries with Hardware-ID matching phone / camera MTP signatures (Apple iPhone, Android MTP/PTP, digital cameras) and connection time inside the print window = phone was
    physically present to photograph the printed documents. WindowsPortableDevices registry confirms MTP enumeration. DeviceSetup-20001 gives first-connect event-time. setupapi-dev-log corroborates driver-install
    moment.
  attribution: User → Phone/camera device presence
  casey: C3
- n: 6
  question: Did the printed document originate from a network share the user shouldn't have touched?
  artifacts:
  - Security-5140
  - Security-4663
  - ShellBags
  join-key:
    concept: LogonSessionId
    role: sessionContext
  primary-source: ms-event-4624
  attribution-sentence: Event 4624 records a successful account logon and emits TargetLogonId, a hex LUID that uniquely identifies the session until the matching 4634 logoff closes it, threading every in-session
    event through a single session scope (Microsoft, n.d.).
  conclusion: Security-5140 (share access) on the share's server side + Security-4663 file-access on the printed document — joined on LogonSessionId — confirm the user's session reached the source file
    on a remote share before printing. ShellBags UNC-path navigation records corroborate. Off-role share access in this chain = deliberate exfil behavior, not incidental.
  attribution: User → Remote share → Local print → Physical exfil
  casey: C2
provenance:
- libyal-libregf
- libyal-libfwsi
- libyal-liblnk
- ms-shllink
- libyal-libolecf
- ms-cfb
- ms-print-spooler-architecture-spl-and
- 13cubed-2020-print-job-forensics-recovering
- matrix-nd-dt061-detect-text-authored-in
- project-2023-windowsbitsqueuemanagerdatabas
- ms-event-4688
- ms-include-command-line-in-process-cre
- uws-event-4688
- ms-print-spooler-port-monitor-architec
- mitre-t1547-010
- robbins-2022-group-policy-preferences-and-t
- ms-cve-2021-34527-printnightmare-advis
- mitre-t1068
- zerosteiner-2021-printnightmare-exploit-and-reg
- rathbun-2023-program-compatibility-assistan
- mandiant-2015-shim-me-the-way-application-co
- ms-cortana-privacy-speech-data-retenti
- aboutdfir-com-2023-windows-11-snipping-tool-foren
- ms-windows-clipboard-history-feature-r
- forensics-2019-the-windows-swapfile-what-it-c
- libyal-libesedb
- aboutdfir-nd-usb-devices-windows-artifact-r
- hedley-2024-usbstor-install-first-install
- uws-event-20001
- ms-setupapi-logging-file-locations-and
- ms-event-5140
- uws-event-5140
- ms-event-4663
- uws-event-4663
- online-2021-registry-hive-file-format-prim
- ms-event-4624
- uws-event-4624
- ms-sysmon-system-monitor
- hartong-2024-sysmon-modular-a-repository-of
- uws-event-90001
- casey-2002-error-uncertainty-loss-digital-evidence
- casey-2020-standardization-evaluative-opinions
- forensicartifacts-repo
- kape-files-repo
- insiderthreatmatrix-repo
- thedfirreport
- ms-advanced-audit-policy
- regripper-plugins
---

# Print + Photograph Exfil Chain

## Purpose
Reconstruct the paper/photograph exfil pattern — the one that ignores network DLP entirely. Chain threads document-access (Step 1) → print-job submission (Step 2) → test-print prep (Step 3, optional) → parallel on-screen capture (Step 4) → phone-as-MTP device (Step 5) → remote-share source (Step 6) for full attribution across the physical/digital boundary.

## Why this matters
Print + photograph exfil is deliberately physical. Network DLP, CASB, cloud-access-governance, and endpoint DLP file-write monitoring all miss it. The only forensic path is on-host artifacts that document the document-access + print + capture + phone-connection as separate-but-correlated events.
