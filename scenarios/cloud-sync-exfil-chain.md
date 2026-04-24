---
name: Cloud sync exfil chain (leaver → personal OneDrive / Dropbox background upload)
anchors:
  entry: UserSID
  conclusions:
    - LogonSessionId
    - MFTEntryReference
severity: reference
summary: |
  Multi-step walkthrough for a departing-employee cloud-sync exfil
  pattern. Insider stages files into a sync-watched folder, relies on
  a personal-tenant OneDrive / Dropbox / similar client to upload in
  background, and leaves no interactive "upload" moment. Analyst
  threads file staging → sync-client execution → outbound bytes via
  UserSID / ExecutableHash / HandleId / ProcessId.
narrative: |
  Grounded in ITM PR016 Data Staging + PR032 Mover/Leaver + IF001
  Exfiltration via Web Service. A classic weekend-before-resignation
  scenario: sensitive directory copies light up UsnJrnl mass-writes,
  then a non-corporate sync binary (personal OneDrive, Dropbox, MEGA
  client) executes under the user's session and its process handles
  read the staged files as the cloud upload progresses. SRUM Network
  Usage + Sysmon-3 outbound connections to sync-provider endpoints
  complete the chain. PR019 Private/Incognito Browsing sometimes
  coexists as a decoy ("I used a browser, not a client") that the
  artifact chain contradicts.

artifacts:
  primary:
    - MFT
    - UsnJrnl
    - ShellBags
    - Recent-LNK
    - Amcache-InventoryApplicationFile
    - Amcache-InventoryApplication
    - Uninstall-Keys
    - Prefetch
    - Run-Keys
    - Security-4624
    - Security-4688
    - Sysmon-1
    - Scheduled-Tasks
    - Security-4663
    - Sysmon-11
    - OneDrive-SyncEngine
    - OneDrive-SafeDelete
    - Sysmon-3
    - SRUM-NetworkUsage
    - SRUM-Process
    - DNSCache
    - proxy-log
    - Chrome-History
    - Edge-History
    - Zone-Identifier-ADS
  corroborating:
    - I30-Index
    - ActivitiesCache
    - AutomaticDestinations
    - Firefox-places

join-keys:
  - concept: UserSID
    role: profileOwner
  - concept: ExecutableHash
    role: contentHash
  - concept: LogonSessionId
    role: sessionContext
  - concept: ProcessId
    role: actingProcess
  - concept: HandleId
    role: openedHandle
  - concept: MFTEntryReference
    role: targetFile
  - concept: URL
    role: visitedUrl
  - concept: IPAddress
    role: destinationIp

steps:
  - n: 1
    question: "Which user account copied bulk files into a sync-watched folder outside normal hours?"
    artifacts:
      - MFT
      - UsnJrnl
      - ShellBags
      - Recent-LNK
    join-key:
      concept: UserSID
      role: profileOwner
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records TargetUserSid alongside TargetDomainName and TargetUserName; the SID is the persistent machine-unique account identifier that threads session events to ProfileList, SAM, and NTDS-dit records for the same account (Microsoft, n.d.)."
    conclusion: "UsnJrnl mass USN_REASON_FILE_CREATE / USN_REASON_CLOSE records clustered into a sync-client folder path outside documented business hours. MFT $STANDARD_INFORMATION timestamps corroborate. ShellBags confirm the user browsed to the source directory before staging. Recent-LNK for each source file preserves the original path. Attribution currently at ACCOUNT level only."
    attribution: "Account → Staging folder"
    casey: "C2"

  - n: 2
    question: "Was a non-corporate sync client installed or executed to handle the staging folder?"
    artifacts:
      - Amcache-InventoryApplicationFile
      - Amcache-InventoryApplication
      - Uninstall-Keys
      - Prefetch
      - Run-Keys
    join-key:
      concept: ExecutableHash
      role: contentHash
    primary-source: mitre-t1574
    attribution-sentence: "Amcache-InventoryApplicationFile records the SHA-1 hash of every executable that has run on the host under the InventoryApplicationFile subkey; BAM and 4688 events citing the same executable path cross-verify the hash-to-path binding (MITRE ATT&CK, n.d.)."
    conclusion: "Amcache InventoryApplicationFile SHA-1 hash of the sync binary cross-references against known client hashes (personal-OneDrive, Dropbox, MEGA, pCloud, Box). Uninstall-Keys reveals install source path (often a user-Downloads location — personal install, not enterprise-deployed). Prefetch + Run-Keys confirm execution frequency and auto-start. InstallSource in Uninstall-Keys gives the drop-file path."
    attribution: "Sync client identified + user-scope install"
    casey: "C2"

  - n: 3
    question: "Under which logon session did the sync process run, and did it spawn from an interactive desktop or a scheduled trigger?"
    artifacts:
      - Security-4624
      - Security-4688
      - Sysmon-1
      - Scheduled-Tasks
    join-key:
      concept: LogonSessionId
      role: sessionContext
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records a successful account logon and emits TargetLogonId, a hex LUID that uniquely identifies the session until the matching 4634 logoff closes it, threading every in-session event through a single session scope (Microsoft, n.d.)."
    conclusion: "Security-4624 TargetLogonId identifies the interactive session; 4688 SubjectLogonId on the sync-client process creation ties the process to that session. Sysmon-1 ParentProcessId distinguishes interactive-launched (parent = Explorer) from scheduled-launch (parent = svchost / taskhostw). Scheduled-Tasks registry reveals any task triggering the sync client at logon/idle."
    attribution: "Session → Process"
    casey: "C3"

  - n: 4
    question: "Which files did the sync client actually read/open inside the staging folder?"
    artifacts:
      - Security-4663
      - Sysmon-11
      - OneDrive-SyncEngine
      - OneDrive-SafeDelete
    join-key:
      concept: HandleId
      role: openedHandle
    primary-source: ms-advanced-audit-policy
    attribution-sentence: "Windows Advanced Audit Policy object-access events record HandleId, a per-process handle identifier that correlates matching 4656 (open), 4663 (access), and 4658 (close) events to bracket the object's handle-lifetime within a process (Microsoft, n.d.)."
    conclusion: "Security-4663 file-access events (when SACL on the staging folder is enabled) with HandleId threaded from the sync-client process reveal per-file opens. Sysmon-11 (FileCreate) + ObjectAccess records give a fuller opening picture. OneDrive-SyncEngine's proprietary SQLite databases hold the sync-client-side upload record for OneDrive; SafeDelete captures files deleted from the staging folder post-upload."
    attribution: "Process → File reads"
    casey: "C3"

  - n: 5
    question: "What outbound destinations and byte volumes correlate with the sync-client process window?"
    artifacts:
      - Sysmon-3
      - SRUM-NetworkUsage
      - SRUM-Process
      - DNSCache
      - proxy-log
    join-key:
      concept: ProcessId
      role: actingProcess
    primary-source: ms-event-4688
    attribution-sentence: "Event 4688 records every successful process creation with NewProcessId (a system-wide unique PID for the lifetime of the process) and SubjectLogonId, threading the process back to a specific user session (Microsoft, n.d.)."
    conclusion: "Sysmon-3 outbound connections by ProcessId of the sync client + DNSCache resolutions for sync-provider endpoints (onedrive.live.com, dropbox.com, mega.nz) confirm network destinations. SRUM-NetworkUsage quantifies bytes-out per-process per-time-window — large outbound bytes from the sync client in the upload window = exfil volume. Proxy-log corroborates from the gateway side."
    attribution: "Process → Outbound bytes"
    casey: "C4"

  - n: 6
    question: "Did the user preview or touch the same files from a browser to confirm upload success?"
    artifacts:
      - Chrome-History
      - Edge-History
      - Zone-Identifier-ADS
      - AutomaticDestinations
    join-key:
      concept: URL
      role: visitedUrl
    primary-source: ms-background-intelligent-transfer-ser
    attribution-sentence: "The Background Intelligent Transfer Service records each queued URL in qmgr.db, preserving the attacker-chosen endpoint as evidence even after the downloaded file is cleaned from the filesystem (Microsoft, 2022)."
    conclusion: "Browser history entries for the sync provider's web UI (onedrive.live.com/?id=..., dropbox.com/home) within hours of the upload window corroborate user-verification of the exfil. Zone-Identifier ADS on files re-downloaded from the cloud (if user tested) confirms download direction. Jump Lists (AutomaticDestinations) preserve the sync-client's recent-file interactions."
    attribution: "User-verified upload"
    casey: "C3"
provenance:
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
  - libyal-libusnjrnl-usn-journal-format-max-header
  - ms-change-journal-record-header-fsctl
  - online-2021-registry-hive-file-format-prim
  - libyal-libfwsi
  - libyal-libregf
  - libyal-liblnk
  - ms-shllink
  - rathbun-2023-program-compatibility-assistan
  - mandiant-2015-shim-me-the-way-application-co
  - ms-uninstall-registry-key-applications
  - nirsoft-2023-uninstallview-enumerate-instal
  - project-2023-windowsbitsqueuemanagerdatabas
  - carvey-2022-windows-forensic-analysis-tool
  - libyal-libscca
  - mitre-t1547
  - mitre-t1547-001
  - ms-event-4624
  - uws-event-4624
  - ms-event-4688
  - ms-include-command-line-in-process-cre
  - uws-event-4688
  - ms-sysmon-system-monitor
  - hartong-2024-sysmon-modular-a-repository-of
  - uws-event-90001
  - ms-task-scheduler-1-0-legacy-format-re
  - ms-task-scheduler-2-0-xml-schema-refer
  - mitre-t1053-005
  - ms-event-4663
  - uws-event-4663
  - hartong-2024-sysmon-modular-11-file-create
  - sans-2022-the-importance-of-sysmon-event
  - khatri-2022-onedriveexplorer-parser-for-on
  - labs-2023-onedrive-safedelete-db-a-sleep
  - hartong-2024-sysmon-modular-3-network-conne
  - trustedsec-2022-sysinternals-sysmon-a-swiss-ar
  - koroshec-2021-user-access-logging-ual-a-uniq
  - libyal-libesedb
  - khatri-srum-dump
  - ms-name-resolution-policy-table-nrpt-r
  - chromium-history-schema
  - libyal-libolecf
  - ms-cfb
  - mozilla-places-schema
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - thedfirreport
  - ms-advanced-audit-policy
  - regripper-plugins
---

# Cloud Sync Exfil Chain

## Purpose
Reconstruct a weekend-before-departure cloud-sync-based exfil end-to-end. The distinguishing feature of this pattern versus file-copy-to-USB: there is no interactive "upload" event — background sync handles the transfer, making the exfil invisible to shoulder-surfing DLP. The chain depends on threading `UserSID → ExecutableHash → LogonSessionId → ProcessId → HandleId → MFTEntryReference` to move from "user touched files" to "sync binary moved bytes out."

## Required telemetry
- Audit Object Access + SACL on the staging directory for Security-4663
- Sysmon with default config for 1 / 3 / 11
- SRUM auto-collected on all modern Windows

## Casey ceiling
C4 when network bytes-out at the gateway confirm the upload volume. C3 without gateway corroboration (process-initiated outbound is strong but not gateway-verified).
