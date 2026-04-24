---
name: Token staging + VPN pivot chain (credential exfil → remote re-use from personal device)
anchors:
  entry: UserSID
  conclusions:
    - LogonSessionId
    - MFTEntryReference
    - VolumeGUID
    - FilesystemVolumeSerial
    - MachineNetBIOS
severity: reference
summary: |
  Insider stages an authorization token (browser cookie / Kerberos TGT
  / DPAPI blob / Credential-Manager credential) to a removable or
  cloud-sync location so it can be replayed from a personal device
  over corporate VPN. Analyst traces extraction → staging → VPN
  authentication → internal resource access from the unexpected
  source.
narrative: |
  Grounded in ITM PR030 Authorization Token Staging + PR031 VPN Usage
  + IF025 Internal Credential Sharing. The pattern combines credential
  harvesting with VPN-remoting-in from a personal device — giving the
  attacker persistent access after badge-revoke. Detection requires
  correlating file-level extraction (handle-level read of DPAPI /
  Credential directories) with post-exfil VPN-auth events sourced from
  an unfamiliar IP.

artifacts:
  primary:
    - Sysmon-10
    - Sysmon-11
    - Security-4663
    - DPAPI-MasterKeys
    - Chrome-LoginData
    - Chrome-Cookies
    - Edge-Cookies
    - Firefox-Cookies
    - Kerberos-Tickets-Cache
    - Credential-Manager-Vault
    - LSA-Secrets
    - Security-4672
    - MFT
    - UsnJrnl
    - USBSTOR
    - OneDrive-SyncEngine
    - Zone-Identifier-ADS
    - Security-4624
    - NetworkList-profiles
    - NLA-Cache-Intranet
    - NetworkProfile-10000
    - Security-5140
    - Security-5156
    - UAL-Database
    - firewall-log
    - Security-4776
    - NTDS-dit
  corroborating:
    - Windows-Hello-NGC

join-keys:
  - concept: ProcessId
    role: actingProcess
  - concept: HandleId
    role: openedHandle
  - concept: UserSID
    role: profileOwner
  - concept: LogonSessionId
    role: sessionContext
  - concept: MFTEntryReference
    role: targetFile
  - concept: VolumeGUID
    role: mountedVolume
  - concept: FilesystemVolumeSerial
    role: runtimeSerial
  - concept: IPAddress
    role: authSourceIp
  - concept: MachineNetBIOS
    role: trackerMachineId

steps:
  - n: 1
    question: "What process touched DPAPI master keys or the browser cookie store?"
    artifacts:
      - Sysmon-10
      - Sysmon-11
      - DPAPI-MasterKeys
      - Chrome-LoginData
      - Chrome-Cookies
      - Edge-Cookies
      - Firefox-Cookies
    join-key:
      concept: HandleId
      role: openedHandle
    primary-source: ms-advanced-audit-policy
    attribution-sentence: "Windows Advanced Audit Policy object-access events record HandleId, a per-process handle identifier that correlates matching 4656 (open), 4663 (access), and 4658 (close) events to bracket the object's handle-lifetime within a process (Microsoft, n.d.)."
    conclusion: "Sysmon-10 (ProcessAccess) for handles into lsass.exe = DPAPI + credential-material harvesting. Sysmon-11 (FileCreate) / FileAccess for reads against %APPDATA%\\Microsoft\\Protect, Chrome / Edge / Firefox profile directories. HandleId threads the reading process (PowerShell, rundll32, unsigned binary) to per-file opens on credential stores."
    attribution: "Process → Credential read"
    casey: "C3"

  - n: 2
    question: "Were Kerberos tickets or credential vault blobs accessed?"
    artifacts:
      - Kerberos-Tickets-Cache
      - Credential-Manager-Vault
      - LSA-Secrets
      - Security-4672
    join-key:
      concept: LogonSessionId
      role: sessionContext
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records a successful account logon and emits TargetLogonId, a hex LUID that uniquely identifies the session until the matching 4634 logoff closes it, threading every in-session event through a single session scope (Microsoft, n.d.)."
    conclusion: "Kerberos-Tickets-Cache memory extraction typically requires lsass-dump (Sysmon-10 from Step 1). Credential-Manager-Vault file-level reads (Sysmon-11 events targeting %APPDATA%\\Microsoft\\Credentials\\ and \\Vault\\) provide the DPAPI-encrypted blobs. LSA-Secrets in SECURITY hive copied-out indicates SYSTEM-level dump. Security-4672 (special privileges assigned) shows elevation in the same session — prerequisite for LSA access."
    attribution: "Process → Credential-material dump"
    casey: "C3"

  - n: 3
    question: "Was the staged token file written to a removable or sync location?"
    artifacts:
      - MFT
      - UsnJrnl
      - USBSTOR
      - OneDrive-SyncEngine
      - Zone-Identifier-ADS
    join-key:
      concept: MFTEntryReference
      role: targetFile
    primary-source: ms-ntfs-on-disk-format-secure-system-f
    attribution-sentence: "Every NTFS file is uniquely addressed by a file reference combining a 48-bit MFT record number and a 16-bit sequence number, and the USN Journal and $LogFile record every lifecycle change keyed on this reference (Microsoft, 2025)."
    conclusion: "UsnJrnl USN_REASON_FILE_CREATE events for a file on a removable volume (USBSTOR Hardware-ID + VolumeGUID matching the FilesystemVolumeSerial) OR inside a OneDrive / Dropbox sync directory = staging for external retrieval. MFT entry preserves the file path + size. Zone-Identifier ADS marking internet-sourced tooling distinguishes authored-locally vs downloaded. Same MFTEntryReference across local source + removable destination = copy-out."
    attribution: "Process → Staging location"
    casey: "C3"

  - n: 4
    question: "Did a VPN client authenticate from an unusual network soon after?"
    artifacts:
      - Security-4624
      - NetworkList-profiles
      - NLA-Cache-Intranet
      - NetworkProfile-10000
    join-key:
      concept: IPAddress
      role: authSourceIp
    primary-source: ms-event-5156
    attribution-sentence: "Windows Filtering Platform event 5156 records a permitted connection with SourceAddress, SourcePort, DestAddress, DestPort, and ProcessId, providing per-connection attribution keyed on IPAddress pairs (Microsoft, n.d.)."
    conclusion: "Security-4624 type 10 / type 3 from an IP NOT matching the user's usual residential / corporate network = out-of-band logon. NetworkList-profiles + NLA-Cache-Intranet show the intranet the session was routed through post-VPN. NetworkProfile-10000 records network-connect events. If the source IP is a consumer ISP range in a city the user is not known to be in = high-confidence remote-personal-device pivot."
    attribution: "Post-exfil → VPN-authenticated session"
    casey: "C3"

  - n: 5
    question: "What internal resources did the VPN session reach?"
    artifacts:
      - Security-5140
      - Security-5156
      - UAL-Database
      - firewall-log
    join-key:
      concept: LogonSessionId
      role: sessionContext
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records a successful account logon and emits TargetLogonId, a hex LUID that uniquely identifies the session until the matching 4634 logoff closes it, threading every in-session event through a single session scope (Microsoft, n.d.)."
    conclusion: "Security-5140 (network share access) + Security-5156 (Filtering-Platform connection permitted) sourced from the VPN session's TargetLogonId + attacker's VPN IP = post-pivot resource access. UAL-Database (on Server 2012+) aggregates per-role per-client-IP access for forensic retention beyond EVTX. Firewall-log corroborates allowed flows. Cross-reference attacker IP from Step 4 against these — match = confirmed pivot."
    attribution: "VPN session → Internal resource access"
    casey: "C3"

  - n: 6
    question: "Was a secondary account reused against the same resource (credential sharing)?"
    artifacts:
      - Security-4624
      - Security-4776
      - NTDS-dit
    join-key:
      concept: UserSID
      role: identitySubject
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records TargetUserSid alongside TargetDomainName and TargetUserName; the SID is the persistent machine-unique account identifier that threads session events to ProfileList, SAM, and NTDS-dit records for the same account (Microsoft, n.d.)."
    conclusion: "Security-4624 / 4776 events for SECOND account (not Step 4's primary) from the same attacker IP = ITM IF025 Internal Credential Sharing. NTDS-dit snapshot of account-membership contextualizes which privileges the second account brings. Two user SIDs + one IP + overlapping session windows = account-sharing or credential-theft post-pivot."
    attribution: "Multi-account pivot from single source"
    casey: "C2"
provenance:
  - ms-sysmon-system-monitor
  - hartong-2024-sysmon-modular-10-process-acce
  - specterops-2021-understanding-and-defending-ag
  - hartong-2024-sysmon-modular-11-file-create
  - sans-2022-the-importance-of-sysmon-event
  - ms-data-protection-api-architecture-an
  - mitre-t1555-004
  - gentilkiwi-2020-mimikatz-vault-cred-modules-ex
  - specterops-2019-a-deep-dive-into-dpapi-compreh
  - chromium-history-schema
  - mozilla-places-schema
  - ietf-2005-rfc-4120-the-kerberos-network
  - mitre-t1558
  - foundation-2021-volatility-hibernate-address-s
  - ms-credential-manager-credential-provi
  - specterops-2019-sharpdpapi-c-implementation-of
  - ms-configuring-additional-lsa-protecti
  - gentilkiwi-2020-mimikatz-lsadump-cache-extract
  - mitre-t1003-004
  - libyal-libregf
  - ms-event-4672
  - uws-event-4672
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
  - libyal-libusnjrnl-usn-journal-format-max-header
  - ms-change-journal-record-header-fsctl
  - aboutdfir-nd-usb-devices-windows-artifact-r
  - hedley-2024-usbstor-install-first-install
  - khatri-2022-onedriveexplorer-parser-for-on
  - ms-event-4624
  - uws-event-4624
  - ms-network-list-service-and-the-signat
  - ms-network-location-awareness-nla-serv
  - libyal-libevtx
  - ms-event-5140
  - uws-event-5140
  - ms-event-5156
  - mitre-t1071
  - ms-user-access-logging-ual
  - koroshec-2021-user-access-logging-ual-a-uniq
  - zimmerman-2023-kape-ual-compound-target-sqlec
  - ms-windows-defender-firewall-registry
  - ms-event-4776
  - mitre-t1110-003
  - mitre-t1003-006
  - fortra-2022-secretsdump-py-cache-entry-ext
  - libyal-libesedb
  - ms-event-4663
  - uws-event-4663
  - ms-windows-hello-for-business-architec
  - mollema-2022-roadtools-hello2hashcat-offlin
  - robbins-2022-group-policy-preferences-and-t
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - thedfirreport
  - ms-advanced-audit-policy
  - regripper-plugins
---

# Token Staging + VPN Pivot Chain

## Purpose
Reconstruct a post-departure or post-compromise credential-replay pattern where the insider extracts tokens, stages them to a removable / cloud location, retrieves them from a personal device, and replays them into the corporate environment via VPN. Distinct from cleartext-password exfil because the artifacts are DPAPI / Kerberos / Credential-Vault (encrypted material) that requires the source host's key material to decrypt — so the insider's personal device must also have that key material OR use the token blobs against infrastructure that accepts them directly (Kerberos tickets, OAuth cookies).

## Why this chain is tricky
The primary evidence lives in TWO disconnected time windows (pre-exfil extraction + post-exfil VPN session). Bridging them requires correlating file-staging MFT records with subsequent VPN-session IP / timing — neither alone is definitive. Add NTDS-dit lookup of group-membership context to interpret WHY this user's credential material was valuable.
