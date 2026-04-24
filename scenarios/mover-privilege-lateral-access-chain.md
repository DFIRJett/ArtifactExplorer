---
name: Mover privilege accumulation + lateral-access chain
anchors:
  entry: UserSID
  conclusions:
    - LogonSessionId
    - MachineNetBIOS
    - PIDL
    - MFTEntryReference
severity: reference
summary: |
  A Mover (ITM PR032) transferred teams / roles and began touching
  shares outside their new scope. Analyst traces group-membership
  change → privileged logon → cross-share access → off-role file
  reads → local staging → browsing cover-up.
narrative: |
  Grounded in ITM PR032 Mover + PR024 Increase Privileges + IF014
  Unauthorized Changes + IF022 Data Loss. The Mover pattern is
  insider-specific: an employee who changed roles inside the
  organization and retains accumulated permissions from BOTH roles.
  The artifact chain documents the privilege-accumulation event
  and the subsequent off-role data-access behavior that reveals
  deliberate abuse vs. benign transition lag.

artifacts:
  primary:
    - Security-4728
    - Security-4732
    - Security-4738
    - NTDS-dit
    - Security-4624
    - Security-4648
    - NetworkProfile-10000
    - Security-5140
    - Security-4663
    - Security-4656
    - ShellBags
    - TypedPaths
    - WordWheelQuery
    - RecentDocs
    - MFT
    - UsnJrnl
    - Recent-LNK
    - AutomaticDestinations
    - Chrome-History
    - Edge-History
    - Regedit-LastKey
  corroborating:
    - Security-4672
    - Sysmon-1

join-keys:
  - concept: UserSID
    role: identitySubject
  - concept: DomainName
    role: targetDomain
  - concept: LogonSessionId
    role: sessionContext
  - concept: MachineNetBIOS
    role: trackerMachineId
  - concept: HandleId
    role: openedHandle
  - concept: PIDL
    role: browsedItem
  - concept: MFTEntryReference
    role: targetFile

steps:
  - n: 1
    question: "Was the user added to a privileged group post-transfer?"
    artifacts:
      - Security-4728
      - Security-4732
      - Security-4738
      - NTDS-dit
    join-key:
      concept: UserSID
      role: identitySubject
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records TargetUserSid alongside TargetDomainName and TargetUserName; the SID is the persistent machine-unique account identifier that threads session events to ProfileList, SAM, and NTDS-dit records for the same account (Microsoft, n.d.)."
    conclusion: "Security-4728 (global group add) / 4732 (local group add) / 4738 (account change) on the DC document the group-membership change. TargetSid field identifies the mover. NTDS-dit snapshot gives authoritative current membership for cross-check. Dual-role membership (old-team-group + new-team-group) = accumulated access."
    attribution: "Account → Elevated scope"
    casey: "C2"

  - n: 2
    question: "From which workstation did the user log on interactively after the change?"
    artifacts:
      - Security-4624
      - Security-4648
      - NetworkProfile-10000
    join-key:
      concept: LogonSessionId
      role: sessionContext
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records a successful account logon and emits TargetLogonId, a hex LUID that uniquely identifies the session until the matching 4634 logoff closes it, threading every in-session event through a single session scope (Microsoft, n.d.)."
    conclusion: "Security-4624 type 2 (interactive) or 10 (RDP) events with TargetSid = mover's SID. IpAddress + WorkstationName fields identify the source. Network profile (managed/intranet) confirms the session originated inside corporate network. TargetLogonId (LUID) becomes the session-scope join for every subsequent share-access event."
    attribution: "Session identified"
    casey: "C3"

  - n: 3
    question: "What file shares / objects did that session touch?"
    artifacts:
      - Security-5140
      - Security-4663
      - Security-4656
    join-key:
      concept: LogonSessionId
      role: sessionContext
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records a successful account logon and emits TargetLogonId, a hex LUID that uniquely identifies the session until the matching 4634 logoff closes it, threading every in-session event through a single session scope (Microsoft, n.d.)."
    conclusion: "Security-5140 (network share access) on file servers with LogonID matching Step 2's TargetLogonId. Security-4656 / 4663 (handle open + file access) on shares with per-file HandleId. Aggregate the distinct shares accessed — crosscheck against documented new-role scope."
    attribution: "Session → Share access"
    casey: "C3"

  - n: 4
    question: "Were any of those objects in directories outside the new role's scope?"
    artifacts:
      - ShellBags
      - TypedPaths
      - WordWheelQuery
      - RecentDocs
    join-key:
      concept: PIDL
      role: browsedItem
    primary-source: libyal-libfwsi
    attribution-sentence: "Windows Shell Items (PIDL segments) encode every step of a navigation path with ItemType, typed data, and a FILETIME; ShellBags persist these sequences keyed by folder so shell navigation history can be reconstructed (Metz, 2021)."
    conclusion: "ShellBags record folder-navigation history including UNC paths to specific shares — paths deliberately navigated that are NOT in the new-role documented access list = candidate off-role access. TypedPaths captures typed-UNC entries (deliberate navigation, not passive). WordWheelQuery may show search queries within off-role directories. RecentDocs confirms specific files opened from those directories."
    attribution: "Off-role navigation proven"
    casey: "C3"

  - n: 5
    question: "Did the user copy any touched files locally for staging?"
    artifacts:
      - MFT
      - UsnJrnl
      - Recent-LNK
      - AutomaticDestinations
    join-key:
      concept: MFTEntryReference
      role: targetFile
    primary-source: ms-ntfs-on-disk-format-secure-system-f
    attribution-sentence: "Every NTFS file is uniquely addressed by a file reference combining a 48-bit MFT record number and a 16-bit sequence number, and the USN Journal and $LogFile record every lifecycle change keyed on this reference (Microsoft, 2025)."
    conclusion: "Local MFT creation records for files whose source-attribute (path or inferred UNC lineage) matches Step 3's share access = network→local copy. UsnJrnl USN_REASON_FILE_CREATE + DATA_EXTEND pairs document the transfer. Recent-LNK embedded Machine-Identifier and Volume-Label fields preserve the SOURCE server's identity — a LNK pointing to \\\\fileserver\\share\\... confirms remote-read. AutomaticDestinations JumpLists per-app corroborate."
    attribution: "Remote → Local staging"
    casey: "C3"

  - n: 6
    question: "Any runtime-only indicators the user knew this was risky (incognito browsing, cleared registry trail)?"
    artifacts:
      - Chrome-History
      - Edge-History
      - Regedit-LastKey
    join-key:
      concept: UserSID
      role: profileOwner
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records TargetUserSid alongside TargetDomainName and TargetUserName; the SID is the persistent machine-unique account identifier that threads session events to ProfileList, SAM, and NTDS-dit records for the same account (Microsoft, n.d.)."
    conclusion: "Gaps in Chrome-History / Edge-History that don't correspond to normal usage lulls = possible InPrivate / Incognito usage. Regedit-LastKey pointing at Security / Defender / Explorer-MRU-clearing registry paths = post-activity tamper attempt. Combined with Steps 1-5, indicates conscious awareness of off-role access."
    attribution: "Awareness / cover-up indicators"
    casey: "C2"
provenance:
  - ms-event-4728
  - mitre-t1098-007
  - ms-event-4732
  - ms-event-4738
  - mitre-t1098
  - mitre-t1003-006
  - fortra-2022-secretsdump-py-cache-entry-ext
  - libyal-libesedb
  - ms-event-4624
  - uws-event-4624
  - ms-event-4648
  - uws-event-4648
  - ms-network-location-awareness-nla-serv
  - ms-network-list-service-and-the-signat
  - libyal-libevtx
  - ms-event-5140
  - uws-event-5140
  - ms-event-4663
  - uws-event-4663
  - ms-event-4656
  - uws-event-4656
  - online-2021-registry-hive-file-format-prim
  - libyal-libfwsi
  - libyal-libregf
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
  - libyal-libusnjrnl-usn-journal-format-max-header
  - ms-change-journal-record-header-fsctl
  - libyal-liblnk
  - ms-shllink
  - libyal-libolecf
  - ms-cfb
  - chromium-history-schema
  - ms-registry-editor-navigation-state-pe
  - carvey-2013-recentfilecache-bcf-parser-and
  - ms-event-4672
  - uws-event-4672
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

# Mover Privilege-Accumulation + Lateral-Access Chain

## Purpose
ITM's Mover (PR032) pattern: an internal employee who changed roles and retains BOTH old + new access for a window, potentially exploited to reach data outside their current legitimate scope. Distinct from external-attacker lateral movement because the access paths are legitimately-granted, making the behavior (off-role access) rather than the authentication the forensic signal.
