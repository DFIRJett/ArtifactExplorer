---
name: Archive + split + email exfil chain (7-Zip / WinRAR multi-part + renamed-extension mailing)
anchors:
  entry: MFTEntryReference
  conclusions:
    - UserSID
severity: reference
summary: |
  Insider archives a sensitive directory with 7-Zip / WinRAR, splits
  it into multi-part .001 / .002 files renamed to .jpg / .pdf, emails
  the parts out over multiple days to evade attachment-size caps and
  DLP keyword scanning. Analyst reconstructs archive → rename → send.
narrative: |
  Grounded in ITM PR017 Archive Data + PR020 Data Obfuscation + IF010
  Exfiltration via Email. The split-and-rename pattern defeats both
  size-threshold DLP and extension-based scanning, but leaves a rich
  artifact trail: archiver Prefetch, file-read handles during archive
  creation, rename events in UsnJrnl, Outlook/OST attachment records
  correlated with disguised-filename attachments.

artifacts:
  primary:
    - Amcache-InventoryApplicationFile
    - Prefetch
    - PSReadline-history
    - CMD-History-Doskey
    - UserAssist
    - Sysmon-11
    - Security-4663
    - UsnJrnl
    - MFT
    - LogFile
    - I30-Index
    - Outlook-OST
    - Outlook-PST
    - AutomaticDestinations
    - JumpList-DestList-Entry
    - RecentDocs
    - Recent-LNK
    - OfficeRecent-LNK
    - Edge-History
    - Chrome-History
    - Zone-Identifier-ADS
    - RecycleBin-I-Metadata
    - ActivitiesCache
  corroborating:
    - Security-4688
    - Sysmon-1

join-keys:
  - concept: ExecutableHash
    role: contentHash
  - concept: ExecutablePath
    role: ranProcess
  - concept: HandleId
    role: openedHandle
  - concept: MFTEntryReference
    role: targetFile
  - concept: AppID
    role: jumpListApp
  - concept: URL
    role: visitedUrl
  - concept: UserSID
    role: profileOwner

steps:
  - n: 1
    question: "Was an archive utility executed against a sensitive directory?"
    artifacts:
      - Amcache-InventoryApplicationFile
      - Prefetch
      - PSReadline-history
      - CMD-History-Doskey
      - UserAssist
    join-key:
      concept: ExecutableHash
      role: contentHash
    primary-source: mitre-t1574
    attribution-sentence: "Amcache-InventoryApplicationFile records the SHA-1 hash of every executable that has run on the host under the InventoryApplicationFile subkey; BAM and 4688 events citing the same executable path cross-verify the hash-to-path binding (MITRE ATT&CK, n.d.)."
    conclusion: "Amcache SHA-1 hash identifies the archiver binary (7-Zip 7z.exe, WinRAR rar.exe, native tar). Prefetch LastRunTime pinpoints each archive-creation invocation. PSReadline / CMD history preserves the exact command line including source directory and output-archive path. UserAssist counts user-initiated launches."
    attribution: "Archiver execution identified"
    casey: "C2"

  - n: 2
    question: "Which files were read during archive creation?"
    artifacts:
      - Sysmon-11
      - Security-4663
      - UsnJrnl
      - MFT
    join-key:
      concept: HandleId
      role: openedHandle
    primary-source: ms-advanced-audit-policy
    attribution-sentence: "Windows Advanced Audit Policy object-access events record HandleId, a per-process handle identifier that correlates matching 4656 (open), 4663 (access), and 4658 (close) events to bracket the object's handle-lifetime within a process (Microsoft, n.d.)."
    conclusion: "Sysmon-11 (FileCreate) for each source file the archiver touched OR Security-4663 ObjectAccess events when SACL is on the source directory. HandleId threads the archiver's ProcessId to per-file opens. UsnJrnl USN_REASON_CLOSE records for the archive output file confirm when the archive was finalized."
    attribution: "Source-file reads by archiver"
    casey: "C3"

  - n: 3
    question: "Were the archive parts renamed / disguised post-creation?"
    artifacts:
      - UsnJrnl
      - LogFile
      - I30-Index
      - MFT
    join-key:
      concept: MFTEntryReference
      role: targetFile
    primary-source: ms-ntfs-on-disk-format-secure-system-f
    attribution-sentence: "Every NTFS file is uniquely addressed by a file reference combining a 48-bit MFT record number and a 16-bit sequence number, and the USN Journal and $LogFile record every lifecycle change keyed on this reference (Microsoft, 2025)."
    conclusion: "UsnJrnl USN_REASON_RENAME_OLD_NAME + RENAME_NEW_NAME pairs document the .001 → .jpg deception per file. MFTEntryReference remains stable across the rename — the same MFT record appears as both archive-part and disguised-photo, proving the same on-disk content under two filenames. $LogFile records the transactional rename sequence. $I30 index-slack may still hold the old .001 name in free space."
    attribution: "Deceptive renames proven"
    casey: "C3"

  - n: 4
    question: "Were the disguised parts attached to outbound mail via the mail client?"
    artifacts:
      - Outlook-OST
      - Outlook-PST
      - JumpList-DestList-Entry
      - AutomaticDestinations
      - RecentDocs
      - Recent-LNK
    join-key:
      concept: AppID
      role: jumpListApp
    primary-source: mitre-t1204
    attribution-sentence: "Windows AppIDs uniquely identify installed applications; Jump List entries, BAM records, and UserAssist are all keyed by AppID, enabling per-application execution evidence to be aggregated across artifacts (MITRE ATT&CK, n.d.)."
    conclusion: "Outlook OST holds the outbound-mail record with attachment metadata — filenames + MIME types of the attached .jpg files. The filenames match the renamed archive-parts from Step 3. Outlook JumpList AutomaticDestinations (keyed by Outlook's AppID) preserves recent-file references. Recent-LNK confirms per-attachment access by the user immediately before send."
    attribution: "Mail attachments tie to disguised archive parts"
    casey: "C3"

  - n: 5
    question: "Do browser / webmail artifacts corroborate if Outlook wasn't used?"
    artifacts:
      - Edge-History
      - Chrome-History
      - Zone-Identifier-ADS
    join-key:
      concept: URL
      role: visitedUrl
    primary-source: ms-background-intelligent-transfer-ser
    attribution-sentence: "The Background Intelligent Transfer Service records each queued URL in qmgr.db, preserving the attacker-chosen endpoint as evidence even after the downloaded file is cleaned from the filesystem (Microsoft, 2022)."
    conclusion: "Browser history for the webmail provider (Gmail, ProtonMail, personal Outlook web) during the send window + Chrome / Edge Downloads entries for any archive parts re-downloaded to verify. Zone-Identifier ADS distinguishes internet-sourced from local-authored files."
    attribution: "Webmail exfil path (alternate)"
    casey: "C3"

  - n: 6
    question: "Did the subject attempt to clear evidence of the archive?"
    artifacts:
      - RecycleBin-I-Metadata
      - UsnJrnl
      - ActivitiesCache
    join-key:
      concept: MFTEntryReference
      role: targetFile
    primary-source: ms-ntfs-on-disk-format-secure-system-f
    attribution-sentence: "Every NTFS file is uniquely addressed by a file reference combining a 48-bit MFT record number and a 16-bit sequence number, and the USN Journal and $LogFile record every lifecycle change keyed on this reference (Microsoft, 2025)."
    conclusion: "Recycle Bin $I records + MFT resident data preserve the archive-file metadata even after deletion. UsnJrnl USN_REASON_FILE_DELETE records time the deletion. ActivitiesCache (Windows Timeline) may retain an Activity entry for the archive file referencing its original path + MFT entry. Post-delete UsnJrnl records with MFTEntryReference matching Step 1's archive = proof of cover-up attempt."
    attribution: "Cleanup attempted (cover-up signal)"
    casey: "C2"
provenance:
  - rathbun-2023-program-compatibility-assistan
  - mandiant-2015-shim-me-the-way-application-co
  - libyal-libregf
  - carvey-2022-windows-forensic-analysis-tool
  - libyal-libscca
  - canary-2022-powershell-profile-persistence
  - mitre-t1059
  - mitre-t1059-001
  - ms-powershell-operational
  - ms-sysmon-system-monitor
  - hartong-2024-sysmon-modular-11-file-create
  - sans-2022-the-importance-of-sysmon-event
  - ms-event-4663
  - uws-event-4663
  - libyal-libusnjrnl-usn-journal-format-max-header
  - ms-change-journal-record-header-fsctl
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - carrier-2005-file-system-forensic-analysis
  - ms-ntfs-on-disk-format-secure-system-f
  - libyal-libpff
  - ms-pst
  - libyal-libolecf
  - ms-cfb
  - libyal-liblnk
  - ms-shllink
  - libyal-libfwsi
  - chromium-history-schema
  - carvey-2010-rifiuti-rifiuti2-info2-parser
  - ms-how-the-recycle-bin-stores-files-in
  - ms-event-4688
  - ms-include-command-line-in-process-cre
  - uws-event-4688
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

# Archive + Split + Email Exfil Chain

## Purpose
ITM's classic "archive-and-disguise" insider pattern, broken into artifact-threaded investigative steps. Key join: MFTEntryReference threads the rename operation (Step 3) — the same on-disk content appears under successive filenames, which is the proof of deception no other artifact provides as cleanly.

## Casey ceiling
C3. Would escalate to C4 with corroborating mail-gateway logs at the enterprise egress point confirming external recipient + attachment sizes matching archive-parts.
