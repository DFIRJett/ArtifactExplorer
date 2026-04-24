---
name: Anti-forensic log + shadow wipe chain (leaver clears Security.evtx and deletes VSS)
anchors:
  entry: LogonSessionId
  conclusions:
    - UserSID
    - VolumeGUID
    - FilesystemVolumeSerial
    - MachineNetBIOS
severity: reference
summary: |
  Insider clears the Security event log, deletes Volume Shadow Copies,
  and wipes PowerShell history before departure. Analyst reconstructs
  what was hidden using secondary artifacts (Amcache, Prefetch, VSS
  snapshots that survived the wipe, Sysmon, WER).
narrative: |
  Grounded in ITM AF001 Hiding Command History + AF002 Log Deletion +
  AF020 Deletion of Volume Shadow Copy + AF014 System Shutdown. The
  classic pre-departure cleanup pattern: the user runs several
  anti-forensic commands in sequence, intending that Security log
  gaps, shadow-copy deletion, and history-file wipes prevent
  reconstruction. In practice the commands THEMSELVES leave traces
  (Security-1102 log-cleared, Sysmon-1 / Amcache of the wiper binary,
  even the execution timestamp in Prefetch) because the artifacts
  that record execution evidence are DIFFERENT from the artifacts
  being cleared.

artifacts:
  primary:
    - Security-1102
    - System-104
    - Sysmon-1
    - Security-4688
    - PowerShell-4104
    - PSReadline-history
    - Prefetch
    - Amcache-InventoryApplicationFile
    - RecentFileCache-BCF
    - BAM
    - DAM
    - VSS-Shadow-Copies
    - MFT
    - UsnJrnl
    - LogFile
    - System-1074
    - System-41
    - ShutdownTime
    - WER-Report
  corroborating:
    - CMD-History-Doskey
    - Registry-Transaction-Logs

join-keys:
  - concept: ProcessId
    role: actingProcess
  - concept: ExecutablePath
    role: ranProcess
  - concept: ExecutableHash
    role: contentHash
  - concept: LogonSessionId
    role: sessionContext
  - concept: UserSID
    role: identitySubject
  - concept: VolumeGUID
    role: mountedVolume
  - concept: FilesystemVolumeSerial
    role: runtimeSerial
  - concept: MachineNetBIOS
    role: trackerMachineId

steps:
  - n: 1
    question: "Did a process issue a log-clear call?"
    artifacts:
      - Security-1102
      - System-104
      - Sysmon-1
      - Security-4688
    join-key:
      concept: ProcessId
      role: actingProcess
    primary-source: ms-event-4688
    attribution-sentence: "Event 4688 records every successful process creation with NewProcessId (a system-wide unique PID for the lifetime of the process) and SubjectLogonId, threading the process back to a specific user session (Microsoft, n.d.)."
    conclusion: "Security-1102 (audit log cleared) is AUTO-GENERATED as the FIRST event after a clear — it cannot be prevented by clearing the log. System-104 (other-log cleared). Both events carry SubjectUserSid + SubjectLogonId identifying the clearer. Sysmon-1 / Security-4688 for wevtutil.exe / PowerShell Clear-EventLog / WinEvent clear invocation = process-side confirmation."
    attribution: "Actor → Clear command"
    casey: "C3"

  - n: 2
    question: "Were shadow copies deleted (vssadmin / WMIC / PowerShell)?"
    artifacts:
      - PowerShell-4104
      - Sysmon-1
      - PSReadline-history
      - Prefetch
    join-key:
      concept: ExecutablePath
      role: ranProcess
    primary-source: ms-event-4688
    attribution-sentence: "Event 4688 records every successful process creation with NewProcessName (full executable path) and SubjectLogonId, chaining a program launch to both a specific account and a specific session (Microsoft, n.d.)."
    conclusion: "PowerShell-4104 (script-block logging) captures any PS invocation of Delete-ShadowCopy / WMI shadowcopy delete. Sysmon-1 captures vssadmin.exe / wmic.exe with command-line showing 'delete shadows' or 'shadowcopy delete'. Prefetch entry for vssadmin.exe / wmic.exe with LastRunTime matches. PSReadline-history shows the PowerShell command text directly."
    attribution: "Actor → Shadow-delete command"
    casey: "C3"

  - n: 3
    question: "Was PSReadline / Doskey history zeroed or redirected?"
    artifacts:
      - PSReadline-history
      - CMD-History-Doskey
      - UsnJrnl
      - MFT
    join-key:
      concept: MFTEntryReference
      role: targetFile
    primary-source: ms-ntfs-on-disk-format-secure-system-f
    attribution-sentence: "Every NTFS file is uniquely addressed by a file reference combining a 48-bit MFT record number and a 16-bit sequence number, and the USN Journal and $LogFile record every lifecycle change keyed on this reference (Microsoft, 2025)."
    conclusion: "UsnJrnl USN_REASON_FILE_TRUNCATE + DATA_OVERWRITE on ConsoleHost_history.txt = the file was zeroed in place. USN_REASON_RENAME pairs suggest replacement with an empty file. MFT entry for the file is stable across the overwrite — cross-reference with PSReadline-history's surviving partial-content if any. UserSID (owner) from MFT $SI."
    attribution: "Actor → History wipe"
    casey: "C2"

  - n: 4
    question: "What can we still recover from shadow copies on disk or backup?"
    artifacts:
      - VSS-Shadow-Copies
      - MFT
      - LogFile
    join-key:
      concept: VolumeGUID
      role: mountedVolume
    primary-source: ms-shllink
    attribution-sentence: "A Shell Link (.LNK) file's LinkTargetIDList carries a VolumeID shell item encoding the volume's drive-type, serial number, and label, preserving volume-identity-to-file binding across sessions (Microsoft, 2024)."
    conclusion: "If ANY shadow copies survived (vssadmin delete may have failed on some, or the attacker ran it targeting only the default volume), they contain the pre-wipe filesystem state. Map VolumeGUID + FilesystemVolumeSerial from VSS metadata to the live volume. Load each snapshot read-only; recover the pre-clear Security.evtx + pre-wipe PSReadline history + pre-delete files."
    attribution: "Pre-wipe state recovery (when available)"
    casey: "C3"

  - n: 5
    question: "Does Amcache / Prefetch still show the wiper execution the event log no longer covers?"
    artifacts:
      - Amcache-InventoryApplicationFile
      - Prefetch
      - RecentFileCache-BCF
      - BAM
      - DAM
    join-key:
      concept: ExecutableHash
      role: contentHash
    primary-source: mitre-t1574
    attribution-sentence: "Amcache-InventoryApplicationFile records the SHA-1 hash of every executable that has run on the host under the InventoryApplicationFile subkey; BAM and 4688 events citing the same executable path cross-verify the hash-to-path binding (MITRE ATT&CK, n.d.)."
    conclusion: "Security.evtx is cleared but execution-evidence artifacts survive: Amcache SHA-1 of wevtutil.exe / vssadmin.exe + FirstRunTime. Prefetch LastRunTime of the same binaries. BAM / DAM has the process with SID + per-user timestamp. Even cleared-log anti-forensics cannot touch these — they are written by unrelated subsystems (PCA, Task Manager / AELookup) that don't pipe through the Security provider."
    attribution: "Execution-evidence survival (multiple sources)"
    casey: "C3"

  - n: 6
    question: "Did a clean shutdown or forced crash follow (hiding memory)?"
    artifacts:
      - System-1074
      - System-41
      - ShutdownTime
      - WER-Report
    join-key:
      concept: MachineNetBIOS
      role: trackerMachineId
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records WorkstationName (the NetBIOS name of the originating host) for network logons, threading remote authentication events back to the specific source workstation (Microsoft, n.d.)."
    conclusion: "System-1074 (clean shutdown by user) / System-41 (Kernel-Power unexpected reboot) timestamps bracket the host's power-state transition after the wipe sequence. ShutdownTime registry value records last clean-shutdown moment. WER Report.wer files may preserve crash evidence if the forced reboot produced a crash dump. Pairs the cleanup sequence with the power-event that terminated the session."
    attribution: "Post-wipe shutdown timeline"
    casey: "C2"
provenance:
  - ms-event-1102
  - uws-event-1102
  - mitre-t1070-001
  - ms-sysmon-system-monitor
  - hartong-2024-sysmon-modular-a-repository-of
  - uws-event-90001
  - ms-event-4688
  - ms-include-command-line-in-process-cre
  - uws-event-4688
  - mitre-t1059
  - mitre-t1059-001
  - ms-powershell-operational
  - libyal-libevtx
  - canary-2022-powershell-profile-persistence
  - carvey-2022-windows-forensic-analysis-tool
  - libyal-libscca
  - libyal-libusnjrnl-usn-journal-format-max-header
  - ms-change-journal-record-header-fsctl
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - carrier-2005-file-system-forensic-analysis
  - ms-ntfs-on-disk-format-secure-system-f
  - ms-volume-shadow-copy-service-vss-arch
  - mitre-t1490
  - carvey-2009-working-with-volume-shadow-copies
  - libyal-libvshadow-libvshadow-offline-vss-metadat
  - rathbun-2023-program-compatibility-assistan
  - mandiant-2015-shim-me-the-way-application-co
  - libyal-libregf
  - carvey-2013-recentfilecache-bcf-parser-and
  - singh-2017-cortana-forensics-windows-10
  - project-2023-windowsbitsqueuemanagerdatabas
  - koroshec-2021-user-access-logging-ual-a-uniq
  - ms-user32-event-1074-shutdown-initiate
  - ms-event-id-41-the-system-has-rebooted
  - mitre-t1070
  - ms-session-manager-smss-exe-shutdown-w
  - ms-windows-error-reporting-architectur
  - mitre-t1497
  - 13cubed-2020-print-job-forensics-recovering
  - online-2021-registry-hive-file-format-prim
  - suhanov-2019-windows-registry-forensics-par
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - thedfirreport
  - ms-advanced-audit-policy
  - regripper-plugins
---

# Anti-forensic Log + Shadow Wipe Chain

## Purpose
Reconstruct a pre-departure cleanup sequence where the user assumed clearing Security.evtx + deleting shadows + wiping PowerShell history would prevent investigation. The chain demonstrates that Windows execution-evidence artifacts (Amcache, Prefetch, BAM, DAM) SURVIVE clearing operations targeting DIFFERENT artifacts — because they're written by independent subsystems, not by the Security provider.

## Why this is a convergence chain
Each cleanup action (log clear, VSS delete, history wipe) leaves evidence in an INDEPENDENT artifact that the action didn't touch. Triangulating across those independent sources (Security-1102 + Sysmon-1 + Amcache + Prefetch + surviving VSS) reconstructs the cleanup sequence despite the primary targets being destroyed.
