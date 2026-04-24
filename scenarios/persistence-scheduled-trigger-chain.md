---
name: Persistence via scheduled-trigger chain (delayed-execution data collection)
anchors:
  entry: TaskName
  conclusions:
    - UserSID
    - LogonSessionId
    - MFTEntryReference
severity: reference
summary: |
  Insider plants a Scheduled Task that runs a data-collection script
  at logoff / idle so exfil runs without the user present. Analyst
  traces task creation → action → trigger fire → file reads → output
  staging → post-op cleanup.
narrative: |
  Grounded in ITM AF025 Delayed Execution Triggers + PR016 Data
  Staging + IF027 Installing Malicious Software (benign-LOLBin
  variant — the "software" is often PowerShell or robocopy). The
  pattern exploits the separation of user-action-time from payload-
  execution-time: the user plants the task during a normal session,
  then execution happens hours later under a different logon context
  when investigators naturally don't connect the dots.

artifacts:
  primary:
    - Security-4698
    - TaskScheduler-106
    - Scheduled-Tasks
    - ScheduledTask-XML
    - Amcache-InventoryApplicationFile
    - Prefetch
    - TaskScheduler-200
    - TaskScheduler-201
    - Security-4624
    - Security-4688
    - Sysmon-11
    - Security-4663
    - MFT
    - UsnJrnl
    - ShellBags
    - I30-Index
    - ActivitiesCache
  corroborating:
    - Sysmon-1
    - Security-4699
    - PSReadline-history

join-keys:
  - concept: TaskName
    role: scheduledTask
  - concept: UserSID
    role: profileOwner
  - concept: ExecutablePath
    role: configuredPersistence
  - concept: ExecutableHash
    role: contentHash
  - concept: ProcessId
    role: actingProcess
  - concept: LogonSessionId
    role: sessionContext
  - concept: HandleId
    role: openedHandle
  - concept: MFTEntryReference
    role: targetFile

steps:
  - n: 1
    question: "Was a new Scheduled Task registered by a non-admin user context?"
    artifacts:
      - Security-4698
      - TaskScheduler-106
      - Scheduled-Tasks
      - ScheduledTask-XML
    join-key:
      concept: TaskName
      role: scheduledTask
    primary-source: ms-task-scheduler-1-0-legacy-format-re
    attribution-sentence: "Each scheduled task registered with Task Scheduler 2.0 is stored as an XML file under %WINDIR%\\System32\\Tasks\\ with a canonical path that is the TaskName, and Task Scheduler events 106 / 140 / 141 cite that same TaskName at register, update, and delete (Microsoft, n.d.)."
    conclusion: "Security-4698 (task-scheduled) + TaskScheduler/Operational event 106 (task registered) capture the creation. TaskName uniquely identifies the new task. SubjectUserSid in the 4698 XML = creator. ScheduledTask-XML file at %WINDIR%\\System32\\Tasks\\<TaskName> holds Author field (often creator's DOMAIN\\username — direct attribution) + full trigger and action details."
    attribution: "Task → Creator identified"
    casey: "C2"

  - n: 2
    question: "What action / binary does the task invoke?"
    artifacts:
      - ScheduledTask-XML
      - Amcache-InventoryApplicationFile
      - Prefetch
    join-key:
      concept: ExecutablePath
      role: configuredPersistence
    primary-source: ms-event-4688
    attribution-sentence: "Event 4688 records every successful process creation with NewProcessName (full executable path) and SubjectLogonId, chaining a program launch to both a specific account and a specific session (Microsoft, n.d.)."
    conclusion: "ScheduledTask-XML Actions/Exec/Command = target binary; Arguments = command line. Amcache-InventoryApplicationFile SHA-1 of the binary for cross-ref. Prefetch entry for the binary gives earliest-observed execution. Typical attacker invocations: powershell.exe -enc <base64>, robocopy.exe <source> <dest>, or LOLBin scripts."
    attribution: "Action identified"
    casey: "C3"

  - n: 3
    question: "When did the task run and under which logon session?"
    artifacts:
      - TaskScheduler-200
      - TaskScheduler-201
      - Security-4624
      - Security-4688
    join-key:
      concept: ProcessId
      role: actingProcess
    primary-source: ms-event-4688
    attribution-sentence: "Event 4688 records every successful process creation with NewProcessId (a system-wide unique PID for the lifetime of the process) and SubjectLogonId, threading the process back to a specific user session (Microsoft, n.d.)."
    conclusion: "TaskScheduler/Operational 200 (action-started) + 201 (action-completed) time the fire + completion. Security-4624 type 5 (service logon) typically spawns the task's process context. Security-4688 for the task's Exec/Command with ParentProcessId = svchost.exe / taskhostw.exe confirms task-triggered execution. ProcessId threads forward to file-access."
    attribution: "Trigger → Process"
    casey: "C3"

  - n: 4
    question: "What files did the triggered process read?"
    artifacts:
      - Sysmon-11
      - Security-4663
      - MFT
      - UsnJrnl
    join-key:
      concept: HandleId
      role: openedHandle
    primary-source: ms-advanced-audit-policy
    attribution-sentence: "Windows Advanced Audit Policy object-access events record HandleId, a per-process handle identifier that correlates matching 4656 (open), 4663 (access), and 4658 (close) events to bracket the object's handle-lifetime within a process (Microsoft, n.d.)."
    conclusion: "Sysmon-11 (FileCreate for output file) + Security-4663 (file-access events when SACL is set on source directories). HandleId threads task-process ProcessId to per-file opens. UsnJrnl CREATE + DATA_EXTEND + CLOSE for the output file documents the data-collection output."
    attribution: "Process → File collection"
    casey: "C3"

  - n: 5
    question: "Was the output staged to an unusual location?"
    artifacts:
      - ShellBags
      - I30-Index
      - UsnJrnl
      - ActivitiesCache
    join-key:
      concept: MFTEntryReference
      role: targetFile
    primary-source: ms-ntfs-on-disk-format-secure-system-f
    attribution-sentence: "Every NTFS file is uniquely addressed by a file reference combining a 48-bit MFT record number and a 16-bit sequence number, and the USN Journal and $LogFile record every lifecycle change keyed on this reference (Microsoft, 2025)."
    conclusion: "Output file(s) appearing in ShellBags for a user-writable location (Downloads, Desktop, Pictures) or a user-accessible share = staging for subsequent exfil. MFTEntryReference is stable identifier across any subsequent rename/move. $I30 index entries for the directory capture presence. ActivitiesCache may record the file's activity."
    attribution: "Staging location identified"
    casey: "C2"

  - n: 6
    question: "Was the task later deleted to cover tracks?"
    artifacts:
      - Security-4699
      - UsnJrnl
      - ScheduledTask-XML
    join-key:
      concept: TaskName
      role: scheduledTask
    primary-source: ms-task-scheduler-1-0-legacy-format-re
    attribution-sentence: "Each scheduled task registered with Task Scheduler 2.0 is stored as an XML file under %WINDIR%\\System32\\Tasks\\ with a canonical path that is the TaskName, and Task Scheduler events 106 / 140 / 141 cite that same TaskName at register, update, and delete (Microsoft, n.d.)."
    conclusion: "Security-4699 (task-deleted) event with same TaskName as Step 1's creation. UsnJrnl DELETE on the System32\\Tasks\\<TaskName> XML file. The XML file itself may survive in VSS / recent-file-cache. Delete within hours of Step 3's execution + in same user session = deliberate cover-up sequence. If XML is absent but Security-4698 shows creation, the deletion itself is evidentiary."
    attribution: "Cover-up sequence"
    casey: "C2"
provenance:
  - ms-event-4698
  - uws-event-4698
  - ms-tarrask-malware-uses-scheduled-task
  - ms-task-scheduler-2-0-xml-schema-refer
  - mitre-t1053-005
  - libyal-libevtx
  - ms-task-scheduler-1-0-legacy-format-re
  - libyal-libregf
  - project-2023-windowsbitsqueuemanagerdatabas
  - rathbun-2023-program-compatibility-assistan
  - mandiant-2015-shim-me-the-way-application-co
  - carvey-2022-windows-forensic-analysis-tool
  - libyal-libscca
  - ms-event-4624
  - uws-event-4624
  - ms-event-4688
  - ms-include-command-line-in-process-cre
  - uws-event-4688
  - ms-sysmon-system-monitor
  - hartong-2024-sysmon-modular-11-file-create
  - sans-2022-the-importance-of-sysmon-event
  - ms-event-4663
  - uws-event-4663
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
  - libyal-libusnjrnl-usn-journal-format-max-header
  - ms-change-journal-record-header-fsctl
  - online-2021-registry-hive-file-format-prim
  - libyal-libfwsi
  - ms-event-4699
  - hartong-2024-sysmon-modular-a-repository-of
  - uws-event-90001
  - canary-2022-powershell-profile-persistence
  - mitre-t1059
  - mitre-t1059-001
  - ms-powershell-operational
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - thedfirreport
  - ms-advanced-audit-policy
  - regripper-plugins
---

# Persistence via Scheduled-Trigger Chain

## Purpose
Delayed-execution patterns intentionally separate intent-moment (task creation) from execution-moment (task fire) so investigators and tools miss the connection. The chain explicitly threads `TaskName` as the identifier that re-unites the two ends of the delay.
