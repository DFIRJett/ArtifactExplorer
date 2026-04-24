---
name: CONFIGURED
summary: "Persistent-configuration proposition — system state is configured to automatically execute specific code across boot / logon / explorer-start / task-scheduler / service-start / image-load surfaces. Joins the persistence-mechanism artifact cluster via ExecutablePath + RegistryKeyPath + TaskName + ServiceName pivots."
yields:
  mode: new-proposition
  proposition: CONFIGURED
  ceiling: C3
inputs:
  - PERSISTED
input-sources:
  - proposition: PERSISTED
    artifacts:
      - ScheduledTask-Job-Legacy
      - Security-4697
      - System-7045
      - Startup-LNK
      - AppCertDlls
      - ImageFileExecutionOptions
join-chain:
  - concept: ExecutablePath
    join-strength: strong
    sources:
      - mitre-t1547-001
      - mitre-t1053-005
      - mitre-t1574
    description: |
      Binary-identity pivot. Every persistence mechanism ultimately
      specifies WHICH binary will run: ScheduledTask-Job-Legacy
      carries the executable path in its .job binary body;
      Security-4697 + System-7045 carry ImagePath for the
      installed service; Startup-LNK resolves to the target exe
      via the .lnk target path; AppCertDlls lists DLLs in a
      REG_MULTI_SZ registered to load into every process creating
      a user-mode process; ImageFileExecutionOptions binds Debugger
      or GlobalFlag settings to a specific image-name (not path)
      that will be launched/hooked whenever that image runs.
      Joining on ExecutablePath lets an analyst ask "which
      persistence vectors point at THIS binary" — the claim needed
      to assert the scope of a single implant's footprint.
    artifacts-and-roles:
      - artifact: ScheduledTask-Job-Legacy
        role: executablePersisted
      - artifact: Security-4697
        role: executablePersisted
      - artifact: System-7045
        role: executablePersisted
      - artifact: Startup-LNK
        role: executablePersisted
      - artifact: AppCertDlls
        role: executablePersisted
      - artifact: ImageFileExecutionOptions
        role: executablePersisted
  - concept: ServiceName
    join-strength: strong
    sources:
      - mitre-t1543-003
      - ms-scm-events
    primary-source: ms-scm-events
    description: |
      Service-identity pivot. Security-4697 + System-7045 both
      name a ServiceName for the newly-installed service; the
      Services registry key (HKLM\SYSTEM\CurrentControlSet\Services\)
      is the persistent backing store. Joining on ServiceName
      bridges the EVENT record (4697 / 7045) to the STATE record
      (Services subkey LastWrite + ImagePath value). When EVENT
      and STATE disagree (ServiceName exists in Services but no
      4697/7045 in Security log), that indicates Security log
      clearance or direct-registry service install that bypassed
      SCM.
    artifacts-and-roles:
      - artifact: Security-4697
        role: serviceName
      - artifact: System-7045
        role: serviceName
  - concept: TaskName
    join-strength: strong
    sources:
      - mitre-t1053-005
      - ms-task-scheduler-1-0-legacy-format-re
    primary-source: ms-task-scheduler-1-0-legacy-format-re
    description: |
      Task-identity pivot. ScheduledTask-Job-Legacy file name IS
      the task identifier (Task Scheduler 1.0 stored each task
      as a separate .job file in %WINDIR%\Tasks\). Modern task-
      scheduler artifacts (XML under \Windows\System32\Tasks\ +
      corresponding Security-4698 / TaskScheduler-100/140/200 events)
      are out-of-scope for this legacy-only slice. Joining on
      TaskName correlates the .job file to run-history records
      when those exist.
    artifacts-and-roles:
      - artifact: ScheduledTask-Job-Legacy
        role: taskName
  - concept: RegistryKeyPath
    join-strength: strong
    sources:
      - mitre-t1574
      - mitre-t1547-001
    description: |
      Registry-location pivot. AppCertDlls = HKLM\SYSTEM\...\Session
      Manager\AppCertDlls; ImageFileExecutionOptions = HKLM\SOFTWARE\
      Microsoft\Windows NT\CurrentVersion\Image File Execution
      Options\<image>. Joining on RegistryKeyPath binds the
      persistence artifact to the key LastWrite (when the
      persistence was configured) and to Security-4657 registry-
      modification events (when audit is enabled). Also the pivot
      for ACL-tamper detection: a writeable DACL on these keys
      for a non-admin user is a red flag.
    artifacts-and-roles:
      - artifact: AppCertDlls
        role: registryLocation
      - artifact: ImageFileExecutionOptions
        role: registryLocation
exit-node:
  - Services
  - WMI-CIM-Repository
  - FirewallRules
notes:
  - 'ScheduledTask-Job-Legacy: Task Scheduler 1.0 .job files under %WINDIR%\Tasks\. Legacy format (Win7 and earlier; removed from task-scheduler 2.0 by default but may survive in-place upgrade). Binary format — requires libfwnt-style parser.'
  - 'Security-4697: service-installed audit event (Subcategory: Security System Extension). Emits ServiceName + ImagePath + AccountSid of installer. Requires audit policy enabled.'
  - 'System-7045: SCM service-installation event in System log. Emits ServiceName + ImagePath + ServiceType + StartType + ServiceAccount. Universal — does NOT require audit policy (SCM emits it regardless).'
  - 'Startup-LNK: .lnk files in %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup. Legitimate user-convenience location but also a classic per-user persistence anchor.'
  - 'AppCertDlls: HKLM\SYSTEM\...\Session Manager\AppCertDlls — DLLs loaded into every process that calls CreateProcess. High-impact persistence (runs in every user-mode process creation).'
  - 'ImageFileExecutionOptions: HKLM\...\Image File Execution Options\<image-name> — Debugger subkey reroutes launching of the named image through a different binary. Classic utilman.exe-replacement / sticky-keys persistence mechanism.'
provenance:
  - ms-task-scheduler-1-0-legacy-format-re
  - ms-scm-events
  - mitre-t1547-001
  - libyal-libfwnt-job-file-format-libwrc-reverse
  - mitre-t1053-005
  - mitre-t1543-003
  - mitre-t1547-001
  - mitre-t1574
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — CONFIGURED

Tier-2 convergence yielding proposition `CONFIGURED`.

Binds six persistence-mechanism artifacts spanning scheduled tasks, service installation (event + event), startup LNKs, AppCertDlls, and Image File Execution Options. ExecutablePath + ServiceName + TaskName + RegistryKeyPath pivots resolve the binary target and the persistence anchor's location.

Participating artifacts: ScheduledTask-Job-Legacy, Security-4697, System-7045, Startup-LNK, AppCertDlls, ImageFileExecutionOptions.
