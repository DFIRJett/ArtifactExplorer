---
name: Security-control degradation chain (Defender + firewall tamper → out-of-band tool)
anchors:
  entry: LogonSessionId
  conclusions:
    - UserSID
    - FirewallRuleName
severity: reference
summary: |
  Insider with local admin disables Defender, drops AV exclusion
  for a staging folder, turns off a firewall profile, and runs an
  out-of-band remote-access or data-exfil tool. Analyst reconstructs
  the control-weakening sequence as preparation.
narrative: |
  Grounded in ITM PR018 Circumventing Security Controls + PR037
  Oversight Circumvention and Control Degradation + AF007 Modify
  Windows Registry + IF014 Unauthorized Changes. The signature
  pattern: multiple defense-impairment registry writes clustered
  in time before the payload execution. Each tamper is individually
  deniable ("I was troubleshooting") but the cluster + proximate
  payload execution makes intent clear.

artifacts:
  primary:
    - Security-4624
    - Security-4672
    - Security-4688
    - Defender-Exclusions
    - Defender-ASR-Rules
    - Defender-MPLog
    - Security-4657
    - Windows-Firewall-Profiles
    - FirewallRules
    - Firewall-2004
    - Firewall-2005
    - Firewall-2006
    - Sysmon-13
    - Sysmon-1
    - Security-5156
    - Sysmon-3
    - firewall-log
    - SRUM-NetworkUsage
    - UsnJrnl
    - GroupPolicy-Registry-Pol
  corroborating:
    - LSA-Protection-RunAsPPL
    - Credential-Guard-State

join-keys:
  - concept: LogonSessionId
    role: sessionContext
  - concept: UserSID
    role: profileOwner
  - concept: HandleId
    role: openedHandle
  - concept: ProcessId
    role: actingProcess
  - concept: ExecutableHash
    role: contentHash
  - concept: FirewallRuleName
    role: modifiedRule
  - concept: IPAddress
    role: destinationIp

steps:
  - n: 1
    question: "Who elevated and opened a privileged shell?"
    artifacts:
      - Security-4624
      - Security-4672
      - Security-4688
    join-key:
      concept: LogonSessionId
      role: sessionContext
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records a successful account logon and emits TargetLogonId, a hex LUID that uniquely identifies the session until the matching 4634 logoff closes it, threading every in-session event through a single session scope (Microsoft, n.d.)."
    conclusion: "Security-4624 (interactive / remote-interactive) followed by Security-4672 (special privileges assigned) for the same LogonID = UAC elevation OR local-admin session. Security-4688 for reg.exe / powershell.exe / cmd.exe with IntegrityLevel=High in the same session = elevated shell present. TargetLogonId threads forward."
    attribution: "Account → Elevated session"
    casey: "C2"

  - n: 2
    question: "Were Defender exclusions added or ASR rules disabled?"
    artifacts:
      - Defender-Exclusions
      - Defender-ASR-Rules
      - Defender-MPLog
      - Security-4657
    join-key:
      concept: HandleId
      role: openedHandle
    primary-source: ms-advanced-audit-policy
    attribution-sentence: "Windows Advanced Audit Policy object-access events record HandleId, a per-process handle identifier that correlates matching 4656 (open), 4663 (access), and 4658 (close) events to bracket the object's handle-lifetime within a process (Microsoft, n.d.)."
    conclusion: "Registry writes under Software\\Microsoft\\Windows Defender\\Exclusions (Paths, Processes, Extensions) OR Software\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR (per-rule disable). Security-4657 ValueSet records with HandleId tied back to reg.exe / PowerShell ProcessId. Defender-MPLog corroborates configuration-change events from Defender's perspective."
    attribution: "Defender posture weakened"
    casey: "C3"

  - n: 3
    question: "Was the firewall profile or a specific rule altered?"
    artifacts:
      - Windows-Firewall-Profiles
      - FirewallRules
      - Firewall-2004
      - Firewall-2005
      - Firewall-2006
    join-key:
      concept: FirewallRuleName
      role: modifiedRule
    primary-source: mitre-t1562-004
    attribution-sentence: "Adversaries may disable or modify system firewalls to bypass controls limiting network usage; Windows Firewall audit events cite the FirewallRuleName, making rule-level modifications individually attributable (MITRE ATT&CK, n.d.)."
    conclusion: "Windows-Firewall-Profiles registry writes disabling Domain / Private / Public profile OR FirewallRules registry additions allowing specific attacker-needed ports. Firewall-2004 (rule added) / 2005 (modified) / 2006 (deleted) events on the MpsSvc Firewall channel. ModifyingUser field = the account. RuleName joins registry-change evidence to policy-accept evidence."
    attribution: "Firewall posture weakened"
    casey: "C3"

  - n: 4
    question: "What process made the registry / firewall edits?"
    artifacts:
      - Sysmon-13
      - Security-4657
      - Sysmon-1
      - Security-4688
    join-key:
      concept: ProcessId
      role: actingProcess
    primary-source: ms-event-4688
    attribution-sentence: "Event 4688 records every successful process creation with NewProcessId (a system-wide unique PID for the lifetime of the process) and SubjectLogonId, threading the process back to a specific user session (Microsoft, n.d.)."
    conclusion: "Sysmon-13 (RegistryEvent-Set) and Security-4657 (value-set) both carry ProcessId. Joined to Sysmon-1 / Security-4688 process-creation of reg.exe / powershell.exe / direct registry APIs = confirms which process generated the tamper. Command-line (if Audit-Process-Creation-with-CLI is on) reveals exact invocation."
    attribution: "Tamper-process identified"
    casey: "C3"

  - n: 5
    question: "Did the degraded controls permit a new outbound listener / connection?"
    artifacts:
      - Security-5156
      - Sysmon-3
      - firewall-log
      - SRUM-NetworkUsage
    join-key:
      concept: ProcessId
      role: actingProcess
    primary-source: ms-event-4688
    attribution-sentence: "Event 4688 records every successful process creation with NewProcessId (a system-wide unique PID for the lifetime of the process) and SubjectLogonId, threading the process back to a specific user session (Microsoft, n.d.)."
    conclusion: "Security-5156 Filtering-Platform-Connection events post-dating the rule change whose ports / IPs match the new rule scope = rule had enforcement effect. Sysmon-3 corroborates outbound destinations. SRUM-NetworkUsage quantifies bytes-out. If the degradation enabled an attacker RAT / exfil binary, its outbound traffic surfaces here."
    attribution: "Degradation → Network effect"
    casey: "C3"

  - n: 6
    question: "Any attempt to revert the changes before logoff to hide intent?"
    artifacts:
      - Security-4657
      - UsnJrnl
      - GroupPolicy-Registry-Pol
    join-key:
      concept: HandleId
      role: openedHandle
    primary-source: ms-advanced-audit-policy
    attribution-sentence: "Windows Advanced Audit Policy object-access events record HandleId, a per-process handle identifier that correlates matching 4656 (open), 4663 (access), and 4658 (close) events to bracket the object's handle-lifetime within a process (Microsoft, n.d.)."
    conclusion: "Second Security-4657 / Sysmon-13 event on the SAME registry key within the same session that REVERSES the prior change = revert attempt. Combined with Step 2's WEAKEN event, the pair demonstrates deliberate temporary degradation (weaken → exploit → restore). GroupPolicy-Registry-Pol refresh may partially re-enforce baseline — check whether the user's changes out-survive GPO refresh."
    attribution: "Cover-up detected"
    casey: "C2"
provenance:
  - ms-event-4624
  - uws-event-4624
  - ms-event-4672
  - uws-event-4672
  - ms-event-4688
  - ms-include-command-line-in-process-cre
  - uws-event-4688
  - ms-configure-and-validate-exclusions-f
  - ms-protect-security-settings-with-tamp
  - mitre-t1562-001
  - ms-attack-surface-reduction-rules-rule
  - ms-controlled-folder-access-anti-ranso
  - ms-defender-events
  - ms-event-4657
  - uws-event-4657
  - ms-windows-defender-firewall-registry
  - mitre-t1562-004
  - libyal-libregf
  - libyal-libevtx
  - ms-sysmon-system-monitor
  - hartong-2024-sysmon-modular-13-registry-eve
  - uws-event-90013
  - hartong-2024-sysmon-modular-a-repository-of
  - uws-event-90001
  - ms-event-5156
  - mitre-t1071
  - hartong-2024-sysmon-modular-3-network-conne
  - trustedsec-2022-sysinternals-sysmon-a-swiss-ar
  - koroshec-2021-user-access-logging-ual-a-uniq
  - libyal-libesedb
  - khatri-srum-dump
  - libyal-libusnjrnl-usn-journal-format-max-header
  - ms-change-journal-record-header-fsctl
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - carrier-2005-file-system-forensic-analysis
  - ms-group-policy-registry-extension-and
  - mitre-t1484-001
  - schroeder-2016-get-gpppassword-powershell-one
  - project-2023-windowsbitsqueuemanagerdatabas
  - ms-configuring-additional-lsa-protecti
  - mitre-t1003-001
  - robbins-2022-group-policy-preferences-and-t
  - ms-credential-guard-manage-configure-a
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - thedfirreport
  - ms-advanced-audit-policy
  - regripper-plugins
---

# Security-Control Degradation Chain

## Purpose
ITM's classic pre-payload control-weakening pattern. The chain demonstrates HOW multiple minor tamper events, each individually deniable, cluster together in time + scope in a way that demonstrates coordinated defense evasion.
