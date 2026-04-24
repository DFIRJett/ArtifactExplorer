---
name: Authentication → process → firewall tamper convergence chain
anchors:
  entry: LogonSessionId
  conclusions:
    - UserSID
    - FirewallRuleName
severity: reference
summary: |
  Stepwise tier-3 chain correlating Security-4624 (logon), Security-4688
  (process creation), Security-4663 (object access), registry-write
  telemetry (Security-4657), and Firewall-EVTX rule changes (2004/2005/2006)
  into a single end-to-end activity timeline. Demonstrates how a logon
  LUID threads through every subsequent process, file/registry handle,
  and firewall-rule change in the session — enabling full attribution
  from "user logged on at T0" to "firewall rule was added by that user's
  process at T0+Nm" without gaps.
narrative: |
  Reference chain for Defense-Tamper scope investigations: a user logs
  on, spawns a process, that process opens a handle against the
  firewall configuration, writes a new rule, and the rule is accepted
  and enforced. Each step's artifacts are joined to the prior step by
  a single well-defined key — TargetLogonId / NewProcessId / ProcessId /
  HandleId. Walking the chain end-to-end raises cumulative attribution
  from "someone did this" (Casey C2) to "this specific user session
  performed this specific rule change via this specific process"
  (Casey C4). For any case involving Security-4946/4947/4948/4949/4950
  or Firewall-channel 2004/2005/2006 events, use this chain to trace
  back to the triggering logon.

# UNION of artifacts across all steps. Per-step lists under `steps:` below.
artifacts:
  primary:
    # Step 1 — authentication
    - Security-4624
    # Step 2 — process creation in that session
    - Security-4688
    # Step 3 — handle open against firewall config
    - Security-4663
    - Security-4656
    # Step 4 — registry write on firewall rule
    - Security-4657
    - FirewallRules
    # Step 5 — firewall rule change recorded
    - Firewall-2004
    - Firewall-2005
    - Firewall-2006
    # Step 6 — rule effect visible on network activity
    - Security-5156
    - Sysmon-3
  corroborating:
    # Session close for end-bracketing
    - Security-4634
    - Security-4647
    # Sysmon coverage for process + registry
    - Sysmon-1
    - Sysmon-13
    # Privilege escalation
    - Security-4672
    # Firewall-file artifact
    - firewall-log
    # Windows-Firewall-Profiles state (was the firewall even ENABLED)
    - Windows-Firewall-Profiles

join-keys:
  - concept: LogonSessionId
    role: sessionContext
  - concept: ProcessId
    role: actingProcess
  - concept: HandleId
    role: openedHandle
  - concept: UserSID
    role: authenticatingUser
  - concept: FirewallRuleName
    role: modifiedRule

# 
provenance:
  - ms-event-4624
  - uws-event-4624
  - ms-event-4688
  - ms-include-command-line-in-process-cre
  - uws-event-4688
  - ms-event-4663
  - uws-event-4663
  - ms-event-4656
  - uws-event-4656
  - ms-event-4657
  - uws-event-4657
  - ms-windows-defender-firewall-registry
  - mitre-t1562-004
  - libyal-libregf
  - libyal-libevtx
  - ms-event-5156
  - mitre-t1071
  - ms-sysmon-system-monitor
  - hartong-2024-sysmon-modular-3-network-conne
  - trustedsec-2022-sysinternals-sysmon-a-swiss-ar
  - ms-event-4634
  - uws-event-4634
  - ms-event-4647
  - uws-event-4647
  - hartong-2024-sysmon-modular-a-repository-of
  - uws-event-90001
  - hartong-2024-sysmon-modular-13-registry-eve
  - uws-event-90013
  - ms-event-4672
  - uws-event-4672
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - thedfirreport
  - ms-advanced-audit-policy
  - regripper-plugins
--------------------------------------------------------------------
# STEPS — 6-question analyst progression. Each step names the
# artifacts that answer the question and the single join key that
# threads the step to the prior conclusion.
# --------------------------------------------------------------------
steps:
  - n: 1
    question: "Who authenticated and when?"
    artifacts:
      - Security-4624
    join-key:
      concept: LogonSessionId
      role: sessionContext
    conclusion: "Account (UserSID) completed an interactive or network logon. 4624's TargetLogonId (LUID) IS the session-scope identifier that threads every subsequent in-session event. Logon type distinguishes console (2), network (3), RDP (10), remote service (4) — attacker entry vectors differ by type. 4624 Authentication Package + AuthenticationPackageName + WorkstationName + IpAddress complete the logon-context picture."
    attribution: "Person → Session"
    casey: "C4"

  - n: 2
    question: "What process(es) did that session spawn?"
    artifacts:
      - Security-4688
      - Sysmon-1
    join-key:
      concept: ProcessId
      role: actingProcess
    conclusion: "Every Security-4688 in this window with SubjectLogonId matching 4624's TargetLogonId is a process spawned by this session. NewProcessId (PID) is the join key forward to 4663 / 4657 / firewall events that this process generates. CommandLine field (requires Audit Process Creation → Include command line policy) reveals the exact invocation — reg.exe add / netsh advfirewall / powershell Set-NetFirewallRule are textbook tamper invocations."
    attribution: "Session → Process"
    casey: "C4"

  - n: 3
    question: "Did that process open a handle against firewall configuration?"
    artifacts:
      - Security-4663
      - Security-4656
    join-key:
      concept: HandleId
      role: openedHandle
    conclusion: "Security-4656 records the OPEN of a handle (ObjectName + HandleId + ProcessId + SubjectLogonId). 4663 records subsequent ACCESSES (read/write/delete) on that same HandleId. ObjectName of interest: HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules key (registry-backed firewall rule store) or \\Device\\HarddiskVolumeN paths for the firewall log file. HandleId is the join that links the open event to every subsequent access on the same handle by the same process."
    attribution: "Session → Process → Handle"
    casey: "C4"

  - n: 4
    question: "Did the process write to a firewall rule value?"
    artifacts:
      - Security-4657
      - FirewallRules
      - Sysmon-13
    join-key:
      concept: ProcessId
      role: actingProcess
    conclusion: "Security-4657 records REGISTRY VALUE WRITES. Filter for ObjectName under FirewallPolicy\\FirewallRules — each value-write is one rule addition / modification. ProcessId on 4657 joins to 4688's NewProcessId from Step 2. OldValue vs NewValue fields show the before-after state. Sysmon-13 is the alternate channel when Sysmon is deployed — more metadata per registry-value-write event. A chained sequence 4688 (reg.exe add) → 4656 (handle open) → 4663 (write access) → 4657 (value-set) → all sharing ProcessId is the full process-level view of a rule addition."
    attribution: "Session → Process → Registry Write"
    casey: "C4"

  - n: 5
    question: "Was the firewall rule formally added / changed / deleted (policy-layer record)?"
    artifacts:
      - Firewall-2004
      - Firewall-2005
      - Firewall-2006
    join-key:
      concept: FirewallRuleName
      role: modifiedRule
    conclusion: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall channel EventIDs 2004 (rule added), 2005 (rule modified), 2006 (rule deleted) record the POLICY-LAYER change. ModifyingUser field = the account making the change. RuleId + RuleName = the rule affected. Cross-reference RuleName with the registry-write target in Step 4: same rule name = same change. The two sources corroborate: Step 4 proves the process wrote the registry value; Step 5 proves the firewall accepted it as a rule-policy change."
    attribution: "Session → Process → Registry Write → Policy Change"
    casey: "C4"

  - n: 6
    question: "Did the modified rule have an observable network effect?"
    artifacts:
      - Security-5156
      - Sysmon-3
      - firewall-log
    join-key:
      concept: ProcessId
      role: actingProcess
    conclusion: "If the attacker's added rule allowed previously-blocked traffic, Security-5156 (Filtering Platform Connection) records subsequent successful connections matching the rule. Sysmon-3 (NetworkConnect) provides the same info with fuller context. Firewall-log (pfirewall.log) records per-packet drops/allows when logging is enabled — entries post-dating the rule change using ports/addresses matching the rule = the rule's enforcement effect. Chain complete: user → session → process → registry write → policy acceptance → network effect. 4624 TargetLogonId threads through to 5156 via SubjectLogonId on connections initiated by the attacker's session."
    attribution: "Session → Process → Rule Change → Network Effect"
    casey: "C4–C5"

# --------------------------------------------------------------------
# ADDITIONAL NOTES — cross-references and common pitfalls
# --------------------------------------------------------------------
notes: |
  **Required audit policy for full chain:**
  - Audit Logon (Success) → Security-4624
  - Audit Process Creation (Success) + "Include command line in process creation events" → Security-4688 with CommandLine
  - Audit Handle Manipulation (Success) → Security-4656 / 4658
  - Audit Object Access (Success) + SACL on firewall registry keys → Security-4663
  - Audit Registry (Success) → Security-4657 (value-level writes)
  - Firewall-With-Advanced-Security Operational channel enabled → 2004/2005/2006

  **Missed-convergence fallbacks:**
  - If 4688 command-line not captured, fallback to Sysmon-1 (always has CommandLine)
  - If 4663/4657 require SACL not deployed, fallback to Sysmon-13 for registry writes
  - If Security channel rolled before investigation, fallback to prior VSS snapshots of the Security.evtx

  **Common pitfalls:**
  - PID reuse: NewProcessId from 4688 can be reused by a later unrelated process. Bracket the NewProcessId window by the 4688 (start) and 4689 (exit) pair to be certain. Also check ProcessStartTime when correlating 4663/4657 to 4688.
  - LogonSessionId reuse: LUIDs are only unique per-boot. Cross-boot analysis requires boot-relative interpretation.
  - Network service: Security-4688 for services launched by SYSTEM show SubjectLogonId = 0x3e7 (SYSTEM LUID) — NOT the interactive user. Firewall tamper via a SYSTEM-launched service must be traced back via the service-install event (Security-4697) to find the installing user.
---

# Authentication → Firewall Tamper Convergence Chain

## Purpose
Trace a session-level tamper investigation end-to-end. Starting from "Security channel shows a firewall rule was modified" OR "Firewall-2004/2005/2006 fired," walk backwards through the join-key chain to the originating logon. Each step's join key is a single well-defined identifier — TargetLogonId (LUID) → NewProcessId (PID) → HandleId — so no step requires guessing.

## When to use this chain
- Any firewall rule change you don't have an IT ticket for
- Security-4946 / 4947 / 4948 / 4949 / 4950 firewall rule events
- Microsoft-Windows-Windows Firewall With Advanced Security/Firewall 2004 / 2005 / 2006
- Defender-Exclusion or AppLocker-Policy tamper investigations (same join-key pattern applies)

## Casey progression
- Step 1 alone: "someone with these credentials authenticated" (C2)
- Step 5: "this user's process modified this rule" (C4)
- Step 6: "this rule change produced this observable network effect" (C4–C5)

