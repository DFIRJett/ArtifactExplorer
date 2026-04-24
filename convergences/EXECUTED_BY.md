---
name: EXECUTED_BY
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: EXECUTED_BY
  ceiling: C3
inputs:
  - AUTHENTICATED
  - EXECUTED
input-sources:
  - proposition: EXECUTED
    artifacts:
      - BAM
      - Security-4688
      - Sysmon-1
      - UserAssist
join-chain:
  - concept: UserSID
    join-strength: strong
    sources:
      - koroshec-2021-user-access-logging-ual-a-uniq
      - ms-event-4688
      - ms-sysmon-system-monitor
      - libyal-libregf
    primary-source: ms-event-4688
    description: |
      Actor attribution pivot. BAM self-closes EXECUTED_BY by storing
      (user-SID, executable-path, last-run FILETIME) in one record —
      no session-chain inference needed. UserAssist is equally direct
      via HKCU scope (the NTUSER hive IS the user's). Security-4688
      carries SubjectUserSid on the process-creation event; Sysmon-1
      provides User field (or LogonId for SID resolution via the 4624
      session). Joining on UserSID establishes WHO ran the process
      across all four witnesses — without it, process creation events
      are events "on the system" rather than events "by this user."
    artifacts-and-roles:
      - artifact: BAM
        role: actingUser
      - artifact: UserAssist
        role: actingUser
      - artifact: Security-4688
        role: actingUser
      - artifact: Sysmon-1
        role: actingUser
  - concept: ExecutablePath
    join-strength: moderate
    sources:
      - ms-event-4688
      - ms-include-command-line-in-process-cre
      - ms-sysmon-system-monitor
      - hartong-2024-sysmon-modular-a-repository-of
    primary-source: ms-event-4688
    description: |
      Object-of-execution pivot. All four witnesses carry the binary path —
      BAM's RegBinary-encoded path, UserAssist's ROT13-encoded path,
      Security-4688's NewProcessName, Sysmon-1's Image. Same caveats as
      EXECUTED's path pivot — path is moderate-strength (relocation, symlink,
      or impersonation can break it) but combining with UserSID gives the
      composite "THIS user ran THIS program" claim. Degradation: if BAM
      purged or UserAssist cleared, ProcessId + LogonSessionId can
      substitute as the session-scoped pivot for Security-4688 + Sysmon-1
      alone.
    artifacts-and-roles:
      - artifact: BAM
        role: ranProcess
      - artifact: UserAssist
        role: ranProcess
      - artifact: Security-4688
        role: ranProcess
      - artifact: Sysmon-1
        role: ranProcess
exit-node:
  - UserSID
  - ExecutablePath
notes:
  - 'Security-4656: When the accessed object is a process or thread token, 4656 becomes the POSSESSED input for credential-theft investigations. For files/registry, 4656 is the setup event for downstream ACCESSED/MODIFIED claims via 4663/4657.'
  - 'Security-4688: self-closes via SubjectUserSid field — direct user attribution with no session-chain inference needed'
  - 'Sysmon-1: direct user attribution via User field (or LogonId → 4624 for SID resolution)'
  - 'BAM: BAM self-closes EXECUTED_BY(user, process) — both the user-sid and the executable-path are captured in one artifact. No session-chain inference needed, no ProfileList dereference needed.'
  - 'UserAssist: UserAssist self-closes EXECUTED_BY(user, process) via the direct user-sid linkage — no need for session-chain inference'
provenance:
  - koroshec-2021-user-access-logging-ual-a-uniq
  - libyal-libregf
  - ms-event-4688
  - ms-include-command-line-in-process-cre
  - uws-event-4688
  - ms-sysmon-system-monitor
  - hartong-2024-sysmon-modular-a-repository-of
  - uws-event-90001
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - ms-advanced-audit-policy
  - regripper-plugins
---

# Convergence — EXECUTED_BY

Tier-2 convergence yielding proposition `EXECUTED_BY`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: BAM, Security-4656, Security-4688, Sysmon-1, UserAssist.
