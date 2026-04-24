---
name: ANTI_FORENSIC_COORDINATED_WIPE
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: ANTI_FORENSIC_COORDINATED_WIPE
  ceiling: C3
inputs:
  - DELETED
input-sources:
  - proposition: DELETED
    artifacts:
      - System-104
      - Security-1102
join-chain:
  - concept: LogonSessionId
    join-strength: strong
    sources:
      - mitre-t1070-001
      - ms-event-1102
    primary-source: ms-event-1102
    description: |
      Session-window pivot bracketing the coordinated wipe. Both
      Security-1102 (Security-channel cleared) and System-104 (System-
      channel cleared) carry SubjectLogonId — the LUID of the acting
      session. When the two events fire within minutes of each other
      AND share the same SubjectLogonId, the convergence is
      near-certain coordinated wipe (not two unrelated log-clear
      operations). Single-channel clears (Security-1102 alone OR
      System-104 alone) are common admin hygiene; the dual-channel
      SAME-SESSION pattern is the anti-forensic fingerprint.
    artifacts-and-roles:
      - artifact: Security-1102
        role: sessionContext
      - artifact: System-104
        role: sessionContext
  - concept: UserSID
    join-strength: strong
    sources:
      - mitre-t1070-001
    description: |
      Actor-attribution pivot. SubjectUserSid on both 1102 and 104
      names the account that invoked wevtutil clear-log / Clear-
      EventLog / Get-WinEvent piped to the clear-log cmdlet. Binds
      the wipe to a specific user account — critical for attribution
      when auth audit (4624) also fired in the same session.
    artifacts-and-roles:
      - artifact: Security-1102
        role: actingUser
      - artifact: System-104
        role: actingUser
exit-node:
  - Security-1102
  - System-104
notes:
  - 'System-104: Security-1102 + System-104 within the same session + minutes apart = coordinated dual-channel wipe. Well-prepared attackers clear both because System-104 can reveal service installs (7045), unexpected shutdowns (41), driver loads (219), and other paths that a Security-only wipe leaves untouched.'
  - 'Security-1102: The Security-log clear itself. Mandatory-audit event — fires even when Security auditing is otherwise disabled, because the clear is higher-privilege than subcategory policy. Sibling structural guarantee to System-104.'
provenance:
  - ms-event-1102
  - mitre-t1070-001
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - ms-advanced-audit-policy
---

# Convergence — ANTI_FORENSIC_COORDINATED_WIPE

Tier-2 convergence yielding proposition `ANTI_FORENSIC_COORDINATED_WIPE`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: System-104.
