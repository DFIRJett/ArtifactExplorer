---
name: AUTHENTICATED_AS
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: AUTHENTICATED_AS
  ceiling: C3
inputs:
  - AUTHENTICATED
input-sources:
  - proposition: AUTHENTICATED
    artifacts:
      - Security-4624
      - Security-4634
join-chain:
  - concept: LogonSessionId
    join-strength: strong
    sources:
      - ms-event-4624
      - uws-event-4624
      - ms-event-4634
      - uws-event-4634
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records a successful account logon and emits TargetLogonId — a hex LUID assigned by LSASS that uniquely identifies the session until the corresponding 4634 logoff bearing the same TargetLogonId closes it."
    description: |
      LogonSessionId (TargetLogonId LUID on 4624, matched against 4634's
      TargetLogonId at session close) is the session-unique binding that
      brackets the logon interval. This is THE pivot for establishing
      "this user was authenticated during window [T0, T1]." Without the
      LUID match, 4624 and 4634 are free-floating events — pair strength
      drops to time-proximity heuristic. With it, the session interval is
      a strong structural claim.
    artifacts-and-roles:
      - artifact: Security-4624
        role: sessionContext
      - artifact: Security-4634
        role: sessionContext
  - concept: UserSID
    join-strength: strong
    sources:
      - ms-event-4624
      - uws-event-4624
    primary-source: ms-event-4624
    attribution-sentence: "Event 4624 records the TargetUserSid alongside the TargetDomainName and TargetUserName fields — the SID is the persistent machine-unique identifier for the account, whereas the name is human-friendly but can be renamed, so SID is what threads the session event to ProfileList, SAM, and NTDS-dit records for the same account."
    description: |
      UserSID threads the session events to the identity-definer tier.
      Security-4624 carries TargetUserSid; ProfileList resolves SID →
      ProfileImagePath on the host; SAM (local) or NTDS-dit (domain) is
      the terminus authority for the SID's account-state (name, groups,
      password-hash material). The UserSID pivot turns a session-event
      claim into a person-attributable-account claim — but person
      attribution requires non-digital corroboration (Casey certainty
      gap — see USB convergence chain step 10).
    artifacts-and-roles:
      - artifact: Security-4624
        role: identitySubject
      - artifact: ProfileList
        role: identitySubject
exit-node:
  - NTDS-dit
  - SAM
  - ProfileList
notes:
  - 'Security-4624: combined with a matching 4634 logoff or session end, gives the full session window'
  - 'Security-4634: completes the session window when paired with 4624 via TargetLogonId match'
  - 'ProfileList: Security 4624 gives a UserSID; ProfileList resolves that SID to a profile path; combination lets per-user hive analysis proceed'
provenance:
  - ms-event-4624
  - uws-event-4624
  - ms-event-4634
  - uws-event-4634
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - ms-advanced-audit-policy
---

# Convergence — AUTHENTICATED_AS

Tier-2 convergence yielding proposition `AUTHENTICATED_AS`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: ProfileList, Security-4624, Security-4634.
