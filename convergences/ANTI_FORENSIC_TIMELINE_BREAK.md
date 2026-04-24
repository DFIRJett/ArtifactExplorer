---
name: ANTI_FORENSIC_TIMELINE_BREAK
summary: "Timeline-integrity-break proposition — evidence of a gap or disruption in the forensic timeline. Joins unclean-shutdown events (System-41), log-clear events (Security-1102, System-104), and timestamp-provenance state (TimeZoneInformation, ShutdownTime) via TimeWindow + UserSID pivots."
yields:
  mode: new-proposition
  proposition: ANTI_FORENSIC_TIMELINE_BREAK
  ceiling: C3
inputs:
  - UNCLEAN_SHUTDOWN
  - LOG_CLEARED
input-sources:
  - proposition: UNCLEAN_SHUTDOWN
    artifacts:
      - System-41
  - proposition: LOG_CLEARED
    artifacts:
      - Security-1102
      - System-104
join-chain:
  - concept: FILETIME100ns
    join-strength: strong
    sources:
      - ms-event-id-41-the-system-has-rebooted
      - mitre-t1070
    primary-source: ms-event-id-41-the-system-has-rebooted
    description: |
      Temporal-gap pivot. System-41 emits TimeCreated at the
      unclean-boot-resumption point — the delta between the last
      in-log pre-crash timestamp and the 41's TimeCreated defines
      a "lost-events" window. Security-1102 + System-104 emit
      TimeCreated at the moment of clearance — the log contents
      PRIOR to that stamp are gone. Joining on FILETIME lets an
      analyst quantify the "invisible-activity" window and
      correlate with shutdown-timing artifacts (ShutdownTime
      registry) for self-consistency checks. A System-41 whose
      TimeCreated predates ShutdownTime's recorded last-clean-
      shutdown is a flag — clean shutdown registered AFTER an
      unclean-shutdown event is an ordering anomaly.
    artifacts-and-roles:
      - artifact: System-41
        role: absoluteTimestamp
      - artifact: Security-1102
        role: absoluteTimestamp
      - artifact: System-104
        role: absoluteTimestamp
  - concept: UserSID
    join-strength: strong
    sources:
      - mitre-t1070
      - ms-event-1102
    primary-source: ms-event-1102
    description: |
      Actor-attribution pivot. Security-1102 emits SubjectUserSid
      of the account that cleared the Security log; System-104
      emits the same for the System log. System-41 has no user
      attribution (system-level boot event) but the timestamp
      allows session-binding to adjacent authenticated activity.
      Joining on UserSID for the log-clears binds a gap-creation
      event to the account responsible — attribution for
      anti-forensic activity. Correlation: same SubjectUserSid
      + System-104 + Security-1102 close in time = coordinated
      dual-channel wipe (see ANTI_FORENSIC_COORDINATED_WIPE).
    artifacts-and-roles:
      - artifact: Security-1102
        role: actingUser
      - artifact: System-104
        role: actingUser
exit-node:
  - Security-1102
  - System-104
notes:
  - 'System-41: "system rebooted without cleanly shutting down" — fires at next boot. Canonical unclean-shutdown signal. Gap between pre-crash last event and 41 = lost-events window.'
  - 'Security-1102: Security log cleared. Mandatory-audit event — fires regardless of subcategory policy. Exit-node: the clear IS the terminal anti-forensic fact.'
  - 'System-104: System log cleared. Sibling of 1102 but for the System channel. Paired with Security-1102 + same SubjectLogonId = coordinated dual-channel wipe.'
provenance:
  - ms-event-id-41-the-system-has-rebooted
  - ms-event-1102
  - mitre-t1070
  - mitre-t1070-001
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - ms-advanced-audit-policy
---

# Convergence — ANTI_FORENSIC_TIMELINE_BREAK

Tier-2 convergence yielding proposition `ANTI_FORENSIC_TIMELINE_BREAK`.

Binds three timeline-disruption artifacts: unclean-shutdown events (System-41) + log-clear events (Security-1102, System-104). FILETIME + UserSID pivots resolve the gap window and attribution. Complements ANTI_FORENSIC_COORDINATED_WIPE (which specifically captures the dual-channel-same-session pattern).

Participating artifacts: System-41, Security-1102, System-104.
