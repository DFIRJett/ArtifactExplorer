---
name: DELETED
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: DELETED
  ceiling: C3
inputs:
  - HAD_FILE
  - PERSISTENCE_REMOVED
input-sources:
  - proposition: HAD_FILE
    artifacts:
      - Recycle-Bin-INFO2
  - proposition: PERSISTENCE_REMOVED
    artifacts:
      - Security-4699
join-chain:
  - concept: Location
    join-strength: moderate
    sources:
      - ms-how-the-recycle-bin-stores-files-in
      - carvey-2010-rifiuti-rifiuti2-info2-parser
      - ms-event-4699
    primary-source: ms-how-the-recycle-bin-stores-files-in
    description: |
      Delete-target identity pivot. Recycle-Bin-INFO2 (per-user $Recycle.Bin)
      records the original full path and deletion time for a trashed file.
      Security-4699 (scheduled task deleted) carries TaskName, which maps
      back to the task-XML path under \Microsoft\Windows\... — a
      location-form identifier. These are different delete contexts
      (filesystem delete vs. scheduled-task delete) sharing only the
      abstract Location concept. The convergence is less about tight
      correlation and more about "evidence of removal across subsystems"
      — unified under DELETED as a composite claim. For filesystem-only
      deletions, TRANSACTED_FILE_OPERATION's MFTEntryReference pivot is
      the stronger path; DELETED's broader pivot intentionally covers
      non-filesystem objects (tasks, registry keys, services).
    artifacts-and-roles:
      - artifact: Recycle-Bin-INFO2
        role: deletedPath
      - artifact: Security-4699
        role: deletedObject
exit-node:
  - Recycle-Bin-INFO2
  - Security-4699
notes:
  - 'Security-4699: Proof the task existed AND was explicitly removed by the SubjectUserSid.'
provenance:
  - ms-how-the-recycle-bin-stores-files-in
  - carvey-2010-rifiuti-rifiuti2-info2-parser
  - ms-event-4699
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - ms-advanced-audit-policy
---

# Convergence — DELETED

Tier-2 convergence yielding proposition `DELETED`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: Recycle-Bin-INFO2, Security-4699.
