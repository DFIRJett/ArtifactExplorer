---
name: CONTROLLED_ACCESS
summary: "Access-control-state + access-audit proposition — who was allowed to access what at a given moment. Joins the ACL-state authority (Secure-SDS) with the per-access audit events (Security-4663 open, Security-4656 handle-requested) via RegistryKeyPath (object-path) + UserSID + FILETIME pivots."
yields:
  mode: new-proposition
  proposition: CONTROLLED_ACCESS
  ceiling: C3
inputs:
  - HAD_FILE
  - ACCESSED
input-sources:
  - proposition: HAD_FILE
    artifacts:
      - Secure-SDS
  - proposition: ACCESSED
    artifacts:
      - Security-4663
      - Security-4656
join-chain:
  - concept: RegistryKeyPath
    join-strength: strong
    sources:
      - ms-ntfs-on-disk-format-secure-system-f
      - ms-event-4663
    primary-source: ms-ntfs-on-disk-format-secure-system-f
    description: |
      Object-path pivot (the corpus uses RegistryKeyPath for
      arbitrary stringy object paths). Secure-SDS keys entries
      by SDS-offset; each $MFT record references an offset via
      $STANDARD_INFORMATION. Security-4663 + 4656 emit ObjectName
      — the path of the object whose handle was opened. Joining
      on ObjectName / path binds the ACL-state record (Secure-SDS)
      to the per-access record (4663/4656): did the ACL at the
      time of access authorize the operation? ACL-diff between
      Secure-SDS snapshots + 4663 AccessMask + 4656 AccessList is
      the substrate for proving "this access was authorized by
      the ACL in place at time T" — critical for insider-threat
      cases where the defense argues "I had permission."
    artifacts-and-roles:
      - artifact: Secure-SDS
        role: subjectKey
      - artifact: Security-4663
        role: subjectKey
      - artifact: Security-4656
        role: subjectKey
  - concept: UserSID
    join-strength: strong
    sources:
      - ms-ntfs-on-disk-format-secure-system-f
      - ms-event-4663
    primary-source: ms-ntfs-on-disk-format-secure-system-f
    description: |
      Actor-attribution pivot. Secure-SDS DACL entries bind
      access rights to SIDs (allowed / denied). Security-4663
      emits SubjectUserSid (who opened the handle); Security-4656
      emits the same. Joining on UserSID answers "was THIS SID
      permitted at the time of the event, per the DACL in place?"
      — the claim needed for ACL-authorized-access attribution.
      ACL-bypass indicators: SIDs in 4663 that DACL should have
      denied = privilege escalation or ACL-timing manipulation.
    artifacts-and-roles:
      - artifact: Secure-SDS
        role: identitySubject
      - artifact: Security-4663
        role: actingUser
      - artifact: Security-4656
        role: actingUser
  - concept: FILETIME100ns
    join-strength: moderate
    sources:
      - ms-ntfs-on-disk-format-secure-system-f
    primary-source: ms-ntfs-on-disk-format-secure-system-f
    description: |
      Temporal-bracketing pivot. Secure-SDS entries carry the
      timestamps of the $MFT records that reference them (ACL
      effective-at time). Security-4663 + 4656 emit TimeCreated
      for the per-access event. Joining on FILETIME lets an
      analyst verify that the ACL at the time of access matches
      the access outcome — essential when ACLs have been modified
      mid-incident and a 4663 access must be judged against the
      EFFECTIVE ACL at that moment.
    artifacts-and-roles:
      - artifact: Secure-SDS
        role: absoluteTimestamp
      - artifact: Security-4663
        role: absoluteTimestamp
      - artifact: Security-4656
        role: absoluteTimestamp
exit-node:
  - Secure-SDS
notes:
  - 'Secure-SDS: NTFS $Secure:$SDS stream — the canonical ACL state database. Historical DACL reconstruction from this file documents who had access to deleted/modified-ACL files. Exit-node: no upstream — the SDS IS the ACL authority.'
  - 'Security-4663: per-access audit (File System / Registry / Kernel Object / SAM / Removable Storage subcategories of Audit Object Access). Requires SACL on the target. Authoritative per-operation record.'
  - 'Security-4656: handle-requested audit. Opens the object-access lifecycle with the FULL access-rights set; pair with 4663 operation records for complete access reconstruction.'
provenance:
  - ms-ntfs-on-disk-format-secure-system-f
  - ms-event-4663
  - ms-event-4656
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — CONTROLLED_ACCESS

Tier-2 convergence yielding proposition `CONTROLLED_ACCESS`.

Binds three ACL / access-audit artifacts: the ACL-state authority (Secure-SDS) and the per-access audit events (Security-4663, Security-4656). Path + UserSID + FILETIME pivots resolve who was allowed to do what to which object at which moment.

Participating artifacts: Secure-SDS, Security-4663, Security-4656.
