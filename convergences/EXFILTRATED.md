---
name: EXFILTRATED
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: EXFILTRATED
  ceiling: C3
inputs:
  - COMMUNICATED
input-sources:
  - proposition: COMMUNICATED
    artifacts:
      - AnyDesk-Logs
      - BITS-QueueManager
join-chain:
  - concept: URL
    join-strength: moderate
    sources:
      - ms-background-intelligent-transfer-ser
      - project-2023-windowsbitsqueuemanagerdatabas
      - anydesk-2023-anydesk-log-file-locations-and
      - aa24-131a-2024-anydesk-in-ransomware-incident
    primary-source: ms-background-intelligent-transfer-ser
    description: |
      Destination pivot across both exfil-tool witnesses. BITS-QueueManager
      qmgr.db stores the RemoteURL field per upload job (direction=Upload
      indicates data egress vs download). AnyDesk-Logs ad.trace files
      emit file-transfer log lines containing the remote endpoint
      (AnyDesk-ID or host). Joining on URL / endpoint-identifier
      establishes that both channels referenced the SAME destination —
      stronger evidence than either alone because the two subsystems
      are operationally independent (Windows BITS vs AnyDesk's proprietary
      transport). Moderate because the two log shapes use different
      endpoint forms (URL vs AnyDesk-ID) that require normalization.
    artifacts-and-roles:
      - artifact: BITS-QueueManager
        role: destinationEndpoint
      - artifact: AnyDesk-Logs
        role: destinationEndpoint
  - concept: Location
    join-strength: moderate
    sources:
      - anssi-fr-2018-bits-parser-jobs-jdb-qmgr-dat
      - anydesk-2023-anydesk-log-file-locations-and
      - research-2023-blackbasta-lockbit-use-of-anyd
    description: |
      File-source pivot. Both tools log the local path being transferred
      — BITS qmgr.db LocalFilename / LocalPath, AnyDesk log-line filename.
      Agreement on source-path means "the same local file was uploaded
      via BOTH channels" — double-exfil pattern (attacker using two tools
      as redundancy or for different file-size tiers). Disagreement on
      source but agreement on URL means two different local files went
      to the same destination — staged-upload pattern.
    artifacts-and-roles:
      - artifact: BITS-QueueManager
        role: exfilSource
      - artifact: AnyDesk-Logs
        role: exfilSource
exit-node:
  - URL
  - Location
notes:
  - 'BITS-QueueManager: A BITS upload job (direction=Upload) with a non-Microsoft destination URL = data exit.'
  - 'AnyDesk-Logs: File-transfer log lines are direct evidence of data movement through AnyDesk''s file-transfer tool.'
provenance:
  - anydesk-2023-anydesk-log-file-locations-and
  - aa24-131a-2024-anydesk-in-ransomware-incident
  - research-2023-blackbasta-lockbit-use-of-anyd
  - ms-background-intelligent-transfer-ser
  - mitre-t1197
  - project-2023-windowsbitsqueuemanagerdatabas
  - anssi-fr-2018-bits-parser-jobs-jdb-qmgr-dat
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — EXFILTRATED

Tier-2 convergence yielding proposition `EXFILTRATED`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: AnyDesk-Logs, BITS-QueueManager.
