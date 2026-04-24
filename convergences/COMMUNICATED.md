---
name: COMMUNICATED
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: COMMUNICATED
  ceiling: C3
inputs:
  - COMMUNICATED
  - HAD_CONTENT
input-sources:
  - proposition: COMMUNICATED
    artifacts:
      - Security-5156
  - proposition: HAD_CONTENT
    artifacts:
      - Hiberfil
      - Pagefile
join-chain:
  - concept: IPAddress
    join-strength: moderate
    sources:
      - ms-event-5156
      - mitre-t1071
      - ms-hibernate-the-system-hiberfil-sys-f
      - ms-manage-virtual-memory-paging-file-m
    primary-source: ms-event-5156
    description: |
      Network-layer pivot threading the three communication witnesses.
      Security-5156 (WFP connection permitted) records SourceAddress +
      DestAddress + ports per accepted connection. Hiberfil preserves the
      TCP/UDP connection tables active at hibernate moment — queryable
      via Volatility netscan — yielding the same local/remote address
      pairs. Pagefile may carry URL fragments (string search) that embed
      hostnames resolvable to the same addresses. Moderate strength
      because IPs can be shared, rotated, or NATed; strengthens with
      timestamp agreement and process-context (5156 carries PID, Hiberfil
      EPROCESS walk recovers the same PID).
    artifacts-and-roles:
      - artifact: Security-5156
        role: remoteEndpoint
      - artifact: Hiberfil
        role: remoteEndpoint
      - artifact: Pagefile
        role: remoteEndpoint
exit-node:
  - Outlook-PST
  - Hiberfil
  - Pagefile
notes:
  - 'Hiberfil: Active connections in the TCP/UDP tables are direct evidence of network communication ongoing at hibernate moment.'
  - 'Pagefile: URL fragments in pagefile pages serve as COMMUNICATED evidence when other browser / network artifacts are unavailable.'
provenance:
  - ms-event-5156
  - mitre-t1071
  - ms-hibernate-the-system-hiberfil-sys-f
  - recon-2022-hibernation-recon-convert-hibe
  - foundation-2021-volatility-hibernate-address-s
  - for508-2023-hibernation-file-analysis-in-i
  - ms-manage-virtual-memory-paging-file-m
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - ms-advanced-audit-policy
---

# Convergence — COMMUNICATED

Tier-2 convergence yielding proposition `COMMUNICATED`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: Hiberfil, Pagefile, Security-5156.
