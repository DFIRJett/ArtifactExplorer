---
name: RAN_PROCESS
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: RAN_PROCESS
  ceiling: C3
inputs:
  - HAD_CONTENT
  - HAD_PRIOR_STATE
  - OBSERVED_SYSTEM_STATE
input-sources:
  - proposition: HAD_CONTENT
    artifacts:
      - Hiberfil
      - Pagefile
  - proposition: HAD_PRIOR_STATE
    artifacts:
      - VSS-Shadow-Copies
  - proposition: OBSERVED_SYSTEM_STATE
    artifacts:
      - Power-Efficiency-Diagnostics
join-chain:
  - concept: ExecutablePath
    join-strength: moderate
    sources:
      - ms-hibernate-the-system-hiberfil-sys-f
      - recon-2022-hibernation-recon-convert-hibe
      - ms-manage-virtual-memory-paging-file-m
      - moore-2020-powercfg-energy-reports-as-for
      - libyal-libvshadow-libvshadow-offline-vss-metadat
    primary-source: ms-hibernate-the-system-hiberfil-sys-f
    description: |
      Shared process-identity anchor across memory-state and snapshot
      witnesses. Hiberfil's EPROCESS linked-list entries carry ImageFileName
      (short) and the executable's FullPath via VAD traversal; Pagefile PE
      carvings recover the binary's image-header name; Power-Efficiency-
      Diagnostics lists image paths for running processes at report-
      generation time; VSS-Shadow-Copies preserves prior Prefetch /
      Amcache / UsnJrnl entries keyed on the same path. Path match is
      moderate-strength (evadable via rundll32 / legitimate-binary-abuse /
      image-name-spoofing) but no stronger pivot exists across these
      disjoint subsystems. Temporal + path-agreement across 2+ witnesses
      produces C3; a single witness is C2.
    artifacts-and-roles:
      - artifact: Hiberfil
        role: ranProcess
      - artifact: Pagefile
        role: ranProcess
      - artifact: Power-Efficiency-Diagnostics
        role: ranProcess
      - artifact: VSS-Shadow-Copies
        role: ranProcess
exit-node:
  - Hiberfil
  - Pagefile
  - VSS-Shadow-Copies
  - Swapfile
  - CrashDump-MEMDMP
notes:
  - 'Hiberfil: Processes enumerated from the EPROCESS list are direct evidence of execution at hibernate moment.'
  - 'Pagefile: PE-signature carved payload is direct evidence the process ran in this system''s memory.'
  - 'VSS-Shadow-Copies: Prior Prefetch / Amcache / UsnJrnl entries surviving in snapshots corroborate execution evidence attacker-cleaned from the live state.'
  - 'Power-Efficiency-Diagnostics: Processes listed in the report were confirmed running at report-generation time.'
provenance:
  - ms-hibernate-the-system-hiberfil-sys-f
  - recon-2022-hibernation-recon-convert-hibe
  - foundation-2021-volatility-hibernate-address-s
  - for508-2023-hibernation-file-analysis-in-i
  - ms-manage-virtual-memory-paging-file-m
  - ms-volume-shadow-copy-service-vss-arch
  - libyal-libvshadow-libvshadow-offline-vss-metadat
  - ms-powercfg-command-reference-energy-s
  - moore-2020-powercfg-energy-reports-as-for
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — RAN_PROCESS

Tier-2 convergence yielding proposition `RAN_PROCESS`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: Hiberfil, Pagefile, Power-Efficiency-Diagnostics, VSS-Shadow-Copies.
