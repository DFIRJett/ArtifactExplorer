---
name: HAD_FILE
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: HAD_FILE
  ceiling: C3
inputs:
  - DELETED
  - HAD_PRIOR_STATE
  - OBSERVED_FILE
input-sources:
  - proposition: DELETED
    artifacts:
      - OneDrive-SafeDelete
  - proposition: HAD_PRIOR_STATE
    artifacts:
      - VSS-Shadow-Copies
  - proposition: OBSERVED_FILE
    artifacts:
      - Search-Gather-Logs
join-chain:
  - concept: Location
    join-strength: weak
    sources:
      - labs-2023-onedrive-safedelete-db-a-sleep
      - ms-volume-shadow-copy-service-vss-arch
      - ms-windows-search-architecture-gather
    primary-source: ms-volume-shadow-copy-service-vss-arch
    description: |
      File path is the only shared anchor across these three witnesses, and
      it's a weak pivot — each artifact records the file at different
      normalization (OneDrive-SafeDelete stores the logical-view path with
      OneDrive-namespace prefix; VSS-Shadow-Copies preserves the NTFS path
      at snapshot time; Search-Gather-Logs stores the crawl-view path). Path
      match across witnesses requires normalization (case-fold, drive-letter
      substitution, Shadow Copy-prefix strip). Despite the weakness, path
      agreement is the strongest evidence available here since these
      artifacts don't share a stronger identifier like MFTEntryReference.
      VSS-Shadow-Copies is the exit-node because it preserves the actual
      file content (not just the claim it existed) and can be mounted for
      direct recovery.
    artifacts-and-roles:
      - artifact: OneDrive-SafeDelete
        role: deletedPath
      - artifact: VSS-Shadow-Copies
        role: preservedPath
      - artifact: Search-Gather-Logs
        role: indexedPath
exit-node: VSS-Shadow-Copies
notes:
  - 'VSS-Shadow-Copies: Every file that existed on the volume at snapshot time is recoverable from the snapshot.'
  - 'OneDrive-SafeDelete: A deletion record is also proof of prior existence — the user HAD the file at some point before deletion-time.'
  - 'Search-Gather-Logs: Indexed path = the file existed at crawl time, even if deleted since.'
provenance:
  - labs-2023-onedrive-safedelete-db-a-sleep
  - khatri-2022-onedriveexplorer-parser-for-on
  - matrix-nd-dt061-detect-text-authored-in
  - ms-volume-shadow-copy-service-vss-arch
  - mitre-t1490
  - carvey-2009-working-with-volume-shadow-copies
  - libyal-libvshadow-libvshadow-offline-vss-metadat
  - ms-windows-search-architecture-gather
  - moore-2020-powercfg-energy-reports-as-for
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — HAD_FILE

Tier-2 convergence yielding proposition `HAD_FILE`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: OneDrive-SafeDelete, Search-Gather-Logs, VSS-Shadow-Copies.
