---
name: EXECUTED
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: EXECUTED
  ceiling: C3
inputs:
  - RAN_PROCESS
input-sources:
  - proposition: RAN_PROCESS
    artifacts:
      - PCA-Win11
      - RecentFileCache-BCF
      - WER-Report
join-chain:
  - concept: ExecutablePath
    join-strength: moderate
    sources:
      - rathbun-2023-program-compatibility-assistan
      - synacktiv-2023-pca-parsing-and-cross-comparis
      - carvey-2013-recentfilecache-bcf-parser-and
      - ms-windows-error-reporting-architectur
    primary-source: ms-windows-error-reporting-architectur
    description: |
      Executable path is the shared object across all three inputs — each
      artifact independently records WHICH program ran. PCA-Win11 logs the
      launch event with the binary's full path; RecentFileCache-BCF caches
      the path that triggered the launch (SuperFetch perspective);
      WER-Report contains the crashing process's image path in its error
      metadata. Joining on ExecutablePath confirms the SAME program produced
      all three observations — the composite RAN_PROCESS claim. Path is
      moderate-strength (not globally unique — can be evaded by relocation
      or impersonation) but complements each witness's timing precision.
    artifacts-and-roles:
      - artifact: PCA-Win11
        role: ranProcess
      - artifact: RecentFileCache-BCF
        role: ranProcess
      - artifact: WER-Report
        role: ranProcess
exit-node: ExecutablePath
notes:
  - 'PCA-Win11: Direct evidence — PCA only logs launches that actually occurred.'
  - 'WER-Report: A crash report is proof the process ran (it couldn''t have crashed otherwise).'
provenance:
  - rathbun-2023-program-compatibility-assistan
  - synacktiv-2023-pca-parsing-and-cross-comparis
  - carvey-2013-recentfilecache-bcf-parser-and
  - project-2023-windowsbitsqueuemanagerdatabas
  - ms-windows-error-reporting-architectur
  - mitre-t1497
  - 13cubed-2020-print-job-forensics-recovering
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — EXECUTED

Tier-2 convergence yielding proposition `EXECUTED`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: PCA-Win11, RecentFileCache-BCF, WER-Report.
