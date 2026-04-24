---
name: INSTALLED
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: INSTALLED
  ceiling: C3
inputs:
  - CONFIGURED_PATCH_STATE
  - INSTALLED_FROM_SOURCE
input-sources:
  - proposition: CONFIGURED_PATCH_STATE
    artifacts:
      - UpdateStore-DB
  - proposition: INSTALLED_FROM_SOURCE
    artifacts:
      - Installer-Products-SourceList
join-chain:
  - concept: Location
    join-strength: weak
    sources:
      - ms-update-session-orchestrator-uso-arc
      - ms-windows-installer-products-registry
    primary-source: ms-update-session-orchestrator-uso-arc
    description: |
      Installed-product-identity pivot. UpdateStore-DB (WindowsUpdate
      ESE) tracks OS updates by KB-identifier (KBxxxxxxx) and per-update
      install-state; Installer-Products-SourceList tracks per-MSI
      installed products by ProductCode (GUID) with source media path.
      These don't share a natural identifier form — UpdateStore's KB
      identifiers are disjoint from Installer's ProductCodes (different
      installation subsystems: WU-MSU/.cab vs. Windows Installer MSI).
      Weak pivot on the abstract "installed-product location" — practical
      correlation is analyst-driven (e.g. "did the Office 2019 ProductCode
      correspond to the same version KB reported installed?"). Marginal
      convergence; retained because the composite INSTALLED claim with
      both sources strengthens the "this product exists on this host"
      assertion when each source independently corroborates.
    artifacts-and-roles:
      - artifact: UpdateStore-DB
        role: installedProduct
      - artifact: Installer-Products-SourceList
        role: installedProduct
exit-node:
  - UpdateStore-DB
  - Installer-Products-SourceList
notes:
  - 'UpdateStore-DB: Installed-state updates constitute direct evidence of the KB being applied.'
  - 'Installer-Products-SourceList: Corroborates installation evidence with source provenance.'
provenance:
  - ms-update-session-orchestrator-uso-arc
  - ms-windows-installer-products-registry
  - project-2023-windowsbitsqueuemanagerdatabas
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - regripper-plugins
---

# Convergence — INSTALLED

Tier-2 convergence yielding proposition `INSTALLED`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: Installer-Products-SourceList, UpdateStore-DB.
