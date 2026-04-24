---
name: PROTECTS_VOLUME
summary: "Volume-protection configuration proposition — cryptographic or platform mechanisms in place to protect volume contents. Joins BitLocker configuration (BitLocker-FVE) with boot-integrity + platform-attestation state (BCD-Store) via VolumeGUID + RegistryKeyPath pivots."
yields:
  mode: new-proposition
  proposition: PROTECTS_VOLUME
  ceiling: C3
inputs:
  - CONFIGURED_ENCRYPTION
  - BOOT_INTEGRITY
input-sources:
  - proposition: CONFIGURED_ENCRYPTION
    artifacts:
      - BitLocker-FVE
  - proposition: BOOT_INTEGRITY
    artifacts:
      - BCD-Store
join-chain:
  - concept: VolumeGUID
    join-strength: strong
    sources:
      - ms-bitlocker-registry-configuration-re
      - ms-boot-configuration-data-bcd-archite
    primary-source: ms-bitlocker-registry-configuration-re
    description: |
      Volume-identity pivot. BitLocker-FVE stores per-volume
      key-protector GUIDs under FVE\<VolumeGUID>\. BCD-Store
      binds boot-loader entries to specific volume GUIDs via
      device objects. Joining on VolumeGUID resolves "is THIS
      specific volume BitLocker-protected AND boot-anchored into
      the chain the TPM attests?" — the full protection story:
      encryption state + boot-integrity binding + TPM-release
      policy. A BitLocker-protected volume with its boot entry
      removed from BCD = offline-attack attempt (attacker wants
      the encrypted data but can't boot the platform normally).
    artifacts-and-roles:
      - artifact: BitLocker-FVE
        role: accessedVolume
      - artifact: BCD-Store
        role: accessedVolume
  - concept: RegistryKeyPath
    join-strength: moderate
    sources:
      - ms-bitlocker-registry-configuration-re
      - ms-boot-configuration-data-bcd-archite
    primary-source: ms-bitlocker-registry-configuration-re
    description: |
      Configuration-anchor pivot. BitLocker-FVE config lives at
      HKLM\SOFTWARE\Policies\Microsoft\FVE\ (policy overrides) and
      HKLM\SYSTEM\CurrentControlSet\Services\FVE (runtime state);
      BCD-Store is HKLM\BCD00000000 (mounted) or \EFI\Microsoft\
      Boot\BCD (file). Joining on RegistryKeyPath bridges policy
      (GPO-pushed FVE settings) to runtime (current BitLocker
      state) to boot (secure-boot + testsigning flags). Tamper
      detection: policy says "require BitLocker" + runtime says
      "not enabled" = policy non-compliance or removed via local
      admin.
    artifacts-and-roles:
      - artifact: BitLocker-FVE
        role: subjectKey
      - artifact: BCD-Store
        role: subjectKey
exit-node:
  - BitLocker-FVE
  - BCD-Store
notes:
  - 'BitLocker-FVE: FVE = Full Volume Encryption registry + per-volume key-protector GUIDs. Each key-protector GUID maps to a specific unlock path for the associated volume (TPM, TPM+PIN, recovery-key, etc.). Exit-node for volume-encryption-state evidence.'
  - 'BCD-Store: Boot Configuration Data — boot-entry definitions + secure-boot state + test-signing flag. Pairs with BitLocker for the full trust-chain story (BitLocker requires boot integrity to release the VMK).'
provenance:
  - ms-bitlocker-registry-configuration-re
  - ms-ms-fve-recoveryinformation-ad-ds-at
  - ms-boot-configuration-data-bcd-archite
  - passware-2023-bitlocker-offline-analysis-rec
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - regripper-plugins
---

# Convergence — PROTECTS_VOLUME

Tier-2 convergence yielding proposition `PROTECTS_VOLUME`.

Binds two volume-protection artifacts: BitLocker-FVE (encryption state + key-protector GUIDs) and BCD-Store (boot-integrity + secure-boot flags). VolumeGUID + RegistryKeyPath pivots resolve per-volume encryption state and its trust-chain binding.

Participating artifacts: BitLocker-FVE, BCD-Store.
