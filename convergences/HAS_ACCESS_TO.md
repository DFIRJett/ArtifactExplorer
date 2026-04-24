---
name: HAS_ACCESS_TO
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: HAS_ACCESS_TO
  ceiling: C3
inputs:
  - HAD_CREDENTIAL
  - PRIVILEGE_GRANTED
input-sources:
  - proposition: HAD_CREDENTIAL
    artifacts:
      - Credential-Manager-Vault
      - DPAPI-MasterKeys
      - LSA-Cached-Logons
      - Windows-Hello-NGC
  - proposition: PRIVILEGE_GRANTED
    artifacts:
      - Security-4728
      - Security-4732
join-chain:
  - concept: UserSID
    join-strength: strong
    sources:
      - mitre-t1555-004
      - gentilkiwi-2020-mimikatz-vault-cred-modules-ex
      - ms-event-4728
      - ms-event-4732
    primary-source: ms-event-4728
    description: |
      User identity threads credential subsystems to privilege-grant events.
      Each HAD_CREDENTIAL input artifact (Credential-Manager-Vault, DPAPI-
      MasterKeys, LSA-Cached-Logons, Windows-Hello-NGC) binds authentication
      material to a specific UserSID as the credential owner. Each
      PRIVILEGE_GRANTED input event (Security-4728 global-group add,
      Security-4732 local-group add) names the TargetSid that received new
      access rights. Joining both sides on UserSID establishes that THIS
      user simultaneously holds valid credentials AND the group-derived
      access privileges — the composite claim HAS_ACCESS_TO. Without this
      pivot, credential recovery and privilege-grant facts would be
      separate and un-attributable at the per-user layer.
    artifacts-and-roles:
      - artifact: Credential-Manager-Vault
        role: identitySubject
      - artifact: DPAPI-MasterKeys
        role: identitySubject
      - artifact: LSA-Cached-Logons
        role: identitySubject
      - artifact: Windows-Hello-NGC
        role: identitySubject
      - artifact: Security-4728
        role: identitySubject
      - artifact: Security-4732
        role: identitySubject
exit-node: UserSID
notes:
  - 'Credential-Manager-Vault: Each decrypted credential entry is direct proof of authenticatable access to the TargetName resource.'
  - 'DPAPI-MasterKeys: Decrypted master keys enable decryption of all DPAPI-protected secrets — authorizing the holder to access every resource those secrets authenticate to.'
  - 'Windows-Hello-NGC: Recovered NGC PIN enables impersonation of the user''s Windows Hello authentication against AD / Azure AD.'
  - 'Security-4728: Global group membership grants access scoped to the group''s resource / attribute privileges.'
  - 'Security-4732: Group membership grants access scoped to the group''s privilege set.'
  - 'LSA-Cached-Logons: Recovered plaintext domain password = valid domain authentication across the entire environment (not just this host).'
provenance:
  - ms-credential-manager-credential-provi
  - mitre-t1555-004
  - gentilkiwi-2020-mimikatz-vault-cred-modules-ex
  - specterops-2019-sharpdpapi-c-implementation-of
  - ms-data-protection-api-architecture-an
  - specterops-2019-a-deep-dive-into-dpapi-compreh
  - ms-cached-credentials-cachedlogonscoun
  - mitre-t1003-005
  - gentilkiwi-2020-mimikatz-lsadump-cache-extract
  - fortra-2022-secretsdump-py-cache-entry-ext
  - ms-windows-hello-for-business-architec
  - mollema-2022-roadtools-hello2hashcat-offlin
  - robbins-2022-group-policy-preferences-and-t
  - ms-event-4728
  - mitre-t1098-007
  - ms-event-4732
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - ms-advanced-audit-policy
  - regripper-plugins
---

# Convergence — HAS_ACCESS_TO

Tier-2 convergence yielding proposition `HAS_ACCESS_TO`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: Credential-Manager-Vault, DPAPI-MasterKeys, LSA-Cached-Logons, Security-4728, Security-4732, Windows-Hello-NGC.
