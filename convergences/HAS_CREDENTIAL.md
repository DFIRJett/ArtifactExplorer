---
name: HAS_CREDENTIAL
summary: "Credential-material-present proposition — host currently holds recoverable credentials (cached, stored, or ticket-resident). Joins SAM, LSA-Secrets, LSA-Cached-Logons, Credentials-cached, Kerberos-Tickets-Cache, Credential-Manager-Vault, DPAPI-MasterKeys, Windows-Hello-NGC, Security-4782 via UserSID pivot. Present-state parallel to HAD_CREDENTIAL (past-tense recovery)."
yields:
  mode: new-proposition
  proposition: HAS_CREDENTIAL
  ceiling: C3
inputs:
  - HAD_CREDENTIAL
  - CREDENTIAL_CACHED
  - AUTHENTICATED
  - ACCOUNT_CREDENTIAL_MIGRATED
input-sources:
  - proposition: HAD_CREDENTIAL
    artifacts:
      - Credential-Manager-Vault
      - DPAPI-MasterKeys
      - LSA-Cached-Logons
      - Windows-Hello-NGC
  - proposition: CREDENTIAL_CACHED
    artifacts:
      - LSA-Secrets
  - proposition: AUTHENTICATED
    artifacts:
      - Credentials-cached
      - Kerberos-Tickets-Cache
  - proposition: ACCOUNT_CREDENTIAL_MIGRATED
    artifacts:
      - Security-4782
join-chain:
  - concept: UserSID
    join-strength: strong
    sources:
      - mitre-t1003-005
    description: |
      Credential-owner pivot. All credential-material stores are
      per-user or per-machine-identity: Credential-Manager-Vault
      is per-user DPAPI-wrapped saved credentials; DPAPI-
      MasterKeys is the user's DPAPI master-key chain;
      LSA-Cached-Logons stores MSCASH hashes per cached-logon-SID;
      LSA-Secrets holds machine-account + service-account
      credentials keyed by service SID; Credentials-cached
      mirrors the user's vault contents indexed by SID;
      Kerberos-Tickets-Cache entries are per-session-LUID
      (resolvable to owning SID); Windows-Hello-NGC is
      per-user NGC container; Security-4782 emits the TargetSid
      whose hash was migrated. Joining on UserSID binds
      "some credential is present on this host" into "THIS
      specific account's credentials are present on this host" —
      the attribution-grade claim for post-compromise credential-
      recovery scenarios.
    artifacts-and-roles:
      - artifact: Credential-Manager-Vault
        role: targetUser
      - artifact: DPAPI-MasterKeys
        role: targetUser
      - artifact: LSA-Cached-Logons
        role: targetUser
      - artifact: LSA-Secrets
        role: targetUser
      - artifact: Credentials-cached
        role: targetUser
      - artifact: Kerberos-Tickets-Cache
        role: targetUser
      - artifact: Windows-Hello-NGC
        role: targetUser
      - artifact: Security-4782
        role: targetUser
  - concept: MachineNetBIOS
    join-strength: moderate
    sources:
      - mitre-t1003-005
    description: |
      Host-scope pivot. Credential material is local to a specific
      host's disk + memory — the same SID on different hosts can
      have different credential-present states (one host has
      Kerberos-Tickets-Cache for the SID because the user logged
      in there; another host may only have SAM / NTDS-dit binding).
      Joining on MachineNetBIOS distinguishes per-host credential
      inventories in multi-host compromise scenarios and supports
      the "which hosts currently hold credentials for account X?"
      query an IR team needs before locking accounts.
    artifacts-and-roles:
      - artifact: Credential-Manager-Vault
        role: originMachine
      - artifact: DPAPI-MasterKeys
        role: originMachine
      - artifact: LSA-Cached-Logons
        role: originMachine
      - artifact: LSA-Secrets
        role: originMachine
      - artifact: Credentials-cached
        role: originMachine
      - artifact: Kerberos-Tickets-Cache
        role: originMachine
      - artifact: Windows-Hello-NGC
        role: originMachine
exit-node:
  - LSA-Secrets
  - LSA-Cached-Logons
  - Credentials-cached
  - Credential-Manager-Vault
  - DPAPI-MasterKeys
  - Kerberos-Tickets-Cache
  - Windows-Hello-NGC
notes:
  - 'Credential-Manager-Vault: user-mode saved credentials — RDP, Outlook-saved, custom apps. Exit-node for HAS/HAD_CREDENTIAL at the user-mode tier.'
  - 'DPAPI-MasterKeys: key material that unwraps every DPAPI-wrapped user secret. Dependency for vault decryption, not relay to it.'
  - 'LSA-Cached-Logons: MSCASH2 cached domain-logon hashes. Exit-node for offline-domain credential recovery.'
  - 'LSA-Secrets: machine-account + service-account encrypted secrets. Exit-node for system-tier credential recovery.'
  - 'Credentials-cached: Credential Manager vault contents — runtime reflection of Credential-Manager-Vault file-store.'
  - 'Kerberos-Tickets-Cache: ticket material cryptographically bound to auth events. Exit-node for ticket-replay attribution.'
  - 'Windows-Hello-NGC: biometric-authenticator-protected key material. Exit-node for Hello-session credential substrate.'
  - 'Security-4782: password-hash-migrated event (ADMT). Event record, not storage — participates as ancillary evidence of credential migration moments.'
provenance:
  - mitre-t1003-004
  - mitre-t1003-005
  - mitre-t1555-004
  - gentilkiwi-2020-mimikatz-vault-cred-modules-ex
  - ms-event-4782
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — HAS_CREDENTIAL

Tier-2 convergence yielding proposition `HAS_CREDENTIAL`.

Binds eight credential-material artifacts covering user-mode saved credentials (Credential-Manager-Vault), DPAPI key chain (DPAPI-MasterKeys), domain-logon cache (LSA-Cached-Logons), system-tier encrypted secrets (LSA-Secrets), runtime vault reflection (Credentials-cached), Kerberos ticket residue (Kerberos-Tickets-Cache), biometric-authenticator material (Windows-Hello-NGC), and credential-migration events (Security-4782). UserSID + MachineNetBIOS pivots resolve whose credentials are present on which host.

Participating artifacts: Credential-Manager-Vault, DPAPI-MasterKeys, LSA-Cached-Logons, LSA-Secrets, Credentials-cached, Kerberos-Tickets-Cache, Windows-Hello-NGC, Security-4782.
