---
name: HAD_CREDENTIAL
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: HAD_CREDENTIAL
  ceiling: C3
inputs:
  - CONFIGURED_BY_POLICY
  - HAD_CIPHERTEXT
  - HAD_HASH
input-sources:
  - proposition: CONFIGURED_BY_POLICY
    artifacts:
      - GPP-SYSVOL-XML
  - proposition: HAD_CIPHERTEXT
    artifacts:
      - LSA-Secrets
      - Credentials-cached
  - proposition: HAD_HASH
    artifacts:
      - LSA-Cached-Logons
      - SAM
join-chain:
  - concept: UserSID
    join-strength: strong
    sources:
      - mitre-t1003-005
      - mitre-t1552-006
      - gentilkiwi-2020-mimikatz-lsadump-cache-extract
      - fortra-2022-secretsdump-py-cache-entry-ext
    description: |
      Credential-owner pivot. All five sources bind recovered credential
      material to a UserSID: GPP-SYSVOL-XML decrypts cpassword for a
      named local-account SID; LSA-Secrets per-secret subkey names
      encode service SIDs or user contexts; Credentials-cached stores
      per-user vault contents indexed by SID; LSA-Cached-Logons holds
      DCC2 hashes per cached-logon SID; SAM holds local-account hashes
      keyed on RID (which maps deterministically to machine-SID+RID SID
      form). Joining on UserSID establishes THIS user's credentials
      were recovered — promotes HAD_CREDENTIAL from "some credential
      material was extracted" to "this specific user's credentials
      were extracted."
    artifacts-and-roles:
      - artifact: GPP-SYSVOL-XML
        role: targetUser
      - artifact: LSA-Secrets
        role: targetUser
      - artifact: Credentials-cached
        role: targetUser
      - artifact: LSA-Cached-Logons
        role: targetUser
      - artifact: SAM
        role: targetUser
exit-node:
  - LSA-Secrets
  - LSA-Cached-Logons
  - SAM
  - Credentials-cached
notes:
  - 'GPP-SYSVOL-XML: Decrypted cpassword IS the local account password — direct credential recovery.'
  - 'LSA-Secrets: Machine-account password + service-account credentials. Extractable offline via mimikatz lsadump::secrets or Impacket secretsdump.'
  - 'LSA-Cached-Logons: Domain-logon DCC2 hashes — offline-crackable (hashcat mode 2100). Exit-node when NTDS.dit is unavailable.'
  - 'SAM: Local-account NTLM hashes — RID-indexed. Exit-node for local-credential recovery.'
  - 'Credentials-cached: Credential Manager vault — per-user DPAPI-protected secrets (RDP creds, saved browser passwords, Azure tokens).'
provenance:
  - ms-kb2962486-ms14-025-vulnerability-in
  - mitre-t1552-006
  - schroeder-2016-get-gpppassword-powershell-one
  - robbins-2022-group-policy-preferences-and-t
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — HAD_CREDENTIAL

Tier-2 convergence yielding proposition `HAD_CREDENTIAL`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: GPP-SYSVOL-XML.
