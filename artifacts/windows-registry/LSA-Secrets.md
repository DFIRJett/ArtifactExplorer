---
name: LSA-Secrets
aliases:
- LSA cached secrets
- Policy\Secrets
- machine account password cache
link: security
tags:
- system-wide
- tamper-hard
- credential-material
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SECURITY
platform:
  windows:
    min: XP
    max: '11'
location:
  hive: SECURITY
  path: Policy\Secrets
  sub-paths: Policy\Secrets\<secret-name>\{CurrVal,OldVal,SecDesc}
  addressing: hive+key-path
fields:
- name: secret-name
  kind: identifier
  location: subkey name under Policy\Secrets
  note: well-known names include $MACHINE.ACC, DefaultPassword, NL$KM, L$_SQSA_*, _SC_<service>; arbitrary names may exist per-application
  references-data:
  - concept: ServiceName
    role: persistedService
- name: CurrVal
  kind: ciphertext
  location: subkey → CurrVal value
  type: REG_BINARY
  encoding: DPAPI-wrapped with LSA secret key
  note: current encrypted secret value; requires SYSTEM token + DPAPI decryption (Impacket secretsdump, mimikatz lsadump::secrets)
- name: OldVal
  kind: ciphertext
  location: subkey → OldVal value
  type: REG_BINARY
  note: previous secret value; retained for password-rotation fallback — often contains last-rotated machine-account password
- name: key-last-write
  kind: timestamp
  location: per-secret subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: on secret rotation
observations:
- proposition: CREDENTIAL_CACHED
  ceiling: C3
  note: Machine-account password, service-account passwords (_SC_ prefix), DPAPI master seeds live here. Primary target for credential-theft on compromised host.
  qualifier-map:
    object.secret.name: subkey name
    time.rotated: field:key-last-write
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - tool: lsadump::secrets (mimikatz)
    typically-removes: none — reads, does not delete
  detection-signals:
  - access attempts land in Security-4670 (permissions changed on object) if the SACL is set
  - subkey enumeration via reg.exe fails without SYSTEM — attackers typically use psexec -s or SeDebugPrivilege escalation first
provenance:
  - gentilkiwi-2020-mimikatz-lsadump-cache-extract
  - mitre-t1003-004
exit-node:
  is-terminus: true
  primary-source: mitre-t1003-004
  attribution-sentence: 'Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts (MITRE ATT&CK, n.d.).'
  terminates:
    - HAS_CREDENTIAL
    - HAD_CREDENTIAL
  sources:
    - gentilkiwi-2020-mimikatz-lsadump-cache-extract
    - mitre-t1003-004
  reasoning: >-
    LSA Secrets are the on-disk encrypted-blob store for machine-scope credentials: service-account passwords set via sc.exe, DPAPI system keys, cached machine-account password, SQL-Server / IIS / Scheduled-Task credentials. For HAS_CREDENTIAL / HAD_CREDENTIAL at the machine-credential tier, LSA Secrets IS the store; no upstream recovery possible without SYSTEM-token + boot-key + SYSKEY chain.
  implications: >-
    Post-compromise credential-recovery forensics often targets LSA Secrets — presence of specific Secret values in attacker-offered exploit outputs is direct evidence of _LSADUMP. Enables attribution of lateral-movement via service-account abuse. Survival depends on attacker not running 'reg delete HKLM\SECURITY\Policy\Secrets' — which some cleanup kits do.
  preconditions: "SYSTEM hive + SECURITY hive both accessible offline; boot-key derivable from SYSTEM"
  identifier-terminals-referenced:
    - UserSID
---

# LSA-Secrets

## Forensic value
The Local Security Authority's per-machine secret store. Each named secret is DPAPI-wrapped with the LSA's master key, itself unwrapped with the boot key (hidden in SYSTEM hive class names). From a running LSASS, the secrets are decryptable; from a cold hive acquisition, decryption requires both SECURITY + SYSTEM hives.

### Well-known secret names
- `$MACHINE.ACC` — machine account NT hash (primary lateral-movement credential)
- `DefaultPassword` — plaintext autologon password (when AutoLogon is configured)
- `NL$KM` — DPAPI master key for LSA secrets chain
- `_SC_<service>` — service-account passwords for any service configured with an explicit credential
- `L$_SQSA_<SID>` — domain cached credentials (separate from MSCACHE/MSCACHEV2 in Cache subkey)

## Forensic value of OldVal
Secret rotation retains the previous value in `OldVal` for one rotation cycle. For stolen-credential investigations, `OldVal` often yields the credential that was active at the time of compromise — the `CurrVal` might be the post-incident rotated one.

## Detection
- Any process that enumerates `HKLM:\SECURITY\Policy\Secrets` is suspicious. Requires SYSTEM.
- Security event 4798 (A user's local group membership was enumerated) + 4799 may fire during credential enumeration.
- Sysmon-10 (ProcessAccess) against lsass.exe with access mask containing 0x1010 or 0x1410 indicates LSASS-read attempts for in-memory equivalent.

## Cross-references
- **SAM** — local account hashes (different store, different extraction path)
- **AutoLogon** — if DefaultPassword is set here, the registry's DefaultPassword value is plaintext and more accessible

## Practice hint
In a training lab, `secretsdump.py -system SYSTEM -security SECURITY -sam SAM LOCAL` from Impacket extracts cached LSA secrets, SAM hashes, and cached domain credentials offline from an acquired hive set.
