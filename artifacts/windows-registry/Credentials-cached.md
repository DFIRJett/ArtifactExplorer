---
name: Credentials-cached
aliases:
- cached domain credentials
- MSCache
- Domain Cached Credentials
- DCC
- LSA Secrets
link: user
tags:
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SECURITY
platform:
  windows: { min: XP, max: "11" }
  windows-server: { min: "2000", max: "2022" }

location:
  hive: SECURITY
  paths:
    cached-domain: "Cache\\NL$<N>"
    lsa-secrets:   "Policy\\Secrets\\<secret-name>"
  addressing: hive+key-path

fields:
- name: cached-user-sid
  kind: identifier
  location: cache-entry binary structure — parsed SID
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: identitySubject
  note: SID of the domain user whose credentials were cached
- name: cached-email-identity
  kind: identifier
  location: cache entry — UPN or email-form logon name
  encoding: utf-16le
  references-data:
  - concept: EmailAddress
    role: cachedIdentity
  note: "UPN form (user@domain.com) for modern domain accounts — email-form identity"
- name: mscache-hash
  kind: hash
  location: cache-entry hash blob
  encoding: "MD4(NTLM(password) + username-lowercased)"
  note: MSCachev1 (pre-Vista) or MSCachev2 (Vista+); NOT reversible — offline cracking via hashcat mode 1100 (v1) or 2100 (v2)
- name: last-written
  kind: timestamp
  location: cache entry or Cache subkey LastWrite
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: approximates last-successful-domain-logon for this account
- name: secret-name
  kind: identifier
  location: "Policy\\Secrets\\<name> subkey"
  encoding: utf-16le
  note: e.g., "$MACHINE.ACC" (machine account), "DefaultPassword" (autologon), service-name for service credentials

observations:
- proposition: AUTHENTICATED
  ceiling: C3
  note: |
    Cached domain credentials prove the account successfully authenticated at
    some prior time — cache entry exists only after a successful logon.
    LSA Secrets additionally reveal stored service/autologon credentials
    which are themselves high-value.
  qualifier-map:
    principal: field:cached-user-sid
    method: cached-domain-credential
    time.start: field:last-written

anti-forensic:
  write-privilege: unknown
  integrity-mechanism: encryption against LSA SYSKEY
  known-cleaners:
  - tool: klist purge
    typically-removes: partial
    note: clears Kerberos tickets, not MSCache
  - tool: offline hive edit
    typically-removes: full
  survival-signals:
  - cached credentials exist for accounts not present in any ProfileList entry = historical domain-account logons now orphaned
  - service-credential entries in LSA Secrets with filenames pointing to attacker tooling = persistent credential theft
provenance:
  - ms-cached-credentials-cachedlogonscoun
  - gentilkiwi-2020-mimikatz-lsadump-cache-extract
  - mitre-t1003-005
exit-node:
  is-terminus: true
  primary-source: mitre-t1003-005
  attribution-sentence: 'Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable (MITRE ATT&CK, n.d.).'
  terminates:
    - HAS_CREDENTIAL
  sources:
    - ms-cached-credentials-cachedlogonscoun
    - gentilkiwi-2020-mimikatz-lsadump-cache-extract
    - mitre-t1003-005
  reasoning: >-
    Cached domain logon credentials (MSCASH hashes) in HKLM\SECURITY\Cache are the authoritative store for offline-domain authentication — the local system is the authority when the domain controller is unreachable. For HAS_CREDENTIAL, the cache IS the terminus at that moment; there's no upstream to check because the design intent of caching is to NOT need the DC.
  implications: >-
    MSCASH cracking attacks target these entries specifically because they represent crackable off-net authentication fodder. Forensically: presence of a cached entry proves the user logged on to this machine at least once in domain-context — valuable even when other logon artifacts (Security-4624) have been cleared or rolled out.
  preconditions: "SECURITY hive accessible; cachedlogonscount > 0; user previously logged on in domain context"
  identifier-terminals-referenced:
    - UserSID
---

# Cached Domain Credentials + LSA Secrets

## Forensic value
Dual artifact in the SECURITY hive:
1. **Cache\NL$<N>** — cached hashes of the last ~10 domain users who logged into this machine. Used for offline domain-logon when the DC is unreachable. Persists indefinitely.
2. **Policy\Secrets\<name>** — LSA Secrets: service-account credentials, autologon passwords, machine-account Kerberos key, saved RunAs credentials.

Both are encrypted against LSA's SYSKEY (derived from SYSTEM hive bootkey). Offline decryption via `secretsdump.py` or `mimikatz lsadump::secrets`.

## Concept references
- UserSID (cached-user-sid — identitySubject)
- EmailAddress (UPN form for modern cached accounts — cachedIdentity)

## Known quirks
- **SECURITY hive is hardest to acquire.** Live-system READ requires SYSTEM-token even for admins. Offline hive image is the practical path.
- **Encryption requires SYSTEM hive bootkey.** Always acquire SECURITY + SYSTEM together for decryption.
- **MSCachev1 vs v2** — pre-Vista uses v1 algorithm, Vista+ uses v2. Different cracking modes.
- **LSA Secrets can contain cleartext** for DefaultPassword (autologon), service accounts configured with "Log On As" — a password-recovery goldmine.
