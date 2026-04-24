---
name: LSA-Cached-Logons
title-description: "LSA cached domain logons (MSCACHEv2 / DCC2) — hashed copies of the last 10 domain credentials per host"
aliases:
- MSCACHE
- MSCACHEv2
- DCC2
- Cached Domain Credentials
- LSA Cache
link: user
link-secondary: persistence
tags:
- credential-material
- attacker-target
- offline-crackable
- itm:ME
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SECURITY
platform:
  windows:
    min: '2000'
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SECURITY
  path: "Cache"
  addressing: hive+key-path
  note: "The SECURITY hive's Cache subkey holds LSA's cache of previously-successful domain logons so the user can log on when the Domain Controller is unreachable. Each cached entry is encrypted with the machine's LSA secret + machine SID and stores a DCC2 (MSCACHEv2) hash of the user's password plus user / group info. Default cache size is 10 entries; the machine-wide setting is at HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount (0-50). MSCACHE entries are NOT equivalent to NT hashes — they cannot be used for pass-the-hash, but they CAN be cracked offline to recover the plaintext password. PBKDF2-like iteration with SHA-1 (10240 iterations in DCC2) makes cracking slow but feasible given weak passwords + sufficient compute / GPU."
fields:
- name: cached-entry
  kind: content
  location: "Cache\\NL$<N> value"
  type: REG_BINARY
  encoding: "NL$KM encrypted blob (DCC2 hash + username + domain + SID + group list, AES-encrypted with machine key)"
  note: "Each NL$1 through NL$<MaxCachedLogons> entry = one cached logon. Blob contents: user name, domain, SID, group memberships, and DCC2 hash of password. Decrypted offline with the machine's NL$KM key (extracted from same hive) → reveals username + domain + DCC2 hash. DCC2 is then fed to hashcat / John for offline cracking."
- name: cache-key-material
  kind: content
  location: "HKLM\\SECURITY\\Policy\\Secrets\\NL$KM\\CurrVal"
  type: REG_BINARY
  references-data:
  - concept: RegistryKeyPath
    role: subjectKey
  note: "The LSA secret named NL$KM holds the AES key used to encrypt Cache entries. This IS the decryption key — mimikatz lsadump::cache extracts it alongside the cache entries, then decrypts. Backup copy at SECURITY\\Policy\\Secrets\\NL$KM\\OldVal when the key has been rotated."
- name: cache-entry-count
  kind: counter
  location: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount"
  type: REG_SZ (holds integer string)
  note: "Configured maximum cached logons. Default '10'. Microsoft security baseline for high-security environments recommends '1' or '2' to reduce offline-crack exposure. Value '0' disables caching entirely — a user cannot log on while the DC is unreachable. Enterprise policy value '0' on a domain-joined workstation = explicit anti-MSCACHE posture."
- name: dcc2-hash-in-blob
  kind: hash
  location: "inside decrypted NL$<N> blob"
  encoding: DCC2 hash (MD4(MD4(password-UTF-16LE) + username-UTF-16LE) iterated PBKDF2-HMAC-SHA1 10240×)
  note: "The per-user DCC2 hash. Hashcat mode 2100. Slower to crack than NT hash (mode 1000) by ~10000x due to PBKDF2 iteration — but weak passwords (dictionary, common patterns, leaked lists) still fall quickly. Recovery yields the PLAINTEXT domain password — direct credential exposure."
- name: username
  kind: label
  location: "inside decrypted NL$<N> blob"
  encoding: utf-16le
  references-data:
  - concept: UserSID
    role: identitySubject
  note: "Domain\\username of the cached user. Each cache entry identifies a distinct user that logged on — so cache enumeration reveals everyone who's logged into this host within the cache window (typically last 10 users)."
- name: last-logon-time
  kind: timestamp
  location: "inside decrypted NL$<N> blob"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "Last successful cached logon for this user on this host. Gives per-user logon timeline independent of EVTX retention."
- name: user-sid
  kind: identifier
  location: "inside decrypted NL$<N> blob"
  encoding: SID binary
  references-data:
  - concept: UserSID
    role: identitySubject
  note: "Full domain SID of the cached user. Cross-reference with Security-4624 logon events + SAM/AD for consistency check."
observations:
- proposition: HAD_CREDENTIAL
  ceiling: C4
  note: 'LSA cached logons are one of the highest-value targets in
    credential forensics for offline-attack scenarios. Every
    domain-joined Windows host caches up to 10 (default) of the most
    recent domain user logons as DCC2 hashes encrypted with the
    machine secret. Attacker extraction workflow: acquire SECURITY
    and SYSTEM hives → decrypt NL$KM with machine SID key → decrypt
    each NL$<N> cache entry → extract DCC2 hashes → crack offline.
    Success rate against typical enterprise passwords is high. Each
    recovered password is full domain-scope credential material for
    the corresponding user. For incident response: if host was
    imaged, assume cached logons are compromised and force domain
    password rotation for every user whose DCC2 could be on the
    host (per enumeration).'
  qualifier-map:
    actor.user: field:username
    object.credential: field:dcc2-hash-in-blob
    time.start: field:last-logon-time
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: AES-encryption with machine key; no per-entry signing
  known-cleaners:
  - tool: "Set CachedLogonsCount=0 + reboot"
    typically-removes: future cache entries (existing entries persist until they fall out of the rolling cache or until explicitly cleared)
  - tool: KLIST PURGE + reboot (indirect)
    typically-removes: some user-session Kerberos cache but NOT MSCACHE
  - tool: "manually delete NL$<N> entries from SECURITY\\Cache"
    typically-removes: specific cached entries
  survival-signals:
  - SECURITY\Cache populated = cached credentials present; offline-crackable given SYSTEM hive + SECURITY hive
  - CachedLogonsCount=0 on workstation = enterprise anti-MSCACHE posture (rare; correlates with security-focused deployment)
  - MSCACHE count exceeding CachedLogonsCount value = cache corruption / manual tampering
provenance:
  - ms-cached-credentials-cachedlogonscoun
  - mitre-t1003-005
  - gentilkiwi-2020-mimikatz-lsadump-cache-extract
  - fortra-2022-secretsdump-py-cache-entry-ext
exit-node:
  is-terminus: true
  primary-source: mitre-t1003-005
  attribution-sentence: 'Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable (MITRE ATT&CK, n.d.).'
  terminates:
    - HAS_CREDENTIAL
    - HAD_CREDENTIAL
  sources:
    - ms-cached-credentials-cachedlogonscoun
    - mitre-t1003-005
    - gentilkiwi-2020-mimikatz-lsadump-cache-extract
  reasoning: >-
    LSA Cached Logons store the last N (default 10 on workstation, 25 on
    server) domain-user logons as MSCASH v2 hashes under
    HKLM\SECURITY\Cache. These hashes are the LOCAL authority for
    offline-domain authentication — when the domain controller is
    unreachable, Windows validates logons against this cache. The cached
    hash IS the credential for offline purposes; there is no upstream to
    relay to (the domain controller's authoritative hash lives in
    NTDS-dit, which is a separate terminus for domain-connected auth).
    For HAS_CREDENTIAL / HAD_CREDENTIAL against an offline-available
    target, this is the definitive recovery source.
  implications: >-
    DCC2-hash cracking (hashcat mode 2100) is offline-feasible but slow
    — cache-recovered hashes are actionable for attacker lateral movement
    even when the host is disconnected from the domain. Attackers
    exfiltrating SECURITY hive contents gain a slow-burn credential-
    recovery window. Survival is strong — default cache size keeps hashes
    for dozens of logons before eviction; clearing requires registry
    writes an attacker would typically not perform.
  preconditions: >-
    SYSTEM token required to read HKLM\SECURITY. Offline extraction
    (mimikatz lsadump::cache or Impacket secretsdump.py) requires the
    SYSKEY chain to decrypt cached entries.
  identifier-terminals-referenced:
    - UserSID
    - DomainName
---

# LSA Cached Domain Logons (MSCACHE / DCC2)

## Forensic value
Every domain-joined Windows host caches up to 10 (default) of the most recent domain user logons so users can authenticate when the DC is unreachable. Each cached entry holds:

- Username + domain + SID + group memberships
- **DCC2 hash** (Domain Cached Credentials v2) of the password — PBKDF2-SHA1 with 10240 iterations
- Last-logon timestamp

Location: `HKLM\SECURITY\Cache\NL$1` through `NL$<CachedLogonsCount>`.

Each entry is AES-encrypted with the machine's LSA secret `NL$KM` (stored in the same SECURITY hive at `Policy\Secrets\NL$KM`). Offline decryption yields the DCC2 hash for cracking.

## Cracking path
```
1. Acquire SECURITY hive + SYSTEM hive (for bootkey)
2. Extract NL$KM LSA secret from SECURITY (uses machine SID from SYSTEM)
3. Decrypt NL$1..NL$10 with NL$KM
4. Read DCC2 hash per entry
5. Feed to hashcat mode 2100 for offline crack
```

Weak passwords (dictionary, leaked, short, common patterns) crack in hours to days. Strong passwords (long random) remain safe.

## Why this is distinct from other credential artifacts
- **NT hash** (SAM hive) — local account passwords; pass-the-hash feasible
- **DPAPI master keys** — per-user blob-decryption keys; decrypt browsers/Credential-Manager
- **Kerberos ticket cache** (LSASS memory) — active session TGTs/service tickets
- **MSCACHE** — ONLY forensic path to last 10 DOMAIN users' passwords from a domain-joined host

If a host is imaged cold (no memory dump), MSCACHE is one of the few cred-recovery avenues for domain accounts.

## Concept references
- UserSID (each cached entry)

## Triage
Live (requires SYSTEM or SeDebugPrivilege):
```
mimikatz
> privilege::debug
> token::elevate
> lsadump::cache
```

Offline from acquired hives:
```
mimikatz
> lsadump::cache /system:SYSTEM /security:SECURITY

# OR
python secretsdump.py -system SYSTEM -security SECURITY LOCAL
```

## Crack workflow
```
hashcat -m 2100 dcc2-hashes.txt /path/to/wordlist.txt -r /path/to/rules
```

## Cross-reference
- **SAM hive** — local account NT hashes
- **DPAPI-MasterKeys** — per-user DPAPI master key material
- **SYSTEM hive** — required bootkey to decrypt SECURITY hive
- **Security-4624** — logon events (enumerate users who have logged on → list of accounts whose cache entries exist)
- **CachedLogonsCount** registry value — governs cache depth

## Practice hint
On a domain-joined lab VM: log on as a few different domain users. Acquire the SECURITY and SYSTEM hives (`reg save HKLM\SECURITY sec.hiv` + `reg save HKLM\SYSTEM sys.hiv`). Run mimikatz `lsadump::cache /system:sys.hiv /security:sec.hiv` — output lists each cached user with their DCC2 hash. Feed one hash to hashcat with a small wordlist — observe the crack process. This end-to-end chain is exactly what attackers execute post-image-acquisition.
