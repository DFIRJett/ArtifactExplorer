---
name: Windows-Hello-NGC
title-description: "Windows Hello / Next-Generation Credentials (NGC) — per-user PIN / biometric container backing TPM-bound keys"
aliases:
- Windows Hello
- NGC containers
- Next Generation Credentials
- Hello PIN / biometric
link: user
link-secondary: persistence
tags:
- credential-material
- biometric
- tpm-bound
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: Windows-Hello-NGC
platform:
  windows:
    min: '10'
    max: '11'
  windows-server:
    min: '2016'
    max: '2022'
location:
  path-ngc-container: "%WINDIR%\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc\\<container-GUID>\\*"
  path-ngc-user-proto: "%WINDIR%\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\NgcPro\\"
  path-crypto-systemkeys: "%ALLUSERSPROFILE%\\Microsoft\\Crypto\\SystemKeys\\ (master encryption keys)"
  path-crypto-protect: "%ALLUSERSPROFILE%\\Microsoft\\Crypto\\Protect\\S-1-5-18\\ (machine-scope DPAPI)"
  path-crypto-rsa-machinekeys: "%ALLUSERSPROFILE%\\Microsoft\\Crypto\\RSA\\MachineKeys\\"
  path-biometric-bio: "%WINDIR%\\System32\\WinBioDatabase\\"
  registry: "HKLM\\SOFTWARE\\Microsoft\\Policies\\PassportForWork\\"
  addressing: file-path
  note: "Windows Hello implements PIN and biometric user authentication via Next-Generation Credentials (NGC). Each enrolled user/PIN/biometric pair creates a per-user NGC container — a directory tree under ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc\\<GUID> holding: the user's private key (encrypted by TPM if available; DPAPI-wrapped otherwise), the PIN protector, biometric match data (when Windows Hello for Business / Face / Fingerprint is enrolled), and linking metadata. Companion biometric data lives under System32\\WinBioDatabase. The NGC container is the on-disk form of what normally exists only in the user's head (PIN) or body (biometric). For DFIR: cracking the PIN unlocks the TPM-bound key that signs Windows Hello authentications — enables impersonation of the user against AD / Azure AD without their password. Research tools (SharpHello, Hello2Hashcat) target these artifacts."
fields:
- name: ngc-container-directory
  kind: content
  location: "Ngc\\<container-GUID>\\ directory tree"
  encoding: multiple files (see below)
  references-data:
  - concept: UserSID
    role: profileOwner
  note: "Root directory for one user's Windows Hello enrollment. Contents: 1.dat / 2.dat / 3.dat (encrypted blobs for PIN protector, TPM-wrapped key, metadata), Policies subkey (container policies), linking / signing metadata. The entire directory must be acquired for offline analysis."
- name: ngc-protector-blob
  kind: content
  location: "Ngc\\<container-GUID>\\<N>.dat files"
  encoding: Windows-Hello proprietary (DPAPI + TPM where available)
  note: "Per-container protector blobs. Binary files holding the PIN protector (PBKDF2-derived from user's PIN) and the TPM-bound or DPAPI-bound wrapped private key. For DFIR: offline PIN cracking requires these files + the system encryption keys + the user's SYSTEM hive (for DPAPI context). Successful crack recovers the PIN → can decrypt the private key."
- name: biometric-database
  kind: content
  location: "%WINDIR%\\System32\\WinBioDatabase\\<sensor-GUID>.*"
  encoding: WinBio proprietary biometric template format
  note: "Biometric match templates (fingerprint / face / iris). Per-user enrollment data. Not used for direct authentication against AD — the biometric unlocks the local NGC container, which then authenticates. Privacy-sensitive: biometric templates in some formats can be reverse-engineered to approximate original biometric data."
- name: system-protect-directory
  kind: content
  location: "%ALLUSERSPROFILE%\\Microsoft\\Crypto\\Protect\\S-1-5-18\\"
  encoding: DPAPI master key blobs (machine scope)
  note: "Machine-scope DPAPI master keys used by the NGC subsystem to wrap per-user container data. Required for offline NGC decryption alongside the user's own DPAPI keys."
- name: passport-for-work-policy
  kind: flags
  location: "HKLM\\SOFTWARE\\Microsoft\\Policies\\PassportForWork\\* / HKCU equivalent"
  type: REG_DWORD / REG_SZ
  note: "Windows Hello for Business policy — required PIN complexity, biometric allowed, TPM required. Policy configures the security level of enrollments. Low-complexity PIN policy = weaker offline-crack difficulty."
- name: container-mtime
  kind: timestamp
  location: Ngc\<GUID> directory + subfile mtimes
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtimes on NGC files. Oldest directory-creation mtime = when enrollment was performed. Most-recent file mtime = when the container was last used (auth event)."
observations:
- proposition: HAD_CREDENTIAL
  ceiling: C3
  note: 'Windows Hello NGC containers hold the on-disk form of TPM-
    bound or DPAPI-bound per-user authentication keys. Offline PIN
    cracking (SharpHello, Hello2Hashcat, impacket-ngc modules)
    recovers the PIN, which unlocks the protector, which releases
    the private key used to sign Hello authentications. Successful
    crack against a domain-joined / Azure-AD-joined host = ability
    to impersonate the user''s Hello authentication without their
    password. For DFIR: acquisition of the NGC directory tree +
    System DPAPI keys + Crypto\\SystemKeys is required for offline
    analysis. Live systems with SYSTEM context can use mimikatz
    ngc::pin / cloudap::sections for direct enumeration.'
  qualifier-map:
    object.credential: field:ngc-protector-blob
    time.start: field:container-mtime
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: TPM-bound keys when TPM is available (extraction from TPM requires physical attack)
  known-cleaners:
  - tool: "Remove-LocalUser / RemoveNgc"
    typically-removes: user's NGC container (re-enrollment required next login)
  - tool: certutil -deletestore MY
    typically-removes: related cert store entries; may affect NGC
  survival-signals:
  - Ngc\<container-GUID> directory for a specific user present = Windows Hello enrolled for that user
  - PIN complexity policy (PassportForWork registry) allows short numeric PINs = weak offline-crack difficulty
  - TPM state disabled (TPM registry + TPM MMC) while Hello is enrolled = DPAPI-bound fallback (easier offline crack; no TPM extraction required)
provenance:
  - ms-windows-hello-for-business-architec
  - mollema-2022-roadtools-hello2hashcat-offlin
exit-node:
  is-terminus: true
  primary-source: mitre-t1555
  attribution-sentence: 'Adversaries may search for common password storage locations to obtain user credentials (MITRE ATT&CK, n.d.).'
  terminates:
    - HAS_CREDENTIAL
    - AUTHENTICATED_AS
  sources:
    - ms-windows-hello-for-business-architec
    - mollema-2022-roadtools-hello2hashcat-offlin
  reasoning: >-
    Windows Hello for Business / NGC stores biometric-authenticator
    protected key material in the NGC container
    (%PROGRAMDATA%\Microsoft\Crypto\Keys and per-user NGC data under
    %LOCALAPPDATA%). The NGC key IS the credential substrate for Hello-
    authenticated sessions — biometric or PIN unlocks it, and the
    resulting key authorizes downstream auth operations. Chain terminates
    here: no further upstream within the Hello-unlocked session. Binds
    directly to identity (per-user NGC) and serves as the root-of-trust
    for the user's Hello-mediated auth chain.
  implications: >-
    Credential-theft scenarios involving Hello-enrolled accounts must
    acquire the NGC container alongside DPAPI keys. Offline brute-force
    of the PIN-protected key material is tractable (hello2hashcat)
    given the container. Presence of unexpected NGC-unlock events +
    missing biometric hardware = pin-authentication fallback or attacker
    replay of captured container. TPM-bound keys resist extraction but
    software-only NGC does not.
  preconditions: >-
    NGC container + user PIN (or biometric) needed for online use;
    container + PIN-hash crack for offline credential recovery. TPM
    binding adds per-device seal that prevents cross-host replay.
  identifier-terminals-referenced:
    - UserSID
---

# Windows Hello / NGC Credential Containers

## Forensic value
Windows Hello implements PIN / biometric authentication via Next-Generation Credentials (NGC). Each user's enrollment creates a container under:

`%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\<container-GUID>\`

The container holds:
- PIN protector (PBKDF2-derived from user's PIN)
- Private key (TPM-wrapped when TPM is present; DPAPI-wrapped fallback)
- Linking metadata (which user, which Azure AD / AD account)

Companion artifacts:
- `%WINDIR%\System32\WinBioDatabase\` — biometric templates (fingerprint, face)
- `%ALLUSERSPROFILE%\Microsoft\Crypto\SystemKeys\` — machine-level crypto keys
- `%ALLUSERSPROFILE%\Microsoft\Crypto\Protect\S-1-5-18\` — machine DPAPI master keys

## What offline PIN crack recovers
1. Acquire NGC directory + Crypto\SystemKeys + Crypto\Protect\S-1-5-18 + user's SYSTEM hive
2. Feed to Hello2Hashcat / ROADtools / SharpHello
3. Brute-force PIN (typically 4-6 numeric digits — often < 10^6 search space)
4. Recovered PIN unlocks the protector → private key → can sign Hello authentications as the user
5. Against AD / Azure AD the signature authenticates without the user's password

## Concept reference
- None direct — credential-material artifact.

## Triage
```cmd
dir /a %WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\
dir /a %WINDIR%\System32\WinBioDatabase\
reg query "HKLM\SOFTWARE\Microsoft\Policies\PassportForWork" /s
```

## Acquisition (offline-friendly)
Acquire the entire tree:
- `%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\` (all containers)
- `%ALLUSERSPROFILE%\Microsoft\Crypto\SystemKeys\`
- `%ALLUSERSPROFILE%\Microsoft\Crypto\Protect\S-1-5-18\`
- User's SYSTEM hive and SECURITY hive for DPAPI context

## Cross-reference
- **DPAPI-MasterKeys** — required for DPAPI-bound Hello variants
- **LSA-Cached-Logons** — sibling credential-forensic target
- **TPM registry** (HKLM\SYSTEM\CurrentControlSet\Services\TPM) — TPM state affects Hello binding mode
- **Microsoft-Windows-User Device Registration/Admin** EVTX — enrollment events

## Practice hint
On a Windows 10/11 VM with TPM: enroll Windows Hello PIN for a local / MSA account. Acquire the Ngc\<GUID> directory for that user (elevated). Note the 1.dat / 2.dat / 3.dat files. Research-lab: feed to Hello2Hashcat in a controlled environment with a weak test PIN to observe crack success. DO NOT run offline-crack tooling against production user enrollments without authorization.
