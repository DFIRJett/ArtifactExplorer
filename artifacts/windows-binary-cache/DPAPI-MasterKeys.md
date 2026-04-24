---
name: DPAPI-MasterKeys
title-description: "DPAPI master keys — per-user and machine-scope AES keys protecting DPAPI-encrypted blobs across Windows"
aliases:
- DPAPI master keys
- Protect directory
- user MasterKey
link: user
link-secondary: persistence
tags:
- credential-material
- attacker-target
- itm:ME
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: DPAPI-MasterKeys
platform:
  windows:
    min: '2000'
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  path-user: "%APPDATA%\\Microsoft\\Protect\\<USER-SID>\\<MASTER-KEY-GUID>"
  path-user-preferred: "%APPDATA%\\Microsoft\\Protect\\<USER-SID>\\Preferred"
  path-machine: "%WINDIR%\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\<MASTER-KEY-GUID>"
  path-machine-preferred: "%WINDIR%\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\Preferred"
  addressing: file-path
  note: "DPAPI (Data Protection API) master keys are the central key material that encrypt / decrypt every DPAPI blob on the system. Per-user master keys protect user-scope blobs (browser-saved passwords, Credential Manager Generic credentials, Windows Hello, Wi-Fi PSKs). Machine-scope master keys (SYSTEM profile) protect machine-scope blobs (IIS AppPool passwords, service account passwords, scheduled-task run-as credentials). The master-key file itself is encrypted with a key derived from the user's password (per-user) or the SYSTEM DPAPI_SYSTEM LSA secret (machine). Attackers with user password hash, with DPAPI_SYSTEM secret, or with domain backup key can decrypt master keys → decrypt all DPAPI blobs on the host. MIMIKATZ dpapi::masterkey is the canonical offensive tooling; same techniques apply defensively for legitimate DPAPI recovery."
fields:
- name: master-key-blob
  kind: content
  location: "Protect\\<SID>\\<GUID> file — encrypted master key structure"
  encoding: DPAPI master-key binary format (version + salt + encrypted-AES-key + HMAC)
  references-data:
  - concept: UserSID
    role: profileOwner
  note: "The encrypted master-key file. Structure: header + MASTERKEY_BLOB (PBKDF2-salt + encrypted AES-256 key) + LOCAL_BACKUP_KEY + DOMAIN_BACKUP_KEY (when domain-joined). Decrypted with user password hash OR domain DPAPI backup key. Resulting plaintext AES key is the master key used to decrypt all DPAPI blobs of that user."
- name: master-key-guid
  kind: identifier
  location: "Protect\\<SID>\\<GUID> filename"
  encoding: guid-string
  note: "Unique identifier per master key. Every DPAPI blob references the master-key GUID it was encrypted with — you match blob's referenced GUID to the master-key file to decrypt. Multiple master keys per user (rotated periodically — every 3 months by default); any surviving master key decrypts the blobs that reference it."
- name: preferred-pointer
  kind: content
  location: "Protect\\<SID>\\Preferred file"
  encoding: binary (GUID + FILETIME)
  note: "Points to the current / preferred master key for new DPAPI encryptions. Format: GUID (16 bytes) + next-rotation FILETIME (8 bytes). Used by DPAPI routines when selecting which master key to use for CryptProtectData. Forensically identifies 'which master key is active right now.'"
- name: domain-backup-blob
  kind: content
  location: "MASTERKEY_BLOB - DOMAIN_BACKUP_KEY subfield (when domain-joined)"
  encoding: RSA-encrypted recovery blob
  note: "Copy of the master-key encrypted with the domain DPAPI backup RSA public key. Enables domain-level recovery of user DPAPI data — domain admin who has the matching private key (held in Domain Controllers) can decrypt any user's master key without the user's password. Same capability an attacker with the domain DPAPI backup key has. MIMIKATZ lsadump::backupkeys extracts it from a DC."
- name: file-mtime
  kind: timestamp
  location: Protect\<SID>\<GUID> file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime = master-key write time. New master-key file mtimes track DPAPI key rotation events (every 3 months by default). Pair with password-change events (Security-4723 / 4724) which may rotate master keys."
- name: policy-history-count
  kind: counter
  location: "Protect\\<SID>\\ directory file count"
  note: "Total number of master-key files = count of historical rotations kept. By default Windows retains a history of master keys so old blobs remain decryptable. Low count on a long-lived profile = master-key pruning (rare, sometimes an anti-forensics signal)."
observations:
- proposition: HAD_CREDENTIAL
  ceiling: C4
  note: 'DPAPI master keys are one of the highest-leverage targets in
    Windows credential forensics. With master keys in hand (offline
    decrypted via user password / domain backup key / DPAPI_SYSTEM
    secret), an investigator reconstructs: browser-saved passwords
    (Chrome, Edge, Firefox for Credential Manager path), Wi-Fi
    PSKs, Credential Manager Generic credentials, Windows Hello PINs
    (indirect), Azure AD PRT cookies, EFS private keys, IIS AppPool
    passwords, scheduled-task stored credentials, service-account
    run-as passwords. Attackers do the same for lateral movement.
    Always acquire the entire Protect\\ directory for every user
    profile plus the machine-scope Protect at System32\\...\\S-1-5-18.'
  qualifier-map:
    object.credential: field:master-key-blob
    object.id: field:master-key-guid
    time.start: field:file-mtime
anti-forensic:
  write-privilege: user
  integrity-mechanism: HMAC-SHA1 over decrypted master-key structure; domain backup blob RSA-integrity
  known-cleaners:
  - tool: "delete %APPDATA%\\Microsoft\\Protect\\<SID>\\ contents"
    typically-removes: all per-user master keys — destroys ability to decrypt old DPAPI blobs for that user
  survival-signals:
  - Protect\<SID>\ directory present with recent master keys = full DPAPI decryption feasible with user's password (or domain key)
  - Protect\<SID>\ directory missing or empty = master keys deleted — DPAPI blobs for that user are unrecoverable from this host alone (domain DPAPI backup key may still work)
  - Machine-scope Protect at %WINDIR%\System32\Microsoft\Protect\S-1-5-18\User missing = machine DPAPI blobs unrecoverable without DPAPI_SYSTEM secret
provenance:
  - ms-data-protection-api-architecture-an
  - mitre-t1555-004
  - gentilkiwi-2020-mimikatz-vault-cred-modules-ex
  - specterops-2019-a-deep-dive-into-dpapi-compreh
exit-node:
  is-terminus: true
  primary-source: mitre-t1555
  attribution-sentence: 'Adversaries may search for common password storage locations to obtain user credentials (MITRE ATT&CK, n.d.).'
  terminates:
    - HAS_CREDENTIAL
    - HAD_CREDENTIAL
  sources:
    - ms-data-protection-api-architecture-an
    - specterops-2019-a-deep-dive-into-dpapi-compreh
    - mitre-t1555-004
  reasoning: >-
    DPAPI master keys are the encryption-key material that unwraps every
    DPAPI-wrapped secret in the user's profile — Credential-Manager-Vault
    entries, saved browser credentials (pre-Chromium move), Outlook-saved
    passwords, wireless profile PSKs, per-app tokens. Without a recovered
    master key the ciphertext stays opaque. This is the KEY-MATERIAL
    terminus — distinct from Credential-Manager-Vault (CREDENTIAL-STORAGE
    terminus). Their relationship is dependency-not-relay: the vault
    cannot be decrypted without the master key, but the master key is
    NOT a reference to the vault — it's independent material that happens
    to be required by multiple downstream consumers.
  implications: >-
    IR acquisition must pull the master keys alongside the vault. Master
    keys have a domain-backup-key fallback when domain-joined, making
    recovery possible via the domain controller even without the user
    password. Attacker-presence signals: master-key rotation outside
    normal patterns (Windows rotates every 90 days or on password
    change), or attacker-copied master keys appearing in suspicious
    locations on a different host.
  preconditions: >-
    Decryption chain: user password OR domain backup key unwraps the
    master key, which then unwraps downstream DPAPI-wrapped blobs.
    Post-compromise: recovered master key enables attacker offline-
    decryption of any DPAPI-wrapped blob they exfiltrated from the host.
  identifier-terminals-referenced:
    - UserSID
---

# DPAPI Master Keys

## Forensic value
DPAPI (Data Protection API) is Windows' built-in per-user / per-machine encryption service. Applications call `CryptProtectData` to encrypt a blob — the OS transparently picks a master key, derives a working key, encrypts, and stores the master-key GUID in the output blob header. `CryptUnprotectData` reverses. All this uses per-user master keys that live at:

`%APPDATA%\Microsoft\Protect\<USER-SID>\<MASTER-KEY-GUID>`

Machine-scope master keys (for IIS AppPool, services, scheduled tasks) live at:

`%WINDIR%\System32\Microsoft\Protect\S-1-5-18\User\<MASTER-KEY-GUID>`

## What DPAPI protects
- Chrome / Edge saved passwords (Login Data DB)
- Firefox saved passwords (via its own key store which wraps DPAPI)
- Windows Credential Manager — Generic credentials, Web credentials
- Wi-Fi PSKs (netsh wlan show profile)
- Windows Hello PIN / biometric keys (indirect)
- Azure AD Primary Refresh Token cookies
- EFS file-encryption private keys
- IIS AppPool passwords
- Scheduled Task "stored credentials"
- Service account run-as passwords set via Services MMC

Master key in hand → all of the above decrypt.

## Decryption paths
1. **User password** — PBKDF2(user-password-hash) derives key that decrypts master-key file. Requires the user's password or NTLM hash.
2. **Domain DPAPI backup key** — on domain-joined machines, each master-key file carries a DOMAIN_BACKUP_KEY sub-blob encrypted with the domain's backup RSA public key. Domain admin can decrypt any user's DPAPI data with the private backup key (mimikatz lsadump::backupkeys).
3. **DPAPI_SYSTEM LSA secret** — decrypts machine-scope master keys at S-1-5-18.

## Concept reference
- None direct — credential-material artifact.

## Triage
```cmd
:: Acquire all per-user Protect directories
for /d %u in (C:\Users\*) do xcopy /E /H /I "%u\AppData\Roaming\Microsoft\Protect" ".\evidence\dpapi\%~nxu\"

:: Machine-scope
xcopy /E /H /I "C:\Windows\System32\Microsoft\Protect" ".\evidence\dpapi\machine\"

:: Also acquire the SECURITY hive (DPAPI_SYSTEM LSA secret lives there)
:: And the SYSTEM hive (LSA key lives there) for full machine-DPAPI recovery
```

## Parsing / decryption
- `mimikatz` — `dpapi::masterkey /in:<file> /password:<pass>` or `/sid:<sid> /key:<domain-backup-key>`
- `impacket dpapi.py` — Python implementation
- `DPAPImk2john` (hashcat) — for cracking password-protected master keys offline

## Cross-reference
- **Credential Manager / Vault** — files under `%APPDATA%\Microsoft\Credentials\` and `\Vault\` are DPAPI-encrypted blobs; master key decrypts them
- **Chrome / Edge Login Data** — SQLite database holding DPAPI-encrypted password blobs
- **SAM hive** — source of NTLM hashes that can unlock user DPAPI master keys
- **LSA-Secrets** — source of DPAPI_SYSTEM for machine-scope master-key decryption

## Practice hint
On a lab VM: set a saved password in Chrome. Acquire the Login Data SQLite (Chrome's credentials DB) and the user's Protect directory. With mimikatz dpapi::chrome, decrypt the Login Data using the master keys + user password. This end-to-end chain is exactly what attackers use for browser-credential theft.
