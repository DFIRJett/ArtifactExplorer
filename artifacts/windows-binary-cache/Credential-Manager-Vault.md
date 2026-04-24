---
name: Credential-Manager-Vault
title-description: "Windows Credential Manager + Vault — DPAPI-encrypted credential blobs (Web creds, Generic creds, WNA SSO)"
aliases:
- Credential Manager
- Windows Vault
- Credentials folder
- Web Credentials
link: user
link-secondary: persistence
tags:
- credential-store
- attacker-target
- itm:ME
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: Credential-Manager-Vault
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  path-credentials-user: "%APPDATA%\\Microsoft\\Credentials\\<hash>"
  path-credentials-system: "%WINDIR%\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials\\<hash>"
  path-credentials-low: "%APPDATA%\\Microsoft\\Credentials\\<hash> (Medium IL)"
  path-vaults-user: "%LOCALAPPDATA%\\Microsoft\\Vault\\<vault-guid>\\"
  path-vaults-system: "%WINDIR%\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault\\<vault-guid>\\"
  addressing: file-path
  note: "Two related subsystems. CREDENTIALS folder holds DPAPI-encrypted Generic / Domain / Certificate credentials (cmdkey, saved RDP mstsc passwords, mapped-drive credentials, VPN saved creds). VAULT directories hold WNA Web Credentials (Internet Explorer / Edge Legacy / Windows account SSO) with per-vault schema files (*.vsch), per-credential data files (*.vcrd), and a master policy file (*.vpol). Both are user-scope by default; machine-scope variants exist under systemprofile. All blobs are DPAPI-encrypted — decryption requires the matching DPAPI master key."
fields:
- name: credential-blob
  kind: content
  location: "Credentials\\<hash> file"
  encoding: DPAPI-wrapped credential (CREDENTIAL structure + target name + username + encrypted password)
  note: "Generic / Domain / Certificate credential saved via CredWrite API or cmdkey.exe. Includes target name (hostname / URL / service identifier), username, and DPAPI-encrypted password. Common entries: mapped network drive credentials, saved RDP passwords (mstsc /savecred), VPN client saved creds, Outlook Exchange saved password, Git credential helper."
- name: vault-policy
  kind: content
  location: "Vault\\<vault-guid>\\Policy.vpol"
  encoding: DPAPI-wrapped vault master key (AES-GCM key)
  note: "Per-vault master encryption key, itself DPAPI-encrypted. Decrypting Policy.vpol with user DPAPI master key yields the vault's internal AES key, which then decrypts per-credential .vcrd files. Two-layer encryption."
- name: vault-credential
  kind: content
  location: "Vault\\<vault-guid>\\*.vcrd"
  encoding: AES-GCM encrypted credential record (key from Policy.vpol)
  note: "Individual credential record — Web credential (hostname + username + password) or Windows account credential (user SID + token). Schema defined by the sibling .vsch file. When decrypted, reveals: HTTP Basic auth credentials saved in Edge Legacy / IE, Windows account passwords saved for SSO across Windows Store apps, and Azure AD cloud-credential tokens."
- name: vault-schema
  kind: identifier
  location: "Vault\\<vault-guid>\\*.vsch"
  encoding: binary schema descriptor
  note: "Per-vault schema file. Describes the layout of .vcrd files in that vault. Different vault GUIDs correspond to different credential classes (Web Credentials vault, Windows Credentials vault). Well-known vault GUIDs documented by Microsoft + community research."
- name: target-name
  kind: label
  location: "Credentials\\<hash> — TargetName field inside decrypted CREDENTIAL"
  encoding: utf-16le
  references-data:
  - concept: URL
    role: embeddedReferenceUrl
  note: "Target of the credential (what it authenticates to). For RDP mstsc /savecred: 'Domain:target=<hostname>'. For Outlook: 'LegacyGeneric:target=<outlook-service-id>'. For Git: 'git:https://<host>'. Reveals which services the user / attacker authenticated to. Attacker-added credentials (for persistence / lateral movement staging) reveal attacker infrastructure."
- name: credential-mtime
  kind: timestamp
  location: each Credentials / Vault file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "File creation / modification time = credential save time. Pair with incident timeline — a credential saved during intrusion window is likely attacker-added."
- name: credential-ownership
  kind: identifier
  location: "Vault\\<vault-guid>\\Policy.vpol — owner SID"
  note: "SID of the user that wrote the vault. Usually matches the enclosing user profile path; discrepancy indicates credentials written by a different context (SYSTEM, different user, attacker)."
observations:
- proposition: HAD_CREDENTIAL
  ceiling: C4
  note: 'Credential Manager and the Windows Vault subsystem hold the
    on-disk form of every credential the user has opted to save for
    automatic reuse. Saved RDP passwords (mstsc /savecred), mapped-
    drive credentials, Outlook Exchange password, Git credential
    helper, VPN client saved creds, Edge Legacy / IE Web Auth
    credentials. Decryption requires the matching user DPAPI master
    key — so this artifact is strictly pair-with DPAPI-MasterKeys.
    For lateral-movement investigations, saved RDP credentials on a
    user''s Credential Manager reveal every host the user has chosen
    to persist credentials for — and for attacker work, the attacker
    may write credentials here for future-use lateral pivots.'
  qualifier-map:
    object.credential: field:credential-blob
    peer.name: field:target-name
    time.start: field:credential-mtime
anti-forensic:
  write-privilege: user
  integrity-mechanism: DPAPI HMAC + AES-GCM authentication tag per vault record
  known-cleaners:
  - tool: cmdkey /delete:<target>
    typically-removes: one credential entry
  - tool: rmdir /s /q %APPDATA%\Microsoft\Credentials + %LOCALAPPDATA%\Microsoft\Vault
    typically-removes: all user credentials + vaults
  survival-signals:
  - Credentials file target-name = RDP hostname matching incident window = saved credential to a lateral-movement destination
  - Vault credential with target-name containing attacker-looking URL or host = attacker-saved future-use credential
  - Credentials directory deleted / empty on an account that should have saved RDP / Outlook credentials = deliberate wipe
provenance:
  - ms-credential-manager-credential-provi
  - mitre-t1555-004
  - gentilkiwi-2020-mimikatz-vault-cred-modules-ex
  - specterops-2019-sharpdpapi-c-implementation-of
exit-node:
  is-terminus: true
  primary-source: mitre-t1555-004
  attribution-sentence: 'The Credential Manager stores credentials for signing into websites, applications, and/or devices that request authentication through NTLM or Kerberos in Credential Lockers (MITRE ATT&CK, n.d.).'
  terminates:
    - HAS_CREDENTIAL
    - HAD_CREDENTIAL
  sources:
    - ms-credential-manager-credential-provi
    - mitre-t1555-004
    - gentilkiwi-2020-mimikatz-vault-cred-modules-ex
  reasoning: >-
    Credential Manager + Vault stores user-mode saved credentials (Domain
    Credentials / Web Credentials / Windows Credentials) as DPAPI-wrapped
    blobs under %APPDATA%\Microsoft\Credentials\ and the Vaults folder. The
    vault IS the terminal store for user-saved secrets — RDP credentials,
    saved browser passwords pre-Chromium move, Outlook-saved passwords,
    custom-app cached tokens. Decryption requires the user's DPAPI master
    key (held in DPAPI-MasterKeys), making that a dependency not a relay.
    For HAS_CREDENTIAL / HAD_CREDENTIAL at the user-mode tier, there is
    no upstream — the blob IS the credential.
  implications: >-
    Post-compromise credential-recovery forensics MUST acquire the vault
    alongside DPAPI-MasterKeys. Presence of attacker-targeted credentials
    (RDP to a lateral-movement destination, cloud-service saved tokens)
    in the vault is direct attribution evidence. Survival is strong —
    deleting %APPDATA%\Microsoft\Credentials\ leaves EventLog traces and
    breaks the user's saved-credential UX, making this a high-visibility
    anti-forensic action.
  preconditions: >-
    DPAPI master-key chain must be recoverable. Offline decryption needs
    the user's password (or domain backup key if domain-joined) to unwrap
    the master key, which then unwraps the vault entries.
  identifier-terminals-referenced:
    - URL
    - UserSID
---

# Credential Manager + Vault

## Forensic value
Windows has two related on-disk credential stores:

- **Credentials folder** (`%APPDATA%\Microsoft\Credentials\`) — holds Generic / Domain / Certificate credentials written via `CredWrite` API (cmdkey, mstsc /savecred, Outlook, VPN clients, Git credential helper)
- **Vault directory** (`%LOCALAPPDATA%\Microsoft\Vault\<vault-guid>\`) — holds Web Credentials (Edge Legacy / IE HTTP auth, Windows account SSO tokens)

Both are DPAPI-encrypted. Decryption requires the matching DPAPI master key (see DPAPI-MasterKeys artifact).

## What typically lives in each

**Credentials folder**:
- Saved RDP mstsc passwords (target = `Domain:target=<host>` / `TERMSRV/<host>`)
- Mapped drive credentials (target = `MicrosoftAccount:user=<account>` / UNC)
- Outlook / Exchange saved password
- Git credential helper entries (target = `git:https://<host>`)
- VPN client saved creds (varies per vendor)

**Vault directory**:
- Edge Legacy / IE saved Web authentication
- Windows account SSO across Store apps
- Azure AD PRT cookies (partial)

## Triage
```powershell
# Enumerate live
cmdkey /list  # per-current-user

# Acquire for offline
Copy-Item "C:\Users\*\AppData\Roaming\Microsoft\Credentials" -Destination .\evidence\creds\ -Recurse
Copy-Item "C:\Users\*\AppData\Local\Microsoft\Vault" -Destination .\evidence\vault\ -Recurse

# Also acquire the DPAPI master keys (Protect\ directory) — required for decryption
```

## Parsing
```
mimikatz
> vault::list
> vault::cred /patch
> dpapi::cred /in:<Credentials-file> /masterkey:<plaintext-masterkey>
```

Or SharpDPAPI (GhostPack):
```
SharpDPAPI.exe credentials /pvk:<domain-backup-key>
SharpDPAPI.exe vaults /pvk:<domain-backup-key>
```

## Concept reference
- None direct — credential-material artifact

## Attack-chain example
Attacker compromises initial host. Pulls user's DPAPI master keys (Protect directory) and Credentials folder. Offline decryption yields saved RDP credential for a domain controller. Attacker RDPs to DC with the recovered credentials — lateral movement without needing to relay or phish further.

This is precisely why Credential Manager + Vault acquisition is mandatory in every IR case.

## Practice hint
On a lab VM: `cmdkey /add:testserver /user:testuser /pass:TestP@ss`. Inspect `%APPDATA%\Microsoft\Credentials\` — new encrypted blob appears. Run mimikatz vault::cred with your master key to decrypt and verify the password. This is the full decrypt chain.
