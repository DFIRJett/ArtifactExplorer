---
name: BitLocker-FVE
title-description: "BitLocker Full Volume Encryption registry metadata (recovery password protectors, key protector state)"
aliases:
- BitLocker FVE
- FVE registry
- BitLocker key protectors
- volume encryption metadata
link: system
link-secondary: persistence
tags:
- full-disk-encryption
- recovery-key-trace
- itm:AF
volatility: persistent
interaction-required: user-session
substrate: windows-registry-hive
substrate-instance: SOFTWARE and SYSTEM
platform:
  windows:
    min: Vista
    max: '11'
    note: "Vista introduced BitLocker on Enterprise / Ultimate SKUs. Now widely available on Pro and Home (device-encryption variant). Registry fingerprint persists even if BitLocker is later disabled — metadata about past encryption state survives."
  windows-server:
    min: '2008'
    max: '2022'
location:
  hive-machine-policy: SOFTWARE (HKLM)
  path-policy: "Policies\\Microsoft\\FVE"
  hive-state: SYSTEM
  path-state: "CurrentControlSet\\Services\\FVE"
  live-boot-volume: "NTFS FVE metadata region on the protected volume (outside registry but encryption-subsystem-owned)"
  addressing: hive+key-path
  note: "Two-layer representation. POLICY side (SOFTWARE\\Policies\\Microsoft\\FVE) holds Group-Policy-pushed BitLocker configuration — recovery-info-to-AD, key-protector requirements, allowed-cipher-suites. STATE side (SYSTEM\\CurrentControlSet\\Services\\FVE) holds per-volume activation state, encryption method, key-protector GUIDs. The actual encrypted volume's on-disk FVE metadata is outside registry (NTFS-level BitLocker metadata region near the volume header). For DFIR the REGISTRY traces reveal policy intent, past encryption state, and key-protector types even after BitLocker is removed or the volume is unmounted."
fields:
- name: encryption-method
  kind: label
  location: "Policies\\Microsoft\\FVE\\EncryptionMethod / EncryptionMethodWithXtsOs / EncryptionMethodWithXtsFdv / EncryptionMethodWithXtsRdv values"
  type: REG_DWORD
  references-data:
  - concept: RegistryKeyPath
    role: subjectKey
  note: "Cipher selection. 1 = AES128 (CBC); 2 = AES256 (CBC); 3 = AES128 XTS (modern default for OS/fixed/removable); 4 = AES256 XTS. The XTS variants are preferred on modern Windows. Enterprise policy may force a specific value — mismatched runtime state vs policy = misconfiguration."
- name: key-protector-guids
  kind: identifier
  location: "CurrentControlSet\\Services\\FVE\\ per-volume subkeys — KeyProtector GUIDs list"
  encoding: guid-strings
  references-data:
  - concept: VolumeGUID
    role: mountedVolume
  note: "GUIDs of key protectors applied to each BitLocker-protected volume. Key protector TYPES include: TPM only, TPM+PIN, TPM+Startup Key, Startup Key only, Password (non-OS volumes), Recovery Password (numerical 48-digit), Recovery Key (external .bek), AD DS recovery, Azure AD recovery, Auto-unlock. Each protector GUID in registry corresponds to a specific unlock method. Critical for investigations: 'Recovery Password' protector presence indicates a 48-digit numerical recovery key was generated and should be backed up somewhere (print, USB, AD, Azure AD)."
- name: recovery-info-to-ad
  kind: flags
  location: "Policies\\Microsoft\\FVE\\OSActiveDirectoryBackup / OSRequireActiveDirectoryBackup / FDVActiveDirectoryBackup / RDVActiveDirectoryBackup"
  type: REG_DWORD
  note: "1 = BitLocker recovery info was configured to be backed up to Active Directory (or Azure AD on newer hosts). Enterprise standard. If enabled, the recovery password is in AD's ms-FVE-RecoveryInformation attribute on the computer object — DFIR can recover it domain-side. If disabled on an enterprise machine, this is a policy anomaly worth flagging."
- name: disable-encryption-event
  kind: timestamp
  location: "Microsoft-Windows-BitLocker-API/Management EVTX channel (cross-reference)"
  note: "Event IDs 745 (encryption started), 773 (decryption started), 24589 (recovery key backup succeeded), 24770 (key protector added), 24771 (key protector removed). Timeline anchors for BitLocker lifecycle events. NOT a registry field but the canonical cross-reference EVTX channel for interpreting FVE registry state."
- name: key-last-write
  kind: timestamp
  location: per-FVE-subkey key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on FVE subkeys updates when encryption state or key-protector configuration changes. Pair with BitLocker EVTX events for a full lifecycle timeline."
- name: tpm-owner-info
  kind: identifier
  location: "SYSTEM\\CurrentControlSet\\Services\\TPM (sibling TPM service key)"
  references-data:
  - concept: MachineNetBIOS
    role: trackerMachineId
  note: "TPM ownership state. BitLocker's TPM-bound protectors require TPM ownership — TPM registry gives TPM-clear and TPM-ownership-change events useful for interpreting BitLocker key-protector rotations."
observations:
- proposition: CONFIGURED_ENCRYPTION
  ceiling: C3
  note: 'BitLocker FVE registry is the authoritative source for which
    volumes are / were encrypted, by which method, with which key-
    protector types, and under which policy. For DFIR the registry
    alone cannot decrypt a BitLocker volume (that requires the
    recovery password or TPM-bound unseal) — but it tells the
    investigator WHAT KEY MATERIAL TO LOOK FOR. Example: if registry
    shows Recovery Password protector was applied and AD backup was
    enabled, pivot to AD ms-FVE-RecoveryInformation attribute. If
    no AD backup, look for printed / USB-stored recovery key in the
    user''s file / print history.'
  qualifier-map:
    setting.registry-path: "Policies\\Microsoft\\FVE + Services\\FVE"
    object.id: field:key-protector-guids
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: FVE metadata on the volume itself has HMAC; registry entries are unsigned
  known-cleaners:
  - tool: manage-bde -off
    typically-removes: encryption (decrypts volume; leaves registry evidence of prior encryption)
  survival-signals:
  - FVE registry entries present with volumes listed but no corresponding BitLocker-running state = prior encryption that was disabled; recovery-key may still be useful for historical evidence
  - Recovery Password protector present without AD backup policy = recovery key stored somewhere else (printed / USB / email) — hunt for that storage location
  - TPM-Clear event (TPM EVTX) followed by BitLocker re-encryption with new protectors = forced TPM reset, potentially to rotate out compromised key material
provenance:
  - ms-bitlocker-registry-configuration-re
  - ms-ms-fve-recoveryinformation-ad-ds-at
  - passware-2023-bitlocker-offline-analysis-rec
exit-node:
  is-terminus: true
  primary-source: ms-bitlocker-registry-configuration-re
  attribution-sentence: 'BitLocker is a Windows security feature that provides encryption for entire volumes, addressing the threats of data theft or exposure from lost, stolen, or inappropriately decommissioned devices (Microsoft, 2022).'
  terminates:
    - PROTECTS_VOLUME
    - HAS_CREDENTIAL
  sources:
    - ms-bitlocker-registry-configuration-re
    - ms-ms-fve-recoveryinformation-ad-ds-at
    - passware-2023-bitlocker-offline-analysis-rec
  reasoning: >-
    BitLocker-FVE registry entries store the authoritative Volume Master Key (encrypted) + recovery-key material + protector configuration for each BitLocker-protected volume. For PROTECTS_VOLUME (what protects this volume) and HAS_CREDENTIAL (what unlocks BitLocker), FVE is the machine-local terminus — without these values, the protected volume contents remain inaccessible.
  implications: >-
    For forensic recovery of BitLocker volumes: FVE provides the material needed either directly (with TPM access + boot-key) or via AD DS recovery-key escrow (when ms-FVE-RecoveryInformation is replicated). Presence confirms BitLocker was configured; absence on a protected volume indicates protector removal or hive corruption. Pairs with ADS recovery-key escrow for domain-joined recovery scenarios.
  preconditions: "FVE hive accessible; protector not explicitly wiped (manage-bde -off)"
  identifier-terminals-referenced:
    - VolumeGUID
---

# BitLocker FVE Registry

## Forensic value
BitLocker's Full Volume Encryption state lives in two registry regions:

- `HKLM\SOFTWARE\Policies\Microsoft\FVE\` — Group-Policy-pushed configuration
- `HKLM\SYSTEM\CurrentControlSet\Services\FVE\` — per-volume state, key-protector GUIDs

The **on-disk** FVE metadata (the actual encrypted volume header containing encrypted VMK, FVEK, key-protector blobs) lives on the protected volume itself, outside registry. But the registry holds the *what* and *how* that tells an investigator what key material to pursue.

## What the registry tells you
- Which volumes are / were encrypted
- Encryption method (AES128 CBC, AES256 CBC, AES128 XTS, AES256 XTS)
- Key-protector types on each volume (TPM-only, TPM+PIN, Recovery Password, Startup Key, etc.)
- Whether recovery-info backup to AD / Azure AD was configured
- Policy-enforced vs user-configured state

## What you need OFF the registry to decrypt
- The 48-digit recovery password (from AD / Azure AD / user record / printed backup)
- The FVEK (Full Volume Encryption Key) from a memory image / hiberfil while unlocked
- The TPM sealed VMK replay (rare; requires TPM access)

## Concept reference
- None direct — metadata-layer artifact pointing at key material sources.

## Triage
```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\FVE" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Services\FVE" /s
manage-bde -status
manage-bde -protectors -get C:
```

## Cross-reference
- **Microsoft-Windows-BitLocker-API/Management** EVTX — lifecycle events (745, 773, 24589, 24770, 24771)
- **AD ms-FVE-RecoveryInformation** — recovery passwords backed to AD (domain-side)
- **Azure AD / Intune** — recovery keys backed to cloud
- **Hiberfil / Memory image** — FVEK extractable if unlocked when acquired
- **UsnJrnl / ShellBags** — if recovery key was saved to a file / printed, UsnJrnl shows the write; print spool shows the print

## Practice hint
On a BitLocker-enabled Windows Pro VM:
```cmd
manage-bde -status
manage-bde -protectors -get C:
```
Note the key-protector GUIDs + types. Inspect `HKLM\SYSTEM\CurrentControlSet\Services\FVE\` — same GUIDs appear. This dual-source (manage-bde output + registry) is the canonical starting point for a BitLocker-focused investigation.
