---
name: CredentialProviders
title-description: "Credential Providers and Credential Provider Filters (Vista+ logon-UI plugin DLLs)"
aliases:
- custom credential provider persistence
- CP / CPF hijack
link: persistence
tags:
- persistence-primary
- credential-access
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  hive: SOFTWARE
  path: "Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers (and \\Credential Provider Filters)"
  addressing: hive+key-path
fields:
- name: credential-provider-clsids
  kind: identifier
  location: "Credential Providers\\<CLSID> subkey name"
  encoding: guid-string
  note: "Each subkey GUID identifies a registered Credential Provider. Default providers on Win10: Picture Password, PIN, Password, Smart Card, Windows Hello Face/Fingerprint. Attacker-registered GUID = custom provider that can intercept or supply credentials during logon."
- name: credential-provider-dll
  kind: path
  location: "Credential Providers\\<CLSID>\\(Default) value → HKLM\\SOFTWARE\\Classes\\CLSID\\<CLSID>\\InprocServer32\\(Default)"
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "The DLL actually loaded for the CLSID. The GUID → DLL resolution goes via the COM class registration under HKLM\\SOFTWARE\\Classes\\CLSID. A Credential Provider CLSID pointing to a DLL outside %SystemRoot%\\System32 is high-suspicion."
- name: credential-provider-name
  kind: label
  location: "Credential Providers\\<CLSID>\\(Default) value"
  type: REG_SZ
  encoding: utf-16le
  note: "Human-readable label displayed in the logon UI (e.g., 'PasswordProvider', 'PicturePasswordLogonProvider'). Attackers sometimes register with names that mimic legitimate providers."
- name: credential-provider-filter-clsids
  kind: identifier
  location: "Credential Provider Filters\\<CLSID> subkey name"
  encoding: guid-string
  note: "Credential Provider Filters are a SEPARATE hook that can HIDE or ENABLE specific providers at logon time. An attacker registering a filter can suppress legitimate providers (forcing users to use the attacker's) or cloak their own provider from the UI."
- name: credential-provider-filter-dll
  kind: path
  location: "Credential Provider Filters\\<CLSID>\\(Default) — resolved via HKLM\\SOFTWARE\\Classes\\CLSID"
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "DLL implementing the filter. Same resolution path as providers; same suspicion profile for non-system32 paths."
- name: key-last-write-cp
  kind: timestamp
  location: Credential Providers key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: key-last-write-cpf
  kind: timestamp
  location: Credential Provider Filters key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'Credential Providers run as SYSTEM in LogonUI (winlogon-hosted) and
    receive credentials during the logon flow. A custom provider is the
    Vista-era replacement for the pre-Vista GINA DLL and has equivalent
    power: it sees every interactive logon attempt, including the
    cleartext password for password-based logons. Filters add a second
    layer — they can hide legitimate providers, effectively forcing
    users through the attacker path.'
  qualifier-map:
    setting.registry-path: "Authentication\\Credential Providers\\<CLSID>"
    setting.dll: field:credential-provider-dll
    time.start: field:key-last-write-cp
anti-forensic:
  write-privilege: admin
  survival-signals:
  - "Credential Provider CLSID whose resolved DLL lives outside %SystemRoot%\\System32 = non-inbox provider (Microsoft's inbox set is entirely in System32)"
  - "Credential Provider Filter where the DLL path matches a Credential Provider DLL = the same malicious DLL both supplies and hides providers"
  - "Provider named similarly to a legitimate one ('PasswdProvider' vs the real 'PasswordProvider') = typosquat"
provenance:
  - ms-credential-providers-in-windows
  - mitre-t1556-002
---

# Credential Providers & Credential Provider Filters

## Forensic value
The Vista+ replacement for GINA. Each registered Credential Provider is a DLL loaded by LogonUI that supplies / interprets credentials during interactive logon. Custom providers:
- Run as SYSTEM
- See cleartext passwords for password-based logons
- Can inject arbitrary code into the logon flow

**Credential Provider Filters** are the second half of the story: they can hide specific providers from the UI. An attacker who registers both a rogue provider AND a filter that cloaks the legitimate Microsoft providers can funnel all user logons through their own code with no UI indicator.

## Concept reference
- ExecutablePath (provider DLL, filter DLL)

## Two-key correlation
Credential Provider registration is a two-registry-location lookup:

1. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\<CLSID>` — declares the CLSID is a provider
2. `HKLM\SOFTWARE\Classes\CLSID\<CLSID>\InprocServer32\(Default)` — resolves CLSID → DLL path

Investigations must query both to get the DLL. Classic mistake: reading only the Authentication key and reporting "no providers" when the CLSIDs are there but not cross-referenced.

## Triage
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers" /s
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters" /s
```
For each CLSID found, also:
```cmd
reg query "HKLM\SOFTWARE\Classes\CLSID\<CLSID>\InprocServer32"
```

Inbox providers (normal set) resolve to DLLs in `%SystemRoot%\System32` only. Anything outside System32 = custom.

## Baseline
Windows 10/11 default providers:
- Picture Password, PIN, Password, Smart Card, Windows Hello Face/Fingerprint, FIDO2, Biometric Framework

Default filters:
- Rarely populated on default installs. Any entry is a reason to investigate.
