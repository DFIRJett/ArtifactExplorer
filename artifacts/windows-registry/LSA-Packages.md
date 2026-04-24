---
name: LSA-Packages
title-description: "LSA Authentication / Notification / Security Packages (lsass.exe-loaded DLLs)"
aliases:
- LSA Security Package injection
- SSP persistence
- LSASS SSP hijack
link: persistence
tags:
- persistence-primary
- credential-access
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: NT4
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SYSTEM
  path: CurrentControlSet\Control\Lsa (and \OSConfig)
  addressing: hive+key-path
fields:
- name: authentication-packages
  kind: path
  location: Authentication Packages value
  type: REG_MULTI_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "DLLs lsass.exe loads as authentication packages at boot. Defaults: msv1_0, kerberos (implicitly). Any additional entry is a persistence DLL that runs in LSASS with access to every authentication event — ideal for credential interception."
- name: notification-packages
  kind: path
  location: Notification Packages value
  type: REG_MULTI_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Password-change notification DLLs lsass.exe loads at boot. Default: scecli, rassfm. Each DLL is called when ANY password changes (incl. plaintext pre-hash) — classic credential-capture persistence (Mimikatz's mimilib.dll uses this vector)."
- name: security-packages
  kind: path
  location: Security Packages value (under \OSConfig or \Lsa depending on Windows version)
  type: REG_MULTI_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Security Support Provider (SSP) DLLs lsass.exe loads as SSPI providers. Defaults: kerberos, msv1_0, schannel, wdigest, tspkg, pku2u, negoexts, cloudAP. Additional entries = rogue SSP — attack surface for NTLM/Kerberos interception. SSPs can access cleartext credentials via the SpAcceptCredentials / SpInitLsaModeContext callbacks."
- name: lsa-cfg-flags
  kind: flags
  location: LsaCfgFlags value
  type: REG_DWORD
  note: "Credential Guard + RunAsPPL flags. 0 = off. 1 = PPL (Credential Guard runs LSASS as Protected Process Light on VBS-capable systems). Setting to 0 after enabling = guardrail tamper."
- name: run-as-ppl
  kind: flags
  location: RunAsPPL value
  type: REG_DWORD
  note: "1 = lsass.exe runs as Protected Process Light (Win8.1+) — blocks unprotected credential-dump tools and SSP/AP loading except for signed packages. 0 or missing = LSASS is unprotected and the Packages values above can load arbitrary DLLs."
- name: run-as-ppl-boot
  kind: flags
  location: RunAsPPLBoot value (Win10 1607+)
  type: REG_DWORD
  note: "Whether RunAsPPL was in effect at the last boot. Compare against current RunAsPPL — mismatch means PPL was toggled since boot."
- name: key-last-write-lsa
  kind: timestamp
  location: Lsa key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'The three Packages values (Authentication, Notification, Security)
    are the three canonical LSASS-injection persistence surfaces. Any non-
    default DLL loaded in LSASS has access to every credential operation
    on the system — the highest-privilege credential observation point
    Windows exposes. PPL (RunAsPPL=1) mitigates by refusing unsigned
    modules but must be ACTIVELY enabled; default-off on many builds.'
  qualifier-map:
    setting.registry-path: Lsa\<value>
    setting.dll-list: field:authentication-packages
    time.start: field:key-last-write-lsa
anti-forensic:
  write-privilege: admin
  integrity-mechanism: RunAsPPL (Win8.1+) blocks unsigned SSP / AP loads once in effect
  survival-signals:
  - Authentication Packages != [msv1_0] → any addition is persistence
  - Notification Packages != [scecli, rassfm] → any addition is password-capture persistence (look for mimilib.dll, ntshrui.dll masquerade, etc.)
  - Security Packages with DLLs outside the Microsoft-signed stock set = rogue SSP
  - RunAsPPL=0 on Win10+ = guardrail disabled (legitimate setup scripts never do this — always a red flag)
provenance:
  - ms-configuring-additional-lsa-protecti
  - delpy-nd-mimikatz-mimilib-dll-as-a-noti
  - mitre-t1547-002
  - mitre-t1547-005
---

# LSA Packages

## Forensic value
LSASS loads three distinct sets of DLLs from the registry at boot. Each set sits at a different abstraction in the authentication stack, and each is an attacker-known persistence target:

| Packages value | Purpose | Attacker use |
|---|---|---|
| **Authentication Packages** | plug-in authentication providers (NTLM, custom AP) | runs in LSASS, sees all authentication calls |
| **Notification Packages** | password-change notification handlers | called with **cleartext** password at change time |
| **Security Packages (SSP)** | SSPI providers (Kerberos, NTLM, etc.) | intercepts Kerberos / NTLM negotiation |

All three load in `lsass.exe` at SYSTEM privilege with full credential access. Adding a DLL to any of them = persistence with the most valuable observation point on a Windows host.

## Modern mitigation: RunAsPPL
On Win8.1+ with RunAsPPL=1 and VBS/Credential Guard, lsass.exe runs as Protected Process Light. PPL refuses to load unsigned DLLs — the Packages values still appear to work, but loads fail at runtime. Critical to check both `RunAsPPL` AND the Packages entries together; non-PPL LSASS with rogue Packages is the worst case.

## Concept reference
- ExecutablePath (DLL list per package type)

## Triage
```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig" /v "Security Packages"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags
```

Clean baseline:
- Authentication Packages = `msv1_0`
- Notification Packages = `scecli`, `rassfm`
- Security Packages (OSConfig or Lsa) = `kerberos msv1_0 schannel wdigest tspkg pku2u negoexts cloudAP` (build-dependent)
- RunAsPPL = 1 on hardened Win10+ systems; 0 or missing on default builds

## Practice hint
On a test VM, add a benign DLL path to Notification Packages, reboot, check for `Security.evtx` event 4657 (registry value modified — if auditing the LSA key). Then verify the DLL is actually loaded in lsass.exe via `Get-Process lsass | Select -Expand Modules`. Confirm RunAsPPL=1 blocks the load: toggle RunAsPPL, reboot, repeat.
