---
name: Credential-Guard-State
title-description: "Credential Guard / VBS / HVCI registry state — virtualization-based protection of LSA secrets"
aliases:
- Credential Guard
- VBS state
- HVCI flags
- Device Guard registry
link: system
link-secondary: persistence
tags:
- vbs-protection
- tamper-signal
- itm:AF
volatility: persistent
interaction-required: user-session
substrate: windows-registry-hive
substrate-instance: SOFTWARE and SYSTEM
platform:
  windows:
    min: '10'
    max: '11'
    note: "Credential Guard requires Windows 10 Enterprise / Education / Server 2016+ and hardware support (VT-x/AMD-V, SLAT, TPM 2.0 recommended). Not available on Home / Pro SKUs (with limited exceptions in recent Win11 builds where Memory Integrity is available on Pro)."
  windows-server:
    min: '2016'
    max: '2022'
location:
  hive-policy: SOFTWARE (HKLM)
  path-policy: "Policies\\Microsoft\\Windows\\DeviceGuard"
  hive-state: SYSTEM
  path-state: "CurrentControlSet\\Control\\DeviceGuard"
  lsa-cfg-flags: "CurrentControlSet\\Control\\Lsa\\LsaCfgFlags"
  addressing: hive+key-path
  note: "Credential Guard uses Virtualization-Based Security (VBS) to isolate LSA secrets (NT hashes, Kerberos TGTs, cached domain creds) into a Virtual Secure Mode (VSM) process (lsaiso.exe) that runs in a separate hypervisor-protected partition. Even SYSTEM-privileged processes in the normal OS cannot read lsaiso.exe memory. Registry captures: enable state, UEFI lock status, companion HVCI (Hypervisor-Enforced Code Integrity) state. For DFIR: Credential Guard state directly determines whether LSASS memory-dump yields anything useful (when CG is on, lsass contains proxy handles only — the actual secrets are in lsaiso which is unreadable from user-mode). Attackers confirming CG is OFF is prerequisite to mimikatz-style LSASS dumping."
fields:
- name: lsa-cfg-flags
  kind: flags
  location: "Control\\Lsa\\LsaCfgFlags value"
  type: REG_DWORD
  note: "Credential Guard enforcement flag. 0 = off; 1 = Enabled with UEFI lock; 2 = Enabled without UEFI lock. Microsoft baseline: 1 or 2 on all Windows 10/11 Enterprise systems. Attacker setting 0 + reboot + UEFI-clear-LsaCfgFlags-variable (if previously UEFI-locked) fully disables CG — then LSASS becomes dumpable."
- name: enable-virtualization-based-security
  kind: flags
  location: "Policies\\Microsoft\\Windows\\DeviceGuard\\EnableVirtualizationBasedSecurity value"
  type: REG_DWORD
  references-data:
  - concept: RegistryKeyPath
    role: subjectKey
  note: "Master switch for VBS (requires VBS for Credential Guard and HVCI). 1 = enabled; 0 = disabled. Setting 0 disables the foundation of CG + HVCI + other VBS features. Enterprise baseline: 1."
- name: hvci-value
  kind: flags
  location: "Policies\\Microsoft\\Windows\\DeviceGuard\\HypervisorEnforcedCodeIntegrity value"
  type: REG_DWORD
  note: "Hypervisor-Enforced Code Integrity — Memory Integrity feature in Windows Security UI. 1 = enabled (kernel-mode code-integrity enforced in hypervisor partition — blocks unsigned kernel drivers). 0 = disabled. Attacker disable prerequisite for loading unsigned kernel rootkit."
- name: required-security-properties
  kind: flags
  location: "Policies\\Microsoft\\Windows\\DeviceGuard\\RequirePlatformSecurityFeatures value"
  type: REG_DWORD
  note: "Bitmask: 1 = Secure Boot required; 2 = Secure Boot + DMA protection required. Tightening value = stricter posture."
- name: secure-boot-state
  kind: flags
  location: "CurrentControlSet\\Control\\SecureBoot\\State value"
  type: REG_DWORD
  note: "1 = Secure Boot enabled; 0 = disabled. Secure Boot is foundational — without it, CG and HVCI are weaker because the boot chain isn't verified. Attacker-disabled Secure Boot preceded by UEFI-shell access = most invasive pre-OS tamper."
- name: running-security-services
  kind: flags
  location: "CurrentControlSet\\Control\\DeviceGuard\\SecurityServicesRunning value"
  type: REG_MULTI_SZ / REG_DWORD array
  note: "Runtime-observed state: which VBS services are ACTUALLY running. 1 = Credential Guard running; 2 = HVCI running. Differs from the configured-to-run state — this reports what the hypervisor actually enforced at boot. Useful for catching configuration-vs-runtime drift (policy enables CG but hardware lacks support → it's configured but not running)."
- name: key-last-write
  kind: timestamp
  location: DeviceGuard + Lsa key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on DeviceGuard or Lsa subkeys = policy-change time. Cross-reference with reboot events — CG enable/disable takes effect on next boot. A LastWrite followed by reboot = tamper cycle candidate."
- name: uefi-lsa-cfg-variable
  kind: flags
  location: UEFI variable LsaCfgFlags (outside registry — UEFI firmware NVRAM)
  note: "When LsaCfgFlags = 1 was configured, Windows sets a corresponding UEFI variable that re-asserts the setting on boot even if the registry is cleared. To truly disable UEFI-locked CG, the attacker must boot to UEFI shell and clear the variable — high-noise operation."
observations:
- proposition: CONFIGURED_DEFENSE
  ceiling: C4
  note: 'Credential Guard state is the forensic ground truth for whether
    LSASS memory contains extractable credential material. When CG
    is ON with UEFI lock, even SYSTEM-privileged mimikatz cannot
    read NT hashes / Kerberos tickets from user-mode. Attacker work
    thus requires disabling CG first — registry + reboot. For DFIR:
    registry state + runtime-observed state + UEFI-lock status
    together answer: "could credentials have been harvested from
    this host via LSASS dump?" A configured-but-not-running CG
    (hardware lacked VBS support OR policy recently changed OR
    tamper) means LSASS was vulnerable regardless of policy intent.'
  qualifier-map:
    setting.registry-path: "Control\\Lsa\\LsaCfgFlags + DeviceGuard\\EnableVirtualizationBasedSecurity"
    time.start: field:key-last-write
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: UEFI-lock — registry-only tamper insufficient when LsaCfgFlags was set with UEFI lock
  known-cleaners:
  - tool: reg delete + reboot (LsaCfgFlags=2 variant)
    typically-removes: CG enforcement if not UEFI-locked
  - tool: UEFI shell + variable clear + reboot (LsaCfgFlags=1 UEFI-locked)
    typically-removes: UEFI lock — visible firmware-level action
  survival-signals:
  - LsaCfgFlags=0 or absent on Win10/11 Enterprise endpoint = misconfigured OR tampered
  - EnableVirtualizationBasedSecurity=0 with no documented reason = VBS foundation disabled
  - SecurityServicesRunning reports CG not running despite policy = configuration-vs-runtime gap (hardware-incompatible OR recently-disabled)
  - DeviceGuard / Lsa key LastWrite + reboot event pair within incident window = tamper cycle
provenance: [ms-credential-guard-manage-configure-a, mitre-t1003-001]
---

# Credential Guard State

## Forensic value
Credential Guard uses Virtualization-Based Security (VBS) to isolate LSA secrets into a hypervisor-protected process (lsaiso.exe) — making them unreadable even from SYSTEM-privileged processes in the normal OS. Registry captures:

- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags` — master CG enforcement flag
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\*` — VBS + HVCI + feature policy
- `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\SecurityServicesRunning` — runtime-observed state

The gap between CONFIGURED and RUNNING state matters: a policy may enable CG, but hardware without VBS support won't actually run it. Registry inspection of both angles reveals this.

## Attack prerequisite
Standard LSASS credential-dump attacks (mimikatz sekurlsa, SharpSleet, comsvcs.dll MiniDump) all REQUIRE CG to be off. Attacker workflow against a CG-protected host:

1. Verify `LsaCfgFlags=2` (not UEFI-locked variant `=1`)
2. `reg add ... LsaCfgFlags /t REG_DWORD /d 0 /f`
3. Reboot (CG applies at boot)
4. Dump LSASS unopposed
5. Optional: restore and reboot again

The two reboots bracketing the dump are the forensic signature. When `LsaCfgFlags=1` (UEFI-locked), the attacker must ALSO boot to UEFI shell and clear the LsaCfgFlags UEFI variable — substantially noisier and often leaves firmware-level evidence.

## Concept reference
- None direct — configuration state artifact.

## Triage
```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\SecurityServicesRunning"
```

PowerShell runtime check:
```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Format-List *
```

Runtime fields to note:
- `SecurityServicesConfigured` — what policy says
- `SecurityServicesRunning` — what's actually running (CG = value 1, HVCI = value 2)
- `VirtualizationBasedSecurityStatus` — 0/1/2

## Cross-reference
- **LSA-Protection-RunAsPPL** — complementary defense (PPL for lsass.exe process; CG for LSA secrets)
- **Kerberos-Tickets-Cache** — memory-forensic target affected by CG state
- **DPAPI-MasterKeys** — similarly affected (CG protects DPAPI key material)
- **System-7036** — DeviceGuard service state changes
- **Microsoft-Windows-DeviceGuard/Operational** EVTX — CG / HVCI events

## Practice hint
On a Windows 10/11 Enterprise lab VM with VBS hardware support: check `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard` → note `SecurityServicesRunning`. Toggle `LsaCfgFlags` (via Group Policy → Computer Configuration → Administrative Templates → System → Device Guard → Turn On Virtualization Based Security). Reboot. Re-check — `SecurityServicesRunning` reflects the runtime state change. This configured-vs-running dual-check is the baseline you rely on in investigations.
