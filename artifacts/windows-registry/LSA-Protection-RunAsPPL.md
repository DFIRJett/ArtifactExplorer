---
name: LSA-Protection-RunAsPPL
title-description: "LSA Protection RunAsPPL registry flag — PPL protection for LSASS process (credential-theft mitigation)"
aliases:
- RunAsPPL
- LSA Protection
- LSASS PPL
- Protected Process Light LSA
link: system
link-secondary: persistence
tags:
- credential-guard-adjacent
- tamper-signal
- itm:AF
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: '8.1'
    max: '11'
    note: "LSA Protection introduced in Windows 8.1 / Server 2012R2. Runs LSASS.exe as Protected Process Light (PPL) — user-mode processes (even with SeDebugPrivilege) cannot attach to / read lsass.exe memory, blocking mimikatz and similar. Required setting on all Windows 10+ builds per Microsoft security baseline."
  windows-server:
    min: '2012R2'
    max: '2022'
location:
  hive: SYSTEM
  path: "CurrentControlSet\\Control\\Lsa"
  value: RunAsPPL
  sibling-value: RunAsPPLBoot
  addressing: hive+key-path+value
  note: "REG_DWORD. 0 (or absent) = LSA Protection OFF (lsass runs unprotected — mimikatz can dump credentials). 1 = LSA Protection ON (lsass runs as PPL — credential-dumping is blocked). 2 = LSA Protection ON + UEFI lock (persists via UEFI variable, can't be disabled by a reboot-into-regedit attack; requires clearing UEFI variable to disable). Attacker workflow: set RunAsPPL=0 → reboot → dump LSASS with mimikatz → set RunAsPPL=1 (or leave off if unobserved). The reboot is the tell — a single boot without PPL is all that's needed for credential exfil."
fields:
- name: run-as-ppl
  kind: flags
  location: "Lsa\\RunAsPPL value"
  type: REG_DWORD
  note: "0 = off; 1 = on; 2 = on + UEFI-locked. Microsoft baseline recommends 1 on Win10+ and 2 where UEFI is available. Value 0 or absence on modern Windows = explicit tamper or misconfigured baseline. Takes effect at next boot (not immediate — the PPL attribute is applied at lsass.exe process creation which happens at boot)."
- name: run-as-ppl-boot
  kind: flags
  location: "Lsa\\RunAsPPLBoot value"
  type: REG_DWORD
  note: "Alternate / successor value used on some newer builds. Semantics equivalent to RunAsPPL. When both are present, check which applies on the target Windows build via Microsoft documentation. Attackers who know the name of the value to clear are more sophisticated; cross-check both."
- name: audit-level
  kind: flags
  location: "Lsa\\AuditLevel value"
  type: REG_DWORD
  note: "Related setting controlling LSA auditing verbosity. 0 = default; 8 = verbose. Attackers sometimes set to 0 to reduce LSA-related audit events; aggressive defenders bump to 8."
- name: key-last-write
  kind: timestamp
  location: Control\\Lsa key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on the Lsa key advances when RunAsPPL or sibling values change. A recent LastWrite on this key without a corresponding IT-baseline-push event = tamper candidate. Cross-reference with System-4800 (RunAsPPL audit event) if LSA-audit is active."
- name: uefi-variable-presence
  kind: identifier
  location: UEFI variable 'LsaCfgFlags' (outside registry — UEFI firmware NVRAM)
  note: "When RunAsPPL=2 was set, a UEFI variable stores the locked state. Even if the attacker clears the registry value, the UEFI-locked setting re-asserts on next boot. To genuinely disable PPL, the attacker must boot to UEFI shell and clear LsaCfgFlags — leaves UEFI-variable-edit evidence. Check UEFI variable state when RunAsPPL=2 is the baseline."
observations:
- proposition: CONFIGURED_DEFENSE
  ceiling: C3
  note: 'RunAsPPL is the single-value gate between "attacker can dump
    LSASS" and "attacker cannot dump LSASS." When ON, lsass.exe
    receives PPL protection — even a SYSTEM-privileged user-mode
    process cannot attach to lsass for memory read. When OFF, lsass
    is a standard process and mimikatz / SharpSleet / nanodump /
    comsvcs.dll MiniDump all succeed. For DFIR, registry value is
    the forensic ground truth — tamper here is a hot tamper signal
    because the ONLY legitimate reason to disable RunAsPPL on a
    modern Windows build is misconfigured IT management. Attacker
    flip-and-reboot sequence often leaves the value at 0 after
    reboot if the attacker was interrupted OR doesn''t restore.
    Registry LastWrite on Lsa key near an intrusion window = tell.'
  qualifier-map:
    setting.registry-path: "Control\\Lsa\\RunAsPPL"
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: UEFI-lock (RunAsPPL=2 variant) — registry-change alone cannot disable when UEFI-locked
  known-cleaners:
  - tool: reg delete / reg add
    typically-removes: the value (requires admin; takes effect next boot)
  - tool: UEFI shell LsaCfgFlags clear
    typically-removes: UEFI lock (physical / boot-menu access required; extra-noisy)
  survival-signals:
  - RunAsPPL=0 or absent on Windows 10/11 baseline-expected-on endpoint = misconfigured OR disabled by attacker
  - Lsa key LastWrite recent and no corresponding IT-management change ticket = drive-by tamper
  - Security channel or System channel showing LSASS start with PPL attribute cleared post-reboot = successful attacker disable cycle
  - UEFI-variable LsaCfgFlags cleared on a machine that previously had RunAsPPL=2 = UEFI-shell-level tamper (very rare; strong signal)
provenance:
  - ms-configuring-additional-lsa-protecti
  - mitre-t1003-001
---

# LSA Protection (RunAsPPL)

## Forensic value
`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` is the single REG_DWORD that controls whether LSASS runs as a Protected Process Light (PPL). Values:

- **0 or absent** — LSA Protection OFF. mimikatz and similar can dump LSASS memory (NT hashes, Kerberos tickets, DPAPI keys, cleartext passwords when WDigest is on).
- **1** — LSA Protection ON. LSASS runs as PPL. Credential-dumping fails with access-denied even for SYSTEM.
- **2** — LSA Protection ON + UEFI-locked. Registry-change alone cannot disable; requires UEFI-shell access to clear LsaCfgFlags UEFI variable.

Microsoft's Windows 10+ security baseline recommends 1 (or 2 when UEFI is available). Any modern endpoint with RunAsPPL=0 is misconfigured or tampered.

## The attacker bypass
Standard attacker sequence when RunAsPPL=1 (not UEFI-locked):
1. Admin context: `reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f`
2. Reboot
3. After reboot LSASS is unprotected — dump with mimikatz / SharpSleet / ProcDump / comsvcs.dll
4. Restore: `reg add ... /d 1 /f` + reboot (if attacker is patient)

Evidence: registry LastWrite on Lsa key twice with short delta; System-1074 reboot events bracketing; possibly an attacker dropper / mimikatz Amcache entry between the two reboots.

## Concept reference
- None direct — configuration state artifact.

## Triage
```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPLBoot
```

PowerShell check of both live-runtime and registry-baseline:
```powershell
# Is LSASS actually PPL right now?
Get-CimInstance Win32_Process -Filter "Name='lsass.exe'" | Select-Object Name, ProcessId, ExecutablePath
# The running PPL state is not trivially queryable but can be inspected via sysinternals Process Explorer → Integrity column
```

## Cross-reference
- **System-1074 / 41 / 6008** — reboot events (bracket tamper cycles)
- **Security-4688** / **Sysmon-1** — reg.exe / PowerShell processes that modified the key
- **Security-4697** — any service plant for post-reboot credential-dump automation
- **Sysmon-10 (ProcessAccess)** — access to lsass.exe (should be rare legitimate; post-disable-PPL spike = evidence of dumping)
- **Registry transaction logs (.LOG1/.LOG2)** — may capture pre-tamper state

## Attack-chain example
Incident timeline reconstruction:
- T0: baseline — RunAsPPL=1 (matches enterprise security policy)
- T+0h: Lsa key LastWrite, reg.exe process-creation event with command-line showing RunAsPPL=0
- T+5min: System-1074 reboot initiated
- T+10min: System-12 OS boot
- T+12min: Sysmon-10 showing many processes accessing lsass.exe (mimikatz-style dump)
- T+25min: reg.exe process-creation showing RunAsPPL=1 restore
- T+28min: reboot

The pair of reboots with a brief unprotected-lsass window is the signature. Forensic detection: registry-write pair + reboot pair + Sysmon-10 spike.

## Practice hint
On a lab Win10/11 VM: check current RunAsPPL value. If 1, observe that `procdump -ma lsass.exe` fails with access-denied (lsass is PPL). Toggle to 0 (`reg add ... /v RunAsPPL /t REG_DWORD /d 0 /f`), reboot, try again — procdump succeeds. Restore to 1. This is the exact attacker bypass — DFIR looks for the registry-LastWrite + reboot pair as evidence it happened.
