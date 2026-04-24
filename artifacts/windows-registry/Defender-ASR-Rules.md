---
name: Defender-ASR-Rules
title-description: "Microsoft Defender Attack Surface Reduction (ASR) rule enforcement state + Network Protection"
aliases:
- ASR rules
- Attack Surface Reduction registry
- Defender Network Protection
- Controlled Folder Access state
link: system
link-secondary: persistence
tags:
- tamper-signal
- endpoint-hardening
- itm:AF
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: '10'
    max: '11'
    note: "ASR introduced in Windows 10 1709. Expanded with every subsequent feature build. Not present pre-Win10 (classic Defender predecessor lacked ASR)."
  windows-server:
    min: '2019'
    max: '2022'
location:
  hive: SOFTWARE (HKLM)
  path-policy: "Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR"
  path-rules: "Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules"
  path-gpo: "Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR"
  path-network-protection: "Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection"
  path-controlled-folder: "Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access"
  addressing: hive+key-path
  note: "ASR comprises ~16+ behavior-blocking rules targeting Office macros, email client executables, obfuscated scripts, process injection, Adobe Reader child processes, LSASS credential theft attempts, WMI persistence, USB-launched untrusted binaries, and more. Each rule has a GUID and independent enforcement mode (Disabled / Block / Audit / Warn). Companion features in the same Exploit Guard registry tree: Network Protection (blocks connections to known-bad destinations) and Controlled Folder Access (anti-ransomware — prevents unauthorized processes from writing to protected folders). All three are configured per-rule / per-feature and are explicit attacker targets for defense impairment (MITRE T1562.001)."
fields:
- name: asr-rule-state
  kind: flags
  location: "ASR\\Rules\\<rule-GUID> value"
  type: REG_SZ (enum string)
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Enforcement mode for a specific ASR rule: '0' = Disabled (not enforcing), '1' = Block (enforce and block), '2' = Audit (log but don't block), '6' = Warn (user prompt). Microsoft recommends Block mode for all ASR rules on hardened endpoints. Attacker turning '1' → '0' silently disables a specific rule — targeted defense-evasion. Commonly-targeted: LSASS credential-theft rule (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2), Office-macro-creates-child-process rule (D4F940AB-401B-4EFC-AADC-AD5F3C50688A), untrusted-USB rule (b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4)."
- name: asr-rule-guid
  kind: identifier
  location: "ASR\\Rules\\<rule-GUID> key name"
  encoding: guid-string
  note: "Microsoft-documented rule GUID. Each GUID maps to a specific behavior. Microsoft's ASR rules page lists all current GUIDs with their rule descriptions. DFIR should baseline a host's full rule-GUID enumeration against Microsoft's published list to catch: (1) expected rule entirely absent, (2) expected rule in Audit/Disabled mode when Block is baseline, (3) unexpected/fake rule entries."
- name: asr-enabled-master
  kind: flags
  location: "Windows Defender Exploit Guard\\ASR\\ExploitGuard_ASR_Rules value"
  type: REG_DWORD
  note: "Master enable flag for ASR rule enforcement. 1 = enforcement active; 0 = ASR rules registry honored but NO enforcement. Attacker setting this to 0 effectively disables all ASR regardless of per-rule state. Sneaky — per-rule inspection still shows Block mode, but the master flag is off."
- name: network-protection-state
  kind: flags
  location: "Windows Defender Exploit Guard\\Network Protection\\EnableNetworkProtection value"
  type: REG_DWORD
  note: "0 = disabled; 1 = enabled (Block); 2 = Audit. Blocks outbound connections to Microsoft-reputation-bad domains/IPs. Attacker setting 0 disables Network Protection — attacker C2 traffic unimpeded by Defender network reputation. Microsoft baseline: 1."
- name: controlled-folder-state
  kind: flags
  location: "Windows Defender Exploit Guard\\Controlled Folder Access\\EnableControlledFolderAccess value"
  type: REG_DWORD
  note: "0 = disabled; 1 = enabled (Block mode — protected folders cannot be written except by allow-listed apps); 2 = Audit; 3 = Block disk modifications only; 4 = Audit disk modifications only. Anti-ransomware feature. Attacker setting 0 before ransomware encryption = removes the protection."
- name: controlled-folder-allowlist
  kind: path
  location: "Windows Defender Exploit Guard\\Controlled Folder Access\\AllowedApplications (REG_MULTI_SZ of app paths)"
  note: "Applications explicitly allowed to write to protected folders. Attacker-added entry = attacker binary allow-listed to bypass Controlled Folder Access."
- name: key-last-write
  kind: timestamp
  location: per-Exploit-Guard-subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on ASR / Network Protection / CFA keys updates on state changes. Cross-reference with Security-4688 / Sysmon-1 for reg.exe / PowerShell / WMI-Set-MpPreference process-creation events."
observations:
- proposition: CONFIGURED_DEFENSE
  ceiling: C3
  note: 'ASR / Network Protection / Controlled Folder Access are the
    behavioral hardening layer of Microsoft Defender. Registry tamper
    here silently disables specific protection behaviors without
    stopping Defender itself. Because Defender Exclusions
    (already covered separately) is a well-known attacker target and
    Tamper Protection now blocks Exclusions changes on
    modern Windows, attackers increasingly pivot to ASR rule disable
    (which Tamper Protection also covers in newer builds, but
    coverage varies). For DFIR: diff the ASR rule enforcement state
    against Microsoft-recommended baseline OR enterprise-deployed
    baseline — deltas are tamper candidates.'
  qualifier-map:
    setting.registry-path: "Microsoft\\Windows Defender\\Windows Defender Exploit Guard"
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: Tamper Protection on Win10/11 Enterprise (when enabled via Intune / Defender portal) blocks ASR registry changes
  survival-signals:
  - ASR rule GUID in Disabled (0) or Audit (2) state where enterprise baseline requires Block (1) = tamper
  - ExploitGuard_ASR_Rules master flag = 0 while per-rule settings look configured = sneaky master-disable
  - EnableNetworkProtection = 0 on a host with established baseline of 1 = tamper
  - AllowedApplications list contains unexpected binary path = allow-list abuse
  - Key LastWrite on Exploit Guard subkeys within incident window = active tamper
provenance: [ms-attack-surface-reduction-rules-rule, mitre-t1562-001, ms-controlled-folder-access-anti-ranso]
---

# Defender ASR / Network Protection / Controlled Folder Access

## Forensic value
Microsoft Defender Exploit Guard includes three registry-configured behavioral defenses:

- **Attack Surface Reduction (ASR)** — 16+ behavior rules each with its own enforcement mode
- **Network Protection** — reputation-based blocking of outbound connections
- **Controlled Folder Access** — anti-ransomware write-protection for designated folders

All three live under `HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\`.

## ASR rule tamper pattern
Attacker targeting endpoint hardened by ASR:
1. Identify rules blocking attacker's payload (e.g., LSASS-credential-theft rule blocks mimikatz attempts)
2. `Set-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions 0`
3. Deploy attacker tooling
4. Rule-disable persists across reboot unless reverted

The registry state `ASR\Rules\<GUID> = "0"` is the forensic evidence.

## Concept reference
- None direct — configuration artifact.

## Triage
```powershell
Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions, EnableNetworkProtection, EnableControlledFolderAccess

# Registry-direct
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard" /s
```

## Baseline comparison
Against Microsoft's documented ASR rule GUID list:
- Every listed rule SHOULD be present in ASR\Rules
- Enterprise policy typically sets all to Block (1)
- Per-rule mode = 0 (Disabled) or 2 (Audit) on an enterprise-baselined machine = tamper

## Cross-reference
- **Microsoft-Windows-Windows Defender/Operational** EVTX — events 1121 / 1122 (ASR block/audit), 1125 / 1126 (Network Protection block/audit), 1123 / 1124 (Controlled Folder Access block/audit)
- **Security-4688 / Sysmon-1** — Set-MpPreference / reg.exe / WMI-Set invocations
- **Tamper Protection** state — under HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection — blocks ASR changes when on

## Practice hint
On a lab Win10/11 VM: `Get-MpPreference | Format-List Attack*` lists current ASR rule states. `Set-MpPreference -AttackSurfaceReductionRules_Ids "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" -AttackSurfaceReductionRules_Actions 0` sets the Office-macro-creates-child rule to Disabled. Observe `HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\` updates. Restore with the same command and -Actions 1.
