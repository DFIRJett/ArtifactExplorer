---
name: PrintNightmare-PointAndPrint
title-description: "Point and Print registry flags — CVE-2021-34527 (PrintNightmare) exploit-surface enabling state"
aliases:
- PrintNightmare
- Point and Print
- NoWarningNoElevationOnInstall
- UpdatePromptSettings
link: persistence
tags:
- exploit-surface
- tamper-signal
- itm:AF
volatility: persistent
interaction-required: user-session
substrate: windows-registry-hive
substrate-instance: SOFTWARE and NTUSER.DAT
platform:
  windows:
    min: '7'
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  hive: SOFTWARE (HKLM) and NTUSER.DAT (HKCU)
  path-gpo: "Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint"
  path-driver-install-allowed: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint\\RestrictDriverInstallationToAdministrators"
  path-legacy-user: "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Providers\\Client Side Rendering Print Provider"
  addressing: hive+key-path
  note: "Point and Print is the Windows feature that lets a client computer dynamically install a print driver from a server when connecting to a shared printer. The legitimate use case: enterprise print servers distribute drivers to clients without admin intervention. CVE-2021-34527 (PrintNightmare) abused this: a non-admin user could install an attacker-supplied 'print driver' (arbitrary signed-or-unsigned DLL) and get SYSTEM-level code execution via the Print Spooler service. Microsoft's July 2021 patch introduced RestrictDriverInstallationToAdministrators=1 as the mitigation. The registry state of that value determines whether the exploit-surface remains open — and attacker registry-flip to 0 before exploitation is the textbook bypass."
fields:
- name: restrict-driver-installation
  kind: flags
  location: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint\\RestrictDriverInstallationToAdministrators value"
  type: REG_DWORD
  references-data:
  - concept: RegistryKeyPath
    role: subjectKey
  note: "THE PrintNightmare mitigation switch. 1 = driver install requires admin (mitigation ACTIVE). 0 or absent = any user can install drivers (mitigation OFF, exploit surface present). Microsoft post-July-2021 baseline: 1. Attacker-flipped to 0 + exploit PrintNightmare = SYSTEM-level execution from non-admin context."
- name: no-warning-no-elevation
  kind: flags
  location: "PointAndPrint\\NoWarningNoElevationOnInstall value"
  type: REG_DWORD
  note: "Legacy pre-patch setting. 1 = suppress UAC / warning dialogs on driver install; 0 = normal warnings. Attackers set 1 alongside RestrictDriverInstallationToAdministrators=0 for silent driver install. Microsoft post-patch baseline: 0 (or absent)."
- name: update-prompt-settings
  kind: flags
  location: "PointAndPrint\\UpdatePromptSettings value"
  type: REG_DWORD
  note: "Legacy pre-patch setting. Controls driver-update prompting. 2 = no prompts for package updates. Attacker-configured value of 2 eliminates another user-interaction barrier. Not directly the CVE but used in chained exploit variants."
- name: allow-server-list
  kind: content
  location: "PointAndPrint\\TrustedServers + ServerList values"
  type: REG_DWORD / REG_SZ
  note: "Allow-listed print servers for Point and Print. When set, clients will only install drivers from listed servers. Empty or absent list + RestrictDriverInstallationToAdministrators=0 = fully-open driver-install attack surface."
- name: key-last-write
  kind: timestamp
  location: PointAndPrint subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on PointAndPrint subkey = policy change time. Attacker registry-flip to open the exploit surface leaves this timestamp. Pair with Security-4688 / Sysmon-1 for the reg.exe / PowerShell process that did the write."
- name: spoolsv-state
  kind: flags
  location: "CurrentControlSet\\Services\\Spooler\\Start value"
  type: REG_DWORD
  note: "Print Spooler service state. 2 = Automatic (default). 4 = Disabled. Microsoft's post-patch guidance for endpoints that don't need print: DISABLE the Spooler entirely (Start=4). Value of 2 on an endpoint that has no business printing = open PrintNightmare surface IF RestrictDriverInstallationToAdministrators is also 0."
observations:
- proposition: CONFIGURED_DEFENSE
  ceiling: C3
  note: 'PrintNightmare (CVE-2021-34527) is one of the most widely-
    exploited Windows vulnerabilities of recent years. The registry
    state of RestrictDriverInstallationToAdministrators is the
    forensic ground truth for whether a host was exploitable at any
    given point. A value of 0 on a modern Windows endpoint post-
    July-2021 = either misconfigured IT OR attacker-flipped pre-
    exploitation. Combined with Spooler service state (Start=2 vs 4),
    this registry tells whether the classic PrintNightmare chain was
    feasible. For DFIR investigations involving Print Spooler
    processes as the compromise vector, inspect this registry first.'
  qualifier-map:
    setting.registry-path: "Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint"
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  survival-signals:
  - RestrictDriverInstallationToAdministrators=0 or absent on a post-July-2021 Windows endpoint = exploit surface open
  - NoWarningNoElevationOnInstall=1 = silent-install vector re-enabled
  - PointAndPrint LastWrite within incident window + Spooler running = possible pre-exploit tamper
  - Companion sign: Print\\Monitors subkeys with recent LastWrite = possible driver-install-as-attacker-DLL (see Port-Monitors artifact)
provenance: [ms-cve-2021-34527-printnightmare-advis, mitre-t1068, zerosteiner-2021-printnightmare-exploit-and-reg]
---

# PrintNightmare / Point and Print Registry

## Forensic value
Point and Print lets Windows clients install print drivers from a server automatically. CVE-2021-34527 (PrintNightmare, 2021) abused this feature so any user could install an arbitrary "driver" (attacker DLL) via the SYSTEM-privileged Print Spooler service — achieving local privilege escalation.

Microsoft's July 2021 mitigation added `RestrictDriverInstallationToAdministrators = 1`. The registry state of this and sibling values determines the host's exposure:

- **RestrictDriverInstallationToAdministrators = 1** — mitigation active (baseline)
- **RestrictDriverInstallationToAdministrators = 0 or absent** — exploit surface OPEN
- **NoWarningNoElevationOnInstall = 1** — silent install enabled (attacker preferred)
- **Spooler Service Start = 2** — Print Spooler running (required for exploit)
- **Spooler Service Start = 4** — Spooler disabled (Microsoft alternate mitigation)

## Attack pattern
1. Attacker has non-admin foothold
2. Checks `RestrictDriverInstallationToAdministrators` — if = 1, attempts to disable (requires admin OR different exploit chain)
3. Delivers attacker "driver" DLL via Point and Print exploit
4. Print Spooler loads the DLL as SYSTEM → attacker has LPE

Registry state + service state = the forensic exposure picture at any given moment.

## Concept reference
- None direct — configuration state artifact.

## Triage
```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v Start
```

Check for baseline compliance:
- RestrictDriverInstallationToAdministrators = 1 (or GPO forcing this)
- NoWarningNoElevationOnInstall absent or = 0
- Spooler Start = 4 on endpoints not needing print (most hardened enterprise endpoints)

## Cross-reference
- **Port-Monitors** — related print-spooler persistence (driver DLL load)
- **Print-Spool-Files** — SPL/SHD files for print job forensics
- **Microsoft-Windows-PrintService/Admin** EVTX — events 808 / 316 / 1000-series for driver installation
- **Security-4688** — spoolsv.exe child process creation (PrintNightmare exploit path)
- **System-7036** — Spooler service state changes
- **Sysmon-7** — DLL load into spoolsv.exe (attacker "driver" DLL)

## Practice hint
On a lab VM: check current state of `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint`. On a fully-patched Win10/11, RestrictDriverInstallationToAdministrators should be 1. Flip to 0 (admin required) — the host is now PrintNightmare-vulnerable. Revert after testing. The registry-flip + reboot or spooler-restart is the pre-exploit signature.
