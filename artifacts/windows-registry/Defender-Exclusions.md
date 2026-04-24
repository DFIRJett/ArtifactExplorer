---
name: Defender-Exclusions
title-description: "Microsoft Defender scan exclusion registry (Paths / Processes / Extensions / IpAddresses)"
aliases:
- Defender exclusions key
- AV scan exclusions
link: security
tags:
- defense-evasion
- tamper-signal
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: '10'
    max: '11'
  windows-server:
    min: '2016'
    max: '2022'
location:
  hive: SOFTWARE
  path: "Microsoft\\Windows Defender\\Exclusions"
  alt-path: "Policies\\Microsoft\\Windows Defender\\Exclusions (GPO-pushed exclusions)"
  addressing: hive+key-path
  note: "Path is SACL-protected on modern Windows with Tamper Protection enabled — writes require trusted-installer or local admin with specific process context. Tamper Protection blocks programmatic changes to the Exclusions keys unless disabled first."
fields:
- name: excluded-paths
  kind: path
  location: "Exclusions\\Paths\\<path> value names"
  type: REG_DWORD
  encoding: utf-16le-value-name
  note: "Value NAME is the full path or glob pattern excluded (e.g., 'C:\\Users\\*\\AppData\\Local\\Temp\\'). Value DATA is 0x00000000. Every excluded path bypasses real-time + scheduled scanning. Attacker-added exclusions nearly always precede payload drop."
- name: excluded-processes
  kind: path
  location: "Exclusions\\Processes\\<process> value names"
  type: REG_DWORD
  encoding: utf-16le-value-name
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Value NAME is a process executable name (e.g., 'mimikatz.exe'). Defender will not scan file activity initiated by that process. Classic evasion: exclude the attacker's dropper's process name."
- name: excluded-extensions
  kind: label
  location: "Exclusions\\Extensions\\<ext> value names"
  type: REG_DWORD
  encoding: utf-16le-value-name
  note: "Value NAME is a file extension (e.g., '.enc', '.dat'). Files with that extension aren't scanned. Attacker drops payload with the excluded extension, then renames at execution time."
- name: excluded-ip-addresses
  kind: label
  location: "Exclusions\\IpAddresses\\<ip> value names (Win11 22H2+)"
  type: REG_DWORD
  encoding: utf-16le-value-name
  note: "Value NAME is an IP address whose outbound/inbound traffic Defender Network Inspection skips. Newer key; exclusions here are unusual even in legitimate deployments."
- name: key-last-write
  kind: timestamp
  location: "Exclusions key metadata (per subkey: Paths, Processes, Extensions, IpAddresses)"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on any Exclusions subkey matching the suspected attack window = tamper indicator."
- name: disable-real-time-monitoring
  kind: flags
  location: "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring value"
  type: REG_DWORD
  references-data:
  - concept: RegistryKeyPath
    role: subjectKey
  note: "1 = real-time protection disabled. Complementary tamper indicator — often set alongside exclusion additions. Blocked by Tamper Protection when enabled."
- name: disable-anti-spyware
  kind: flags
  location: "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware value"
  type: REG_DWORD
  note: "1 = Defender fully disabled (pre-TP). Modern Windows 10/11 ignores this unless Tamper Protection is off."
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'Defender exclusion registry is one of the highest-value tamper
    signals available. Attackers nearly always modify exclusions before
    dropping payloads — the "preparation" step often leaves a timestamp
    window before the payload itself exists. A sudden set of exclusions
    added outside patch/install windows, particularly for paths or
    process names that match subsequently-observed attacker tooling, is
    ground-truth evidence of deliberate evasion.'
  qualifier-map:
    setting.registry-path: "Windows Defender\\Exclusions"
    time.start: field:key-last-write
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: Tamper Protection (Win10 1903+; Intune or Defender UI enabled) blocks non-TrustedInstaller writes
  survival-signals:
  - Exclusions\Paths contains a user-writable path (%TEMP%, %APPDATA%) without a known business reason
  - Exclusions\Processes contains a process name that later appears in Security-4688 or Sysmon-1 as an attacker binary
  - DisableRealtimeMonitoring=1 + Tamper Protection off on a managed machine
  - LastWrite on Exclusions\Paths within hours of a payload execution event
provenance: [ms-configure-and-validate-exclusions-f, ms-protect-security-settings-with-tamp, mitre-t1562-001]
---

# Defender exclusions

## Forensic value
Microsoft Defender stores scan exclusions in four subkeys under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`:
- `Paths` — files/folders Defender won't scan
- `Processes` — process names whose file activity Defender won't inspect
- `Extensions` — file extensions Defender skips
- `IpAddresses` — IPs Network Inspection skips (Win11 22H2+)

Legitimate exclusions exist (SQL database directories, Exchange stores, backup tools). Attacker-added exclusions are almost always visible as:
- Paths in `%TEMP%` / `%APPDATA%` / a user profile — locations real enterprise deployments rarely add
- Process names matching obviously-attacker binaries (mimikatz, psexec, nanodump, etc.)
- Extensions matching something unusual (`.bin`, `.enc`, `.dat`)

Every entry is stored as a **REG_DWORD value whose NAME is the exclusion string** — the value data is `0x00000000` and ignored. To enumerate exclusions you must list the value NAMES under each subkey.

## Concept reference
- ExecutablePath (for Processes exclusions)

## Tamper Protection note
Modern Windows 10 / 11 with Tamper Protection enabled will REFUSE programmatic writes to these keys. Investigations finding exclusion additions on a TP-enabled machine must cross-reference with TP state at the time of the write — TP being toggled off shortly before the exclusion add is itself a high-signal event (System-channel Defender events 5007 and the `TamperProtection` subkey).

## Triage
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" /s
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring
```

Correlate the LastWrite timestamp of each subkey with Security-4657 events (if the key has an SACL; not by default). Cross-reference with Defender-5001 (real-time protection disabled).

## Practice hint
On a test VM, disable Tamper Protection manually, then run `Add-MpPreference -ExclusionPath C:\temp\test`. Observe the new value name under `Exclusions\Paths`. Check Security.evtx for 4657 if the key is SACL'd. Note the `Paths` subkey's LastWrite updating — this timestamp is the single most important forensic pivot for "when was this exclusion added."
