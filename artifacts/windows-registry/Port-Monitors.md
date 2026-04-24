---
name: Port-Monitors
title-description: "Print Spooler Port Monitors — DLL loaded by SYSTEM-privileged spoolsv.exe on startup"
aliases:
- Port Monitor DLL
- spoolsv port monitor
- Print Monitor
link: persistence
tags:
- persistence-primary
- system-privileged
- itm:PR
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: NT4.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SYSTEM
  path: "CurrentControlSet\\Control\\Print\\Monitors\\<monitor-name>"
  addressing: hive+key-path
  note: "Each subkey under Monitors\\ is a registered port monitor name ('Standard TCP/IP Port', 'USB Monitor', 'Local Port', etc.). Each subkey's Driver value points to a DLL loaded into spoolsv.exe at Print Spooler service startup. Because spoolsv.exe runs as LOCAL SYSTEM, an attacker-registered port monitor executes attacker DLL code with full system privileges on every boot."
fields:
- name: driver-dll
  kind: path
  location: "Monitors\\<name>\\Driver value"
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "DLL path loaded into spoolsv.exe. Stock Microsoft port monitors reference DLLs in %SystemRoot%\\System32\\ (tcpmon.dll, localspl.dll, inetppui.dll). A Driver value pointing outside System32 or to an unusual path = candidate hijack. AddMonitor API (documented by Microsoft) is the legitimate installation path — attacker use typically bypasses it and writes registry directly."
- name: monitor-name
  kind: label
  location: "Monitors\\<name> subkey name"
  encoding: utf-16le
  note: "The port monitor name. Stock names ('Standard TCP/IP Port', 'BJ Language Monitor', 'Local Port', 'USB Monitor', 'WSD Port') are well-known. Attacker names are sometimes fanciful ('System Monitor', 'Windows Update Monitor') to look plausible at a glance — cross-reference every entry against the documented in-box set."
- name: key-last-write
  kind: timestamp
  location: "Monitors\\<name> subkey metadata"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on the monitor's subkey reflects registration time. A LastWrite outside printer-driver-install windows = drive-by persistence write. Correlate with System-7045 (service registration — spooler restart after monitor add) and Security-4697 / Security-4688 (AddMonitor API call evidence)."
- name: port-inventory
  kind: identifier
  location: "Monitors\\<name>\\Ports subkey (optional)"
  note: "Some monitors enumerate their configured ports here. Not persistence-critical but useful to understand what endpoints the monitor advertises."
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'Port monitor DLL hijack (MITRE T1547.010) is one of the highest-
    privilege persistence mechanisms on Windows because spoolsv.exe
    runs as LOCAL SYSTEM and starts on boot. A single registry write
    under Print\\Monitors followed by Print Spooler restart loads the
    attacker DLL into SYSTEM context at the next reboot or service
    restart. Because Print Spooler service is enabled by default on
    most Windows installs (yes, still, despite PrintNightmare
    hardening), this is a reliable boot-persistence path. Under-
    inspected by Autoruns sweeps that focus on more-common Run keys.'
  qualifier-map:
    setting.registry-path: "Control\\Print\\Monitors\\<name>\\Driver"
    setting.dll: field:driver-dll
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none; driver DLL is not signature-validated by Print Spooler
  known-cleaners:
  - tool: AddMonitor / DeleteMonitor API or direct registry delete
    typically-removes: the registration (DLL file on disk remains unless separately deleted)
  survival-signals:
  - Monitors\<name>\Driver pointing to a DLL outside System32 = candidate hijack
  - Monitor-name not matching Microsoft in-box set and not matching a documented printer vendor = candidate plant
  - Print Spooler service restart event in System-7036 coinciding with LastWrite on a new Monitors subkey = plant-then-reload pattern
  - MITRE technique T1547.010 ATT&CK coverage references this specific registry path
provenance:
  - ms-print-spooler-port-monitor-architec
  - mitre-t1547-010
---

# Port Monitors (Print Spooler)

## Forensic value
`HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver` points to a DLL loaded into `spoolsv.exe` on Print Spooler service startup. Since spoolsv.exe runs as LOCAL SYSTEM and starts on boot, an attacker-registered port monitor gets SYSTEM-privileged boot persistence.

## Why this beats most other persistence
- **SYSTEM privilege** (not user, not admin — SYSTEM)
- **Starts on boot** via Print Spooler service
- **Print Spooler runs by default** on most Windows installs (disabling it mitigates PrintNightmare CVE-2021-34527, but many enterprises have it on for business continuity)
- **Under-checked** — Autoruns sweeps focus on Run keys and services; Print\\Monitors rarely appears in common playbooks

## Stock baseline (Windows 10/11)
Expected Monitor subkeys with DLLs in `%SystemRoot%\System32\`:
- `Standard TCP/IP Port` → tcpmon.dll
- `Local Port` → localspl.dll
- `USB Monitor` → usbmon.dll
- `WSD Port` → WSDMon.dll
- `BJ Language Monitor` (some builds) → BJMon.dll

Third-party printer drivers legitimately add monitors (Canon, HP, Brother often do). The forensic question is always "does this Driver path match a known legitimate printer driver install, a documented enterprise deployment, or is it unexplained?"

## Concept reference
- ExecutablePath (per registered Driver DLL)

## Triage
```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors" /s
```

For each monitor subkey, validate:
1. Driver DLL path is in System32 or a documented printer vendor's directory
2. Driver DLL is signed (for Microsoft monitors: signed by Microsoft Windows Publisher)
3. Monitor name matches known set OR matches installed printer-vendor software

## Cross-reference
- `System-7036` — Print Spooler service start/stop events (every persistence reload)
- `Security-4697` — service install events (if attacker's plant included a companion service)
- `Security-4688` — spoolsv.exe child processes (may reveal loaded DLL effects)
- `Sysmon-7` — ImageLoad of the port monitor DLL into spoolsv.exe on boot

## Practice hint
On a lab VM (elevated PowerShell):
```powershell
# Inspect current monitor registrations
Get-PrinterPort | Where-Object { $_.MonitorName } | Format-List MonitorName, PortMonitor
# OR registry-direct
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors" | ForEach-Object {
    [PSCustomObject]@{
        Monitor = $_.PSChildName
        Driver = (Get-ItemProperty $_.PSPath).Driver
    }
}
```
Compare against a second clean VM — any deltas not tied to an installed printer = follow up.
