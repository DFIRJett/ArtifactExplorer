---
name: SilentProcessExit-Monitor
title-description: "SilentProcessExit IFEO sibling — attach a monitor process / dump on target process exit"
aliases: [SilentProcessExit, SPE, LSASS SPE persistence]
link: persistence
tags: [persistence-primary, credential-dump, lsass-targeting]
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows: {min: '7', max: '11'}
  windows-server: {min: '2008R2', max: '2022'}
location:
  hive: SOFTWARE (HKLM)
  path: "Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\<process-name>.exe"
  companion-ifeo: "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<process>.exe\\GlobalFlag = 0x200 (FLG_MONITOR_SILENT_PROCESS_EXIT)"
  addressing: hive+key-path
  note: "Sibling to IFEO. Enabled in two parts: (1) IFEO\\<target>.exe\\GlobalFlag = 0x200 (tells kernel to notify on silent exit of target), (2) SilentProcessExit\\<target>.exe subkey with ReportingMode + MonitorProcess values. When the target exits, the MonitorProcess is launched automatically. Canonical abuse: set MonitorProcess = procdump.exe with args to dump lsass.exe to disk; when attacker forces lsass exit (or normal shutdown triggers it), procdump auto-runs to capture credentials. MITRE T1546.012 variant distinct from classic IFEO\\Debugger hijack."
fields:
- name: monitor-process
  kind: path
  location: "SilentProcessExit\\<target>.exe\\MonitorProcess value"
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Full command line of the monitor to launch when target exits. Attacker-typical: 'C:\\\\Temp\\\\procdump.exe -ma lsass.exe C:\\\\Temp\\\\lsass.dmp' — LSASS credential-dump auto-trigger. Any MonitorProcess value pointing to procdump / comsvcs / custom-binary with lsass target = high-severity alert."
- name: reporting-mode
  kind: flags
  location: "SilentProcessExit\\<target>.exe\\ReportingMode value"
  type: REG_DWORD
  note: "Bitmask. 0x1 = enable SilentProcessExit handling. 0x2 = enable WER local dump (separate from Monitor). For attacker persistence, 0x1 is required."
- name: local-dump-folder
  kind: path
  location: "SilentProcessExit\\<target>.exe\\LocalDumpFolder value"
  type: REG_SZ
  note: "Optional output directory for built-in WER-style dump (bypasses MonitorProcess). Setting this + ReportingMode=0x2 causes Windows to dump the target's memory to disk on exit without running an attacker binary — stealth variant."
- name: target-ifeo-globalflag
  kind: flags
  location: "IFEO\\<target>.exe\\GlobalFlag value"
  type: REG_DWORD
  note: "REQUIRED companion — must be 0x200 (FLG_MONITOR_SILENT_PROCESS_EXIT) on the IFEO entry for the SilentProcessExit trigger to fire. Absence of this flag = SilentProcessExit subkey is inert."
- name: key-last-write
  kind: timestamp
  location: SilentProcessExit\\<target>.exe subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'SilentProcessExit persistence is a sibling of IFEO-Debugger hijack but distinct: triggered on PROCESS EXIT rather than process launch. The LSASS-credential-dump variant is well-documented (Outflank, MDSec, SpecterOps). Because the MonitorProcess runs as SYSTEM when the target is SYSTEM-owned (lsass), this is a SYSTEM-privileged credential-dump automation. Detection: SilentProcessExit subkey under any HKLM\\...\\CurrentVersion\\SilentProcessExit that targets lsass.exe OR a security-product process + MonitorProcess pointing to procdump / unsigned binary.'
  qualifier-map:
    setting.registry-path: "Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\<target>"
    setting.command: field:monitor-process
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  survival-signals:
  - SilentProcessExit subkey for lsass.exe with MonitorProcess pointing to procdump / rundll32 (comsvcs.dll MiniDump) / unsigned binary = LSASS-dump persistence
  - SilentProcessExit with LocalDumpFolder in a user-writable path + non-standard target = stealth credential capture
  - IFEO GlobalFlag=0x200 set on lsass.exe OR a security product's binary = SilentProcessExit trigger enabled
provenance:
  - ms-monitoring-silent-process-exit
  - mitre-t1546-012
---

# SilentProcessExit Monitor

## Forensic value
Sibling to IFEO Debugger persistence but fires on target PROCESS EXIT instead of launch. Two-key mechanism:

1. `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target>.exe\GlobalFlag = 0x200` (FLG_MONITOR_SILENT_PROCESS_EXIT)
2. `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<target>.exe\MonitorProcess = <command>`

When target exits → MonitorProcess auto-launches with target's context. For lsass.exe target, classic attacker move is MonitorProcess = procdump.exe -ma lsass.exe — SYSTEM-privileged LSASS credential dump on any shutdown.

## Triage
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v GlobalFlag | findstr /i "0x200"
```

Any output = investigate immediately. Legitimate use of SilentProcessExit is rare outside developer-debug scenarios.

## Cross-reference
- **ImageFileExecutionOptions** — sibling persistence (on-launch Debugger variant)
- **AeDebug** — similar concept (on-crash debugger)
- **DPAPI-MasterKeys** / **LSA-Cached-Logons** / **Kerberos-Tickets-Cache** — all extractable from the resulting lsass dump
