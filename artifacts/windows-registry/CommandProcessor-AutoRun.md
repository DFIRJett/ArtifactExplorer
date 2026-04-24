---
name: CommandProcessor-AutoRun
title-description: "Command Processor AutoRun (HKLM / HKCU) — command-line executed on every cmd.exe start"
aliases:
- cmd.exe AutoRun
- Command Processor AutoRun
link: persistence
tags:
- persistence-primary
- living-off-the-land
- itm:PR
volatility: persistent
interaction-required: user-session
substrate: windows-registry-hive
substrate-instance: SOFTWARE and NTUSER.DAT
platform:
  windows:
    min: NT5.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SOFTWARE (HKLM) and NTUSER.DAT (HKCU)
  path-machine: "Microsoft\\Command Processor\\AutoRun"
  path-user: "Software\\Microsoft\\Command Processor\\AutoRun"
  addressing: hive+key-path+value
  note: "A REG_SZ (or REG_EXPAND_SZ) string value that cmd.exe executes automatically every time it starts — unless invoked with /D to suppress AutoRun processing. Both HKLM and HKCU paths are honored; HKCU takes precedence if both are set. Cmd is invoked by scripts, scheduled tasks, Group Policy, and many administrative tools — this is a HIGH-frequency trigger."
fields:
- name: autorun-command
  kind: content
  location: "Command Processor\\AutoRun value data"
  type: REG_SZ / REG_EXPAND_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Full command line run at every cmd.exe start. Any command / script / binary invocation here is effectively invoked once per cmd.exe launch. Attackers commonly set this to a PowerShell one-liner ('powershell -w hidden -enc ...') or a path to a dropper .bat."
- name: hive-scope
  kind: label
  location: "HKLM vs HKCU"
  references-data:
  - concept: RegistryKeyPath
    role: subjectKey
  note: "HKLM AutoRun fires for every user's cmd.exe; HKCU fires only for the current user but can be set without admin. HKCU is more stealthy for an unprivileged attacker who wants persistence in their own session."
- name: key-last-write
  kind: timestamp
  location: "Command Processor key metadata"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on the Command Processor key moves when AutoRun is added / modified. Pair with Security-4688 / Sysmon-1 to catch the write process."
- name: disabled-flag
  kind: flags
  location: "Command Processor\\EnableExtensions / DisableUNCCheck / DefaultColor values"
  type: REG_DWORD
  note: "Sibling values under Command Processor control other cmd.exe behaviors. Not themselves persistence but edits to this key (other than standard defaults) signal the key has been deliberately touched — worth baseline-comparing the whole key rather than only AutoRun."
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'AutoRun is one of the simplest and most reliable persistence
    mechanisms on Windows. A single REG_SZ write causes an arbitrary
    command to run every time cmd.exe starts. cmd.exe starts
    constantly: every .bat invocation, every scheduled task that
    wraps a command, every "Run" → cmd, every Group Policy startup
    script that calls cmd, every admin script. For a low-skill
    attacker with HKCU write (no admin needed), HKCU\\Software\\
    Microsoft\\Command Processor\\AutoRun is one of the fastest
    persistence plants available.'
  qualifier-map:
    setting.registry-path: "Microsoft\\Command Processor\\AutoRun"
    setting.command: field:autorun-command
    time.start: field:key-last-write
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: none
  known-cleaners:
  - tool: reg delete of the AutoRun value
    typically-removes: the hook (but key LastWrite remains as historical evidence of the prior write)
  survival-signals:
  - HKCU\...\Command Processor\AutoRun populated on a user who doesn't use cmd.exe professionally = opportunistic persistence plant
  - AutoRun value pointing to powershell.exe with -enc / -nop / -w hidden = classic encoded attacker payload
  - Execution evidence (Security-4688 of the AutoRun'd command) every time cmd.exe runs = confirmed active hook
provenance:
  - ms-cmd-exe-d-switch-and-autorun-regist
  - mitre-t1546
---

# Command Processor AutoRun

## Forensic value
A single value under `HKLM\Software\Microsoft\Command Processor\AutoRun` (or HKCU\...) is executed by cmd.exe automatically on every invocation. Because cmd.exe runs constantly in normal Windows operation (batch scripts, scheduled tasks, GPO, admin tooling), an AutoRun value is effectively a "fire on any cmd.exe start" persistence trigger.

Two scopes:
- **HKLM** — machine-wide (admin required; fires for every user's cmd)
- **HKCU** — per-user (user-writable; fires only for that user; HKCU wins if both are set)

cmd.exe can be invoked with `/D` to suppress AutoRun processing — but almost nothing in the wild does this, so AutoRun essentially always fires.

## Why low-skill attackers love this
- Single registry write, no file drop (payload can be inline PowerShell)
- No admin required for HKCU variant
- Standard Windows feature, not flagged by default
- Surviving Autoruns.exe and Sysmon baselines if the analyst doesn't check it
- Inherits whatever privilege context cmd is running in — elevated admin script = elevated AutoRun

## Concept reference
- ExecutablePath (if AutoRun points to or launches an external binary)

## Triage
```cmd
reg query "HKLM\Software\Microsoft\Command Processor" /v AutoRun
reg query "HKCU\Software\Microsoft\Command Processor" /v AutoRun
```

A populated AutoRun value that isn't part of a documented deployment (some enterprise environments legitimately set it for logon banners or environment customization) = suspicious. Pair with Security-4688 / Sysmon-1 for the AutoRun'd command's execution evidence.

## Practice hint
On a test VM: `reg add "HKCU\Software\Microsoft\Command Processor" /v AutoRun /t REG_SZ /d "echo AUTORUN FIRED"`. Open a fresh cmd prompt — observe the echoed text appear before the prompt arrives. That's the trigger the attacker relies on. Set the same in HKLM (elevated) and confirm it fires in every user's cmd. Remove via `reg delete`.
