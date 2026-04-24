---
name: Screensaver-Hijack
title-description: "Screensaver SCRNSAVE.EXE registry — executable launched by Desktop Window Manager at inactivity threshold"
aliases:
- SCRNSAVE.EXE
- Screensaver persistence
- Control Panel Desktop screensaver
link: persistence
tags:
- persistence-primary
- user-idle-trigger
- itm:PR
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: NT3.1
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: NTUSER.DAT (HKCU)
  path: "Control Panel\\Desktop"
  addressing: hive+key-path
  note: "Four sibling values under Control Panel\\Desktop control the screensaver lifecycle: SCRNSAVE.EXE (path to the .scr to launch), ScreenSaveActive (enabled), ScreenSaverIsSecure (require password to exit — determines whether lockout applies), ScreenSaveTimeOut (idle seconds before trigger). An attacker with user-scope write (no admin) can set SCRNSAVE.EXE to any executable and the Desktop Window Manager will launch it as the screensaver at the configured timeout — user-context execution at a predictable trigger."
fields:
- name: screensaver-path
  kind: path
  location: "Control Panel\\Desktop\\SCRNSAVE.EXE value"
  type: REG_SZ / REG_EXPAND_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Path to the screensaver executable. Legitimate .scr files live in %SystemRoot%\\System32\\ (bubbles.scr, ribbons.scr, photoScreensaver.scr, etc.). Technically ANY executable works — Windows does not validate that the file is a true screensaver .scr. A path outside System32 or a non-.scr extension = hijack. Common attacker pattern is to point this at a renamed .exe for user-scope persistence that fires automatically after N minutes of idle."
- name: screensaver-active
  kind: flags
  location: "Control Panel\\Desktop\\ScreenSaveActive value"
  type: REG_SZ (holding '0' or '1')
  note: "'1' = screensaver enabled; '0' = disabled. Set to '1' for the hijack to fire. Legitimate state varies per user preference."
- name: screensaver-timeout
  kind: counter
  location: "Control Panel\\Desktop\\ScreenSaveTimeOut value"
  type: REG_SZ (holding integer seconds)
  note: "Idle-time threshold in seconds before the screensaver launches. Default 900 (15 minutes). Attackers sometimes lower this (60 or 120) for faster trigger — anomalously low timeout value = signal."
- name: screensaver-is-secure
  kind: flags
  location: "Control Panel\\Desktop\\ScreenSaverIsSecure value"
  type: REG_SZ ('0' / '1')
  note: "'1' = exiting screensaver requires user password (lock); '0' = no lock. Attacker-set SCRNSAVE.EXE usually does not set IsSecure=1 because the goal is silent execution, not session lockout. Legitimate enterprise policy often sets IsSecure=1 via GPO."
- name: key-last-write
  kind: timestamp
  location: "Control Panel\\Desktop key metadata"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite updates on SCRNSAVE.EXE / ScreenSaveActive / timeout changes. Correlate with the user's logon session (Security-4624) and with any process-creation events writing these values."
- name: gpo-policy-scrnsave
  kind: path
  location: "HKCU\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\SCRNSAVE.EXE (GPO)"
  type: REG_SZ
  references-data:
  - concept: RegistryKeyPath
    role: subjectKey
  note: "Group-Policy-pushed screensaver path. When present, GPO wins over the user's Control Panel\\Desktop value — attackers who control GPO can enforce a screensaver hijack across all affected users. In domain environments, verify GPO-pushed SCRNSAVE.EXE alongside the user-scope value."
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'Screensaver hijack (MITRE T1546.002) is one of the cleanest
    user-scope persistence paths on Windows: single registry write (no
    admin needed), predictable trigger (N seconds of user idle),
    executes in the user''s security context. The target process is
    launched directly by Desktop Window Manager (not by Explorer),
    so it does not inherit a shell parent process — process-tree
    anomaly. Widely documented yet under-checked in standard sweeps
    because it is associated with "old Windows" — in fact the
    mechanism fires on every modern Windows build.'
  qualifier-map:
    setting.registry-path: "Control Panel\\Desktop\\SCRNSAVE.EXE"
    setting.dll: field:screensaver-path
    time.start: field:key-last-write
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  survival-signals:
  - SCRNSAVE.EXE pointing to a path outside %SystemRoot%\System32 = candidate hijack
  - SCRNSAVE.EXE path to a .exe (not .scr) extension = deliberate executable substitution
  - ScreenSaveTimeOut set to anomalously low value (< 120 seconds) on a user profile = fast-trigger plant
  - ScreenSaverIsSecure=0 with ScreenSaveActive=1 and custom SCRNSAVE.EXE = silent-execute-at-idle pattern
  - Process-creation evidence (Security-4688) of the custom SCRNSAVE.EXE path with parent=DWM / svchost = screensaver launch occurred
provenance:
  - ms-desktop-window-manager-screensaver
  - mitre-t1546-002
---

# Screensaver hijack (SCRNSAVE.EXE)

## Forensic value
Per-user screensaver configuration lives at `HKCU\Control Panel\Desktop`. Four values control the lifecycle:

- `SCRNSAVE.EXE` — path to the executable Desktop Window Manager launches at idle threshold
- `ScreenSaveActive` — `0` / `1` enable flag
- `ScreenSaveTimeOut` — idle seconds before launch (default 900)
- `ScreenSaverIsSecure` — lock on exit

Windows does NOT validate that SCRNSAVE.EXE points to a genuine `.scr` file or a signed binary. Any executable works. Combined with the fact that HKCU writes require no admin privileges, this is one of the cleanest user-scope persistence paths on Windows (MITRE T1546.002):

- User logs in → idle for N seconds → DWM launches SCRNSAVE.EXE in the user's security context
- Runs under the user's token, parented by DWM / svchost rather than Explorer (process-tree anomaly)
- No admin required to set up, survives reboot, triggers on predictable schedule

## Concept reference
- ExecutablePath (the SCRNSAVE.EXE path)

## Triage
```cmd
reg query "HKCU\Control Panel\Desktop" /v SCRNSAVE.EXE
reg query "HKCU\Control Panel\Desktop" /v ScreenSaveActive
reg query "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut
reg query "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure
```

Validate SCRNSAVE.EXE:
- Path is in `%SystemRoot%\System32\`
- Extension is `.scr`
- File is signed by Microsoft (for stock screensavers)
- Anything else = investigate

Also check GPO-pushed equivalents:
```cmd
reg query "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v SCRNSAVE.EXE
```

## Cross-reference
- `Security-4688` — process creation of SCRNSAVE.EXE target at trigger time (parent should be DWM/svchost)
- `Sysmon-1` — same, with more detail
- Prefetch entry for the custom SCRNSAVE.EXE target = execution occurred

## Practice hint
On a lab VM: open Registry Editor, navigate to `HKCU\Control Panel\Desktop`, change `SCRNSAVE.EXE` to `C:\Windows\System32\calc.exe`, set `ScreenSaveTimeOut` to `60`, `ScreenSaveActive` to `1`. Wait 60 seconds idle — calc.exe launches. Clear the hijack with `reg delete` or restore a known-good screensaver path.
