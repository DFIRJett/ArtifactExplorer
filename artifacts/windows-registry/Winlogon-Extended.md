---
name: Winlogon-Extended
title-description: "Extended Winlogon persistence values (AppSetup / GPExtensions / Notify / System / Taskman / UiHost / VMApplet / AvailableShells)"
aliases:
- Winlogon Notify
- Winlogon AppSetup
- Winlogon GinaDLL
link: persistence
tags:
- persistence-primary
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: NT3.1
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SOFTWARE
  path: Microsoft\Windows NT\CurrentVersion\Winlogon (and \Winlogon\Notify subkey)
  addressing: hive+key-path
fields:
- name: app-setup
  kind: path
  location: AppSetup value
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "command line run by Winlogon during one-time post-install setup. Should be empty on any normal post-setup system. Populated = persistence that runs once on next boot with SYSTEM privilege."
- name: gp-extensions
  kind: path
  location: "GPExtensions\\<GUID>\\DllName values"
  type: REG_EXPAND_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Group Policy Client-Side Extensions. Each sub-GUID registers a DLL that runs during policy processing. Attackers add a GUID with an attacker DLL to get SYSTEM execution whenever policy refreshes (every 90 min by default)."
- name: gina-dll
  kind: path
  location: GinaDLL value
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Pre-Vista GINA (Graphical Identification and Authentication) DLL. Replaced by Credential Providers on Vista+ but the value still honored on legacy/XP systems. Trojan GINA = complete credential interception."
- name: notify-packages
  kind: path
  location: "Notify\\<name>\\DllName values"
  type: REG_EXPAND_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Legacy Winlogon notification packages. Each sub-key registers a DLL that receives callbacks for logon/logoff/lock/unlock events. Classic NT4–XP persistence; still recognized on modern Windows if present."
- name: system
  kind: path
  location: System value
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "apps launched by Winlogon in SYSTEM context at user logon. Default: LsaIso.exe on systems with Credential Guard; empty otherwise. Any unexpected entry runs as SYSTEM during interactive-session setup."
- name: taskman
  kind: path
  location: Taskman value
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "replacement for taskmgr.exe (fires when user presses Ctrl+Shift+Esc). Normally unset = default taskmgr. Non-empty value = persistence triggered by user's Task Manager shortcut."
- name: ui-host
  kind: path
  location: UiHost value
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Winlogon UI screen application (Win10+). Default LogonUI.exe. Replacement = intercept login UI."
- name: vm-applet
  kind: path
  location: VMApplet value
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Virtual memory applet (rundll32 + sysdm.cpl historically). Deprecated but still honored. Replacement = execution on VM applet launch."
- name: available-shells
  kind: path
  location: AvailableShells subkey values
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "alternative shell candidates. Winlogon consults this list if the primary Shell value is unavailable. Adding an entry here is a secondary-path persistence for shell hijack — fires only when explorer.exe can't launch."
- name: key-last-write
  kind: timestamp
  location: Winlogon key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'The Winlogon subkey is one of the oldest and richest persistence
    surfaces on Windows. This artifact covers the 9 values that the
    companion Winlogon-Userinit-Shell artifact does NOT — specifically
    the auxiliary hooks (AppSetup, Notify, GPExtensions, GinaDLL, System,
    Taskman, UiHost, VMApplet, AvailableShells). Different entries fire
    at different logon-flow points; no single user-logon sequence touches
    all of them, but an attacker with admin can place persistence at any
    point.'
  qualifier-map:
    setting.registry-path: Winlogon\<value>
    setting.binary: field:system
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  survival-signals:
  - AppSetup non-empty on a system months past install = persistence
  - Notify subkey contents on Win8+ = suspicious (feature largely retired)
  - GinaDLL non-empty on Vista+ = legacy persistence sitting in modern Windows
  - GPExtensions with non-Microsoft DllName values = GP-CSE persistence
  - Taskman / UiHost / VMApplet populated = user-action-triggered persistence
provenance: [ms-winlogon-registry-entries, mitre-t1547-004, carvey-2022-windows-forensic-analysis-tool]
---

# Winlogon (Extended)

## Forensic value
Complements `Winlogon-Userinit-Shell` (which covers the two most-common values — `Userinit` and `Shell`). This artifact covers the other 9 values in the `Winlogon` subkey, each of which can be weaponized for persistence:

- `AppSetup` — one-shot post-install
- `GPExtensions\<GUID>\DllName` — policy-refresh hook
- `GinaDLL` — legacy login UI replacement
- `Notify\<name>\DllName` — logon/logoff notification DLL
- `System` — SYSTEM-context logon launch
- `Taskman` — Task Manager replacement
- `UiHost` — LogonUI replacement
- `VMApplet` — legacy VM settings applet
- `AvailableShells\<n>` — fallback shell candidates

Each has its own trigger condition — together they provide an attacker with many different "when this happens, run my code" entry points.

## Concept reference
- ExecutablePath (one or more per value)

## Triage
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions" /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AvailableShells" /s
```

Baseline for most values on Vista+: empty or pointing to `%SystemRoot%\system32\*.dll` (LogonUI.exe, etc.). Any value pointing outside `%SystemRoot%` or named with non-Microsoft naming conventions warrants investigation.
