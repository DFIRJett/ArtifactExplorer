---
name: Active-Setup
title-description: "Active Setup — run-once-per-user command invoked by userinit.exe on first logon after stub change"
aliases:
- Active Setup Installed Components
- Active Setup StubPath
- run-once-per-user persistence
link: persistence
tags:
- persistence-primary
- per-user-trigger
- itm:PR
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: NT5.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SOFTWARE (HKLM) — canonical installed-components list
  path-machine: "Microsoft\\Active Setup\\Installed Components\\<GUID>"
  hive-check: NTUSER.DAT (HKCU) — per-user 'last-executed' tracking
  path-user: "Software\\Microsoft\\Active Setup\\Installed Components\\<GUID>"
  addressing: hive+key-path
  note: "Two-part mechanism. HKLM subkey holds the component definition + StubPath command. HKCU mirror subkey holds the last-executed-version for that user. When a user logs on, userinit.exe compares each HKLM component's Version against the user's HKCU Version; mismatch or missing HKCU entry → StubPath executes in the user's security context. Attacker-authored components fire on every new user logon and on the next logon of existing users who lack a matching HKCU entry."
fields:
- name: stub-path
  kind: content
  location: "Installed Components\\<GUID>\\StubPath value"
  type: REG_SZ / REG_EXPAND_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Command line executed by userinit.exe at logon trigger. Stock Microsoft Active Setup components reference signed Microsoft binaries under %SystemRoot% (ie4uinit.exe, themeui.exe). A StubPath pointing to rundll32.exe with an attacker DLL argument, or to a non-Microsoft binary, or to a script-interpreter + inline command = textbook attacker plant."
- name: component-name
  kind: label
  location: "Installed Components\\<GUID>\\(Default) value"
  type: REG_SZ
  note: "Human-readable component name. Stock components have descriptive names ('Internet Explorer Components', 'Windows Media Player', 'Themes Setup'). Attacker components sometimes have blank or generic Default values — worth checking against a baseline."
- name: version
  kind: label
  location: "Installed Components\\<GUID>\\Version value"
  type: REG_SZ
  note: "Dotted version string ('1,0,0,0' for legacy format or '1,0' newer). userinit compares HKLM.Version > HKCU.Version to decide whether StubPath fires. Incrementing this value in HKLM (attacker technique) forces the StubPath to re-fire for every user — including those who previously completed the component."
- name: is-installed
  kind: flags
  location: "Installed Components\\<GUID>\\IsInstalled value"
  type: REG_DWORD
  note: "1 = active (process StubPath); 0 = inactive (skip). Stock components typically have IsInstalled=1. Setting IsInstalled=0 is a way to suppress execution without deleting the registration."
- name: key-last-write
  kind: timestamp
  location: "Installed Components\\<GUID> key metadata"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on a component's subkey reflects registration or version-bump time. A fresh LastWrite not corresponding to a Windows feature install or OS update = drive-by plant."
- name: hkcu-version-marker
  kind: label
  location: "HKCU\\Software\\Microsoft\\Active Setup\\Installed Components\\<GUID>\\Version"
  references-data:
  - concept: RegistryKeyPath
    role: subjectKey
  note: "Per-user 'last executed' stamp. Compare against HKLM.Version — if HKLM is newer (or HKCU entry missing), StubPath fires at next logon. For forensics, the ABSENCE of this value under a given user's NTUSER.DAT means that user has NOT yet received the component's StubPath execution."
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'Active Setup is a per-user-triggered persistence mechanism
    (MITRE T1547.014) distinct from Run / RunOnce: the trigger is
    any user logon where HKCU.Version lags HKLM.Version. Attacker
    plants one HKLM component (admin-required) and achieves
    execution in EVERY user session on the box — current users at
    their next logon, and every newly-created user forever. Runs in
    the logging-on user''s security context, invoked by userinit.exe
    which is a trusted Windows login component. Under-inspected
    because Active Setup is often considered "legacy IE deployment"
    — but the mechanism is alive and fires on every modern Windows
    install.'
  qualifier-map:
    setting.registry-path: "Microsoft\\Active Setup\\Installed Components\\<GUID>\\StubPath"
    setting.command: field:stub-path
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  survival-signals:
  - Active Setup component <GUID> present in HKLM with StubPath pointing to non-Microsoft binary = candidate plant
  - StubPath invoking rundll32 / regsvr32 / mshta / wscript / cscript with URL or path argument = script-launcher persistence
  - HKLM component's Version value has been incremented above the HKCU value for all users = force-refire pattern (attacker wants previously-persistent users to re-execute)
  - KEY LastWrite recent and no Windows-Update / feature-install event in corresponding window = drive-by registration
provenance:
  - ms-active-setup-internet-explorer-depl
  - mitre-t1547-014
---

# Active Setup (run-once-per-user)

## Forensic value
Active Setup is userinit.exe's per-user-trigger mechanism. At every interactive logon, userinit enumerates HKLM components under:

`HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\<GUID>`

For each component, it compares the HKLM `Version` against the user's HKCU `Version`:

`HKCU\Software\Microsoft\Active Setup\Installed Components\<GUID>`

If HKLM > HKCU (or HKCU missing), userinit executes the HKLM `StubPath` value in the user's security context, then writes HKLM's Version to HKCU.

**Result**: any component registered in HKLM fires once per user. New user → fires. Existing user with no HKCU entry → fires. Existing user whose HKCU Version is stale → fires.

## Attack pattern (MITRE T1547.014)
1. Register a new `<GUID>` subkey in HKLM with StubPath pointing at attacker command
2. Do nothing else — wait for the next user logon
3. Every user logon going forward triggers the StubPath in that user's context
4. Persistence survives user-profile rebuilds (HKCU will be absent → re-fires)
5. Optionally bump HKLM Version to re-fire on users who already executed once

## Stock baseline
Typical Windows 10/11 HKLM components (in-box):
- `{2C7339CF-2B09-4501-B3F3-F3508C9228ED}` — Theme Component
- `{6BF52A52-394A-11D3-B153-00C04F79FAA6}` — Microsoft Windows Media Player
- `{8B9C1C61-2EAC-4C2B-8C78-3F2F7F3ED78D}` — Internet Explorer Core Fonts
- Several others signed by Microsoft

The stock set is well-known. A GUID not in the documented set, with a StubPath outside %SystemRoot%, is a candidate.

## Concept reference
- ExecutablePath (per StubPath command)

## Triage
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s  :: per-user state
```

For each HKLM component:
- Validate StubPath binary against signing / known-good
- Compare GUID against Microsoft in-box list
- Note LastWrite against expected Windows-Update / install windows

## Cross-reference
- `Security-4688` — StubPath command execution at logon (new process creation)
- `Security-4624` type 2 — interactive logon that triggered Active Setup
- `Prefetch` — execution evidence of StubPath-invoked binaries
- `Amcache / InventoryApplicationFile` — executable metadata for binaries referenced by StubPath

## Practice hint
On a test VM (elevated):
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{00000000-0000-0000-0000-DFIRTEST1234}" /ve /d "DFIR Test Component" /f
reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{00000000-0000-0000-0000-DFIRTEST1234}" /v StubPath /t REG_SZ /d "cmd /c echo ACTIVE SETUP FIRED > C:\temp\active-setup-fired.txt" /f
reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{00000000-0000-0000-0000-DFIRTEST1234}" /v Version /t REG_SZ /d "1,0,0,0" /f
reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{00000000-0000-0000-0000-DFIRTEST1234}" /v IsInstalled /t REG_DWORD /d 1 /f
```
Log out and back in. Check `C:\temp\active-setup-fired.txt` — it exists. That's the trigger. Remove the test component when done.
