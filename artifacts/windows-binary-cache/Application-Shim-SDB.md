---
name: Application-Shim-SDB
title-description: "Application Compatibility Shim databases (.sdb) — custom shims applied via AppCompatFlags registry"
aliases:
- SDB files
- Custom shim databases
- Application Compatibility shims
- Shim Database persistence
link: persistence
tags:
- persistence-primary
- living-off-the-land
- itm:PR
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: Application-Shim-SDB
platform:
  windows:
    min: NT5.1
    max: '11'
    note: "Shim infrastructure exists on every Windows version since XP. Custom .sdb registration mechanism (sdbinst.exe) unchanged across releases. In-box shims ship in sysmain.sdb / drvmain.sdb; custom shims land in the Custom directory."
  windows-server:
    min: '2003'
    max: '2022'
location:
  path-custom: "%WINDIR%\\AppPatch\\Custom\\ and %WINDIR%\\AppPatch\\Custom\\Custom64\\"
  path-inbox: "%WINDIR%\\AppPatch\\sysmain.sdb and drvmain.sdb (Microsoft baseline — do not modify)"
  path-registered: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\ and \\InstalledSDB\\"
  addressing: file-path + registry-join
  note: "Shim installation is a two-part operation: (1) drop the .sdb file in %WINDIR%\\AppPatch\\Custom\\; (2) register it via sdbinst.exe which writes subkeys under AppCompatFlags\\Custom (maps target-executable-name → GUID) and AppCompatFlags\\InstalledSDB (maps GUID → SDB-file-path). BOTH the file AND the registry entries are required for the shim to fire. Checking either alone misses half the plant."
fields:
- name: sdb-file
  kind: path
  location: "%WINDIR%\\AppPatch\\Custom\\*.sdb"
  encoding: binary SDB format (reverse-engineered; community parsers handle it)
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "The shim database itself — a compiled collection of shim rules (pattern matches against executables plus actions to apply). Attacker shim databases typically contain a single entry: 'when <target>.exe runs, apply InjectDll / RedirectEXE / RedirectShortcut action pointing to attacker DLL/EXE'. sdb2xml (Python) parses the format; SDBExplorer (Willi Ballenthin) provides GUI inspection."
- name: target-executable
  kind: path
  location: "SDB INEXE_NAME tag inside the shim database"
  encoding: utf-16le
  note: "The executable NAME (not path) that triggers this shim. When any process with this name launches, the ApplicationCompatibilityEngine consults the registered SDB and applies its actions. Common persistence targets: commonly-executed binaries like iexplore.exe, explorer.exe, or attacker-renamed benign launches."
- name: shim-action
  kind: label
  location: "SDB ACTION tag inside the shim database"
  note: "The operation applied. Forensically interesting: InjectDll (load attacker DLL into target), RedirectEXE (replace target binary with attacker one), RedirectShortcut (hijack LNK targeting), NoExecute (deny execution — anti-forensics DoS). InjectDll is the classic persistence path."
- name: shim-guid
  kind: identifier
  location: "Registry HKLM\\...AppCompatFlags\\InstalledSDB\\{GUID}\\ (key name)"
  encoding: guid-string
  note: "GUID assigned at sdbinst time. Joins registry-side registration to the on-disk SDB file via the DatabasePath value under the same subkey."
- name: database-description
  kind: label
  location: "Registry HKLM\\...\\InstalledSDB\\{GUID}\\DatabaseDescription value"
  type: REG_SZ
  note: "Author-supplied description of the database. Legitimate in-box shims have descriptive text. Attacker SDBs frequently have blank, generic, or misleading descriptions — worth comparing against Microsoft shim descriptions."
- name: install-time
  kind: timestamp
  location: "Registry HKLM\\...\\InstalledSDB\\{GUID}\\DatabaseInstallTimeStamp value"
  type: REG_QWORD
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "Install time recorded by sdbinst at registration. Direct pivot — this IS the moment the shim persistence was planted."
- name: registry-mapping
  kind: identifier
  location: "Registry HKLM\\...\\AppCompatFlags\\Custom\\<target.exe>\\<GUID>.sdb value"
  type: REG_DWORD
  note: "Per-target-executable registration mapping. The presence of this value is what tells the shim engine 'apply <GUID>.sdb when <target.exe> launches'. Enumerate the Custom subkey to find all target-executables with custom shims applied."
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'Application Compatibility shim persistence (MITRE T1546.011) is
    a classic living-off-the-land technique: it uses legitimate
    Microsoft infrastructure (shim engine, sdbinst.exe signed by
    Microsoft) to load attacker code into legitimate processes. The
    shim engine is integrated into every process startup — every
    CreateProcess call triggers a check of the AppCompatFlags
    registry for matching shims. InjectDll shims load attacker code
    into normal applications with their process identity / privileges
    intact, making EDR detection harder. A correctly-acquired
    investigation must sweep BOTH the Custom directory on disk AND
    the AppCompatFlags\\Custom + InstalledSDB registry keys to catch
    shim plants.'
  qualifier-map:
    setting.file: field:sdb-file
    setting.target: field:target-executable
    time.start: field:install-time
anti-forensic:
  write-privilege: admin
  integrity-mechanism: "none on .sdb contents; sdbinst.exe is signed by Microsoft (the enabler, not a protection)"
  known-cleaners:
  - tool: sdbinst -u {GUID}
    typically-removes: both the registry registration and the Custom\\<GUID>.sdb file (clean uninstall)
  - tool: reg delete HKLM\...\Custom + del Custom\*.sdb
    typically-removes: manual removal — leaves hive mtime update and may leave orphan files
  survival-signals:
  - .sdb files in %WINDIR%\AppPatch\Custom\ that do not correspond to a known enterprise deployment (line-of-business app shim) = investigate
  - InstalledSDB GUID entries with blank DatabaseDescription and recent DatabaseInstallTimeStamp = drive-by shim plant
  - AppCompatFlags\Custom\<target.exe> mapping a custom SDB to a commonly-executed binary (explorer, iexplore, a widely-used vendor EXE) = persistence via high-frequency process
  - sdbinst.exe invocation in Security-4688 / Sysmon-1 with unusual parent process (powershell, cmd, wmic) = scripted shim install
provenance:
  - mitre-t1546-011
  - mandiant-2015-shim-me-the-way-application-co
  - ballenthin-2015-python-sdb-sdb-explorer-parsin
  - ms-application-compatibility-toolkit-s
---

# Application Compatibility Shim (SDB)

## Forensic value
Application Compatibility shims are a Windows feature that allows third parties (Microsoft, ISVs, enterprise IT) to compile small patch programs that modify runtime behavior of specific executables — e.g., faking an older OS version, redirecting file access, handling compatibility quirks. The shim engine consults a registered database every time a process starts. Matching shims load and execute.

Attackers weaponize this as persistence (MITRE T1546.011):

1. Author a `.sdb` with an `InjectDll` action targeting a common executable
2. Drop the file in `%WINDIR%\AppPatch\Custom\`
3. Register via `sdbinst.exe` → writes `AppCompatFlags\Custom` and `AppCompatFlags\InstalledSDB` registry entries
4. Every time the target executable runs, the attacker DLL loads into that process

The persistence is triggered by normal user / system activity (any process start of the targeted binary). The code runs in the target's process context with the target's privileges.

## Two halves of a shim plant
Correctly sweeping requires checking BOTH:

**On disk**:
- `%WINDIR%\AppPatch\Custom\*.sdb`
- `%WINDIR%\AppPatch\Custom\Custom64\*.sdb` (64-bit shims)

**In registry**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\<target.exe>\<GUID>.sdb`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\{GUID}\`

A plant without the registry entries is inert; registry entries without a matching on-disk SDB produce shim-engine errors in Application-1000 events. Both present = active persistence.

## Concept reference
- ExecutablePath (the target executable and the injected DLL referenced inside the SDB)

## Parsing SDB contents
```cmd
# Willi Ballenthin's sdb-dump
python sdb-dump.py %WINDIR%\AppPatch\Custom\<GUID>.sdb
```
Output includes: EXE-matching entries, action list, injected DLL paths, compatibility flags.

## Triage
```cmd
dir /a /t:w %WINDIR%\AppPatch\Custom\*.sdb
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom" /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" /s
```

Cross-reference each `InstalledSDB\{GUID}\DatabasePath` value against a file present in AppPatch\Custom\. Orphan in either direction = evidence of incomplete install or partial cleanup.

## Practice hint
On a test VM, use the free Compatibility Administrator tool (Windows SDK) to create a shim for `notepad.exe` with a harmless flag (e.g., DisableAdvancedRPCCalls). Install with `sdbinst -q <file>.sdb`. Observe the Custom subkey and InstalledSDB GUID. Run notepad — shim fires silently. Uninstall with `sdbinst -u {GUID}`. This is the exact plant-and-trigger flow attackers use, just with benign content.
