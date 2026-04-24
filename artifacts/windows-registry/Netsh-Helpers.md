---
name: Netsh-Helpers
title-description: "Netsh helper DLLs (HKLM\\Software\\Microsoft\\Netsh) — loaded into netsh.exe on every invocation"
aliases:
- Netsh helper DLLs
- Netsh Helper key
- netsh extension DLLs
link: persistence
tags:
- persistence-primary
- living-off-the-land
- itm:PR
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: NT5.1
    max: '11'
  windows-server:
    min: '2003'
    max: '2022'
location:
  hive: SOFTWARE (HKLM)
  path: "Microsoft\\Netsh"
  addressing: hive+key-path
  note: "Each REG_SZ value under this key maps a 'helper name' (value name) to a DLL path (value data). netsh.exe loads ALL registered helpers when it starts, regardless of which context the user is invoking. Any DLL path here is effectively a load-on-netsh-execute persistence, triggered whenever netsh.exe runs — and netsh runs constantly during normal Windows operation (scripting, GPO processing, diagnostic scripts)."
fields:
- name: helper-dll-path
  kind: path
  location: "Microsoft\\Netsh\\<helper-name> value data"
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "DLL loaded into netsh.exe. Legitimate helpers ship from Microsoft: wlancfg, ifmon, p2pnetsh, nshhttp, etc. — all in %SystemRoot%\\System32\\. A path outside System32 or a name not matching a stock helper = persistence plant."
- name: helper-name
  kind: label
  location: "Microsoft\\Netsh\\<helper-name> value NAME"
  references-data:
  - concept: RegistryKeyPath
    role: subjectKey
  note: "The value NAME is the helper's context name ('wlancfg' → netsh wlan ...). Stock set on Win10/11 is well-known; Autoruns and AutorunsC enumerate all registered helpers alongside their DLL signing state."
- name: key-last-write
  kind: timestamp
  location: "Microsoft\\Netsh key metadata"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite timestamp — moves when a helper is added/removed. Correlate with System-7045 / Security-4697 or software install telemetry."
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'Netsh helper DLL persistence (MITRE T1546.007) is a classic
    living-off-the-land technique: netsh.exe is signed by Microsoft,
    present on every Windows install, and routinely invoked by both
    users and system scripts. An attacker-registered helper name +
    DLL path executes the attacker code in the signed netsh.exe
    process every time netsh runs. Low user-visible footprint,
    trivial to implement, and survives reboot because it''s a
    registry config not a service.'
  qualifier-map:
    setting.registry-path: "Microsoft\\Netsh"
    setting.dll: field:helper-dll-path
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none (the DLL itself may or may not be signed; registration doesn't care)
  survival-signals:
  - Helper-dll-path outside %SystemRoot%\System32 = non-stock helper
  - Helper-name not matching any documented Microsoft netsh context = fabricated registration
  - Microsoft\Netsh LastWrite without a corresponding installer event = drive-by persistence write
provenance:
  - mitre-t1546-007
  - ms-netsh-helper-architecture-and-exten
---

# Netsh Helper DLLs

## Forensic value
`HKLM\SOFTWARE\Microsoft\Netsh` holds a list of name → DLL-path pairs. Every `netsh.exe` invocation loads ALL registered helpers at startup, independent of which netsh context the invocation targets. An attacker-registered helper executes the attacker DLL inside the Microsoft-signed netsh.exe process, providing quiet persistence with a trigger (netsh execution) that fires routinely:

- Group Policy processing invokes netsh internally
- Admin scripts use `netsh advfirewall`, `netsh wlan`, etc.
- Diagnostic / troubleshooting tools run netsh
- End users run netsh from a cmd prompt

This is a canonical living-off-the-land persistence path.

## Stock helper baseline (Windows 10/11)
Typical entries (all pointing to `%SystemRoot%\System32\`):
- `wlancfg` → wlancfg.dll
- `ifmon` → ifmon.dll
- `nshhttp` → nshhttp.dll
- `p2pnetsh` → p2pnetsh.dll
- `hnetmon` → hnetmon.dll
- `authfwcfg` → authfwcfg.dll
- `wcncsvc` → wcnnetsh.dll
- (plus ~10 more depending on feature set)

Each stock helper has a well-known name and sits in System32. A non-System32 path or a helper name outside the documented Microsoft set = candidate hijack.

## Concept reference
- ExecutablePath (one per registered helper DLL)

## Triage
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Netsh"
```

For each value: compare name against the known Microsoft netsh contexts. For each path: verify the DLL exists in System32, is signed by Microsoft, and matches expected file version. Delta = follow up.

## Execution evidence
Netsh helper hijack typically also leaves:
- Prefetch entry for netsh.exe (+ the helper DLL appearing in the prefetch file's loaded-modules list)
- Security-4688 for netsh.exe with unusual parent / command-line
- Sysmon event 7 (ImageLoad) for the helper DLL into netsh.exe

Pair registry check with any of the above to tighten the timeline.

## Practice hint
On a test VM (elevated): `reg add HKLM\SOFTWARE\Microsoft\Netsh /v demo /t REG_SZ /d C:\test\demo.dll`. The DLL doesn't need to exist for the registration to stick. Run `netsh` and observe the load-error traceback in Event Viewer — proof the entry IS consulted on every netsh start. Delete the registration when done.
