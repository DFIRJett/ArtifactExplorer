---
name: AeDebug
title-description: "Application Error Debugger (AeDebug) registry — auto-invoked debugger on process crash or WER escalation"
aliases:
- AeDebug
- Automatic Debugging key
- JIT debugger registration
- Postmortem debugger
link: persistence
tags:
- persistence-primary
- crash-trigger
- itm:PR
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: NT4.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SOFTWARE (HKLM)
  path-64bit: "Microsoft\\Windows NT\\CurrentVersion\\AeDebug"
  path-wow64: "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug"
  addressing: hive+key-path
  note: "Defines the Just-In-Time (JIT) debugger invoked by Windows Error Reporting when a process crashes. Both the native and WoW64 paths must be checked on 64-bit Windows. Populated by legitimate developer tooling (Visual Studio installs itself as AeDebug; WinDbg ships a registration command). On a production workstation with no dev tools installed, a populated AeDebug should not be present — and when it is, the registered Debugger command runs with the privileges of the crashing process."
fields:
- name: debugger-command
  kind: content
  location: "AeDebug\\Debugger value"
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Command line executed when WER triggers. Standard format contains %ld placeholders for PID and event handle. Legitimate Visual Studio entry: '\"C:\\WINDOWS\\system32\\vsjitdebugger.exe\" -p %ld -e %ld -j 0x%p'. Attacker-authored entries replace the binary path with a dropper or injector — the crash of ANY application triggers attacker-code execution in the crashing process's security context."
- name: auto-flag
  kind: flags
  location: "AeDebug\\Auto value"
  type: REG_DWORD or REG_SZ
  note: "0 = prompt user before launching debugger; 1 = launch automatically without prompt. Auto=1 combined with an attacker-Debugger value = silent on-crash trigger. Auto=0 only fires on user interaction with the WER prompt, reducing attack surface but still viable."
- name: key-last-write
  kind: timestamp
  location: AeDebug key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite updates when Debugger / Auto values are written. Baseline a clean Windows install (no dev tooling) → this key should be empty or absent; any populated AeDebug on such a host = investigate."
- name: sibling-image-file-execution-options
  kind: identifier
  location: "Windows NT\\CurrentVersion\\Image File Execution Options\\<process>.exe\\Debugger value"
  note: "Per-process debugger hijack — different mechanism, same concept. ImageFileExecutionOptions\\<process.exe>\\Debugger causes Windows to launch the specified debugger in place of the named process. Classic AccessibilityFeature / sticky-keys persistence (utilman.exe, sethc.exe). Sibling artifact worth checking alongside AeDebug."
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'AeDebug is a narrow-trigger but high-impact persistence. The
    trigger is "a process crashes" — which happens constantly in
    normal operation (Office, browsers, drivers). Each crash invokes
    the attacker-registered Debugger command with access to the
    crashing process''s memory and security token. Because AeDebug is
    not commonly checked by Autoruns sweep playbooks (it shows under
    "Misc" if at all), it is under-detected in real investigations.
    Pair this artifact with ImageFileExecutionOptions Debugger
    hijacks (per-process variant) for a complete debugger-persistence
    sweep.'
  qualifier-map:
    setting.registry-path: "Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\Debugger"
    setting.command: field:debugger-command
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none; WER does not validate that the Debugger path is signed
  survival-signals:
  - Populated AeDebug\Debugger on a host with no developer tools installed = plant
  - Debugger path outside %ProgramFiles%\...\VS\...\vsjitdebugger.exe and outside %SystemRoot% = candidate hijack
  - Auto=1 combined with non-Microsoft Debugger path = fully-automatic attacker trigger
  - Key LastWrite recent and no Visual Studio / Debugging Tools install event = drive-by write
provenance:
  - ms-configuring-automatic-debugging-aed
  - mitre-t1546-012
---

# AeDebug (automatic JIT debugger)

## Forensic value
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug` defines the Just-In-Time debugger Windows launches when a process crashes. Two key values:

- `Debugger` — the command line to invoke (with %ld placeholders for PID and event handle)
- `Auto` — 0 (prompt user) or 1 (launch without prompt)

The trigger is `WerFault.exe` handling an unhandled exception. An attacker-registered Debugger runs in the context of the crashing process — inheriting its token, memory access, and execution privileges. Because any application can crash, this is effectively an opportunistic persistence: the next time Office, Outlook, a browser, or a driver fault triggers WER, the attacker code runs.

## Dual paths on 64-bit Windows
Check BOTH:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug` (64-bit processes)
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug` (32-bit processes under WoW64)

A hijack targeting only 32-bit crashes would plant in the WoW6432Node variant.

## Concept reference
- ExecutablePath (the registered Debugger path)

## Triage
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug"
```

Validate Debugger against expected state:
- On a fresh Windows install with no dev tools: empty / absent
- With Visual Studio installed: points to `...vsjitdebugger.exe`
- With Debugging Tools for Windows installed: points to `...windbg.exe` or `...cdb.exe`
- Anything else: suspicious

## Related sweep
While at it, inspect `Image File Execution Options\<process>.exe\Debugger` for per-process Debugger hijacks (MITRE T1546.012) — the classic utilman.exe / sethc.exe / magnify.exe accessibility-feature hijack. Same concept, process-specific trigger.

## Practice hint
On a lab VM: `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v Debugger /t REG_SZ /d "cmd /c start calc.exe" /f` and set Auto=1. Then force a crash in a test process (e.g., drag an odd file into a known-vulnerable test app, or use `DebugBreak`). Observe calc.exe launching at the crash moment — proof the hook fires. Remove via `reg delete` when done.
