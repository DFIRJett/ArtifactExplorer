---
name: Winlogon-Userinit-Shell
aliases:
- Winlogon persistence
- Userinit
- Shell value
- logon init
link: persistence
tags: []
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: NT4
    max: '11'
location:
  hive: SOFTWARE
  path: Microsoft\Windows NT\CurrentVersion\Winlogon
  addressing: hive+key-path
fields:
- name: userinit
  kind: path
  location: Userinit value
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: comma-separated list of executables run AFTER logon; default is 'C:\Windows\system32\userinit.exe,'
- name: shell
  kind: path
  location: Shell value
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: the shell process launched for a user; default is 'explorer.exe'
- name: key-last-write
  kind: timestamp
  location: Winlogon key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'Winlogon Userinit value runs on every logon (elevated context). Shell

    value controls which shell launches per user. Classic persistence

    vectors with highly-privileged execution context (Userinit runs as

    the logging-on user BUT typically as admin for standard users).

    '
  qualifier-map:
    setting: Winlogon\Userinit OR Winlogon\Shell
    value: field:userinit OR field:shell
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  survival-signals:
  - Userinit value with additional entries beyond 'userinit.exe,' = persistence added
  - Shell value != 'explorer.exe' = shell hijacked — investigate
provenance:
  - ms-winlogon-registry-entries
  - mitre-t1547-004
---

# Winlogon Userinit / Shell

## Forensic value
Two of the oldest persistence mechanisms on Windows:
- **Userinit** — comma-separated executables launched at user logon (before desktop shell). Default: `userinit.exe,`.
- **Shell** — the shell process for the user session. Default: `explorer.exe`.

Modifying either to add or substitute an attacker binary causes that binary to run on every logon. Ancient but still seen, particularly in older corporate environments and by less-sophisticated malware.

## Concept reference
- ExecutablePath (Userinit + Shell values)

## Quick triage
```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /v Shell
```
- `Userinit` should be exactly `C:\Windows\system32\userinit.exe,` (trailing comma normal)
- `Shell` should be exactly `explorer.exe`
- Any other value = investigate
