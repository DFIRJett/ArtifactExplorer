---
name: PSReadline-history
aliases:
- PSReadLine history
- ConsoleHost_history.txt
link: application
tags:
- per-user
- tamper-easy
volatility: persistent
interaction-required: user-action
substrate: windows-text-log
substrate-instance: ConsoleHost_history.txt
platform:
  windows:
    min: '10'
    max: '11'
    note: PSReadLine module required — built-in on 10+
location:
  path: '%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
  addressing: line-per-command
fields:
- name: command-line
  kind: identifier
  location: log line (one command per line)
  encoding: utf-8
  references-data:
  - concept: UserSID
    role: profileOwner
  note: the verbatim PowerShell command line the user typed
- name: line-ordinal
  kind: counter
  location: line-number within file
  encoding: integer
  note: approximates chronological order; file grows append-only until 4096-line rollover
- name: file-mtime
  kind: timestamp
  location: filesystem metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: individual commands lack timestamps — file mtime is the ONLY temporal anchor (last command's approximate time)
observations:
- proposition: EXECUTED
  ceiling: C2
  note: 'Per-user plaintext log of PowerShell commands typed in the console.

    No per-command timestamps, no execution-success confirmation — just

    the verbatim text of what was typed. Limited as sole evidence but

    valuable as narrative: reveals WHAT the user was doing, even when

    timestamps are missing.

    '
  qualifier-map:
    process.image: powershell.exe / pwsh.exe
    process.command-line: field:command-line
    actor.user: '%APPDATA% owner'
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: manual delete of ConsoleHost_history.txt
    typically-removes: full
  - tool: Set-PSReadLineOption -HistorySaveStyle SaveNothing
    typically-removes: prospective
  - tool: Clear-History
    typically-removes: session-only — does NOT affect file
  survival-signals:
  - PSReadline-history absent on an otherwise-active user profile = deliberate cleanup
  - PSReadline lines contain explicit Invoke-Expression / IEX + base64 blobs = attack indicator
provenance: [canary-2022-powershell-profile-persistence, mitre-t1059, mitre-t1059-001, ms-powershell-operational]
---

# PSReadLine ConsoleHost History

## Forensic value
Per-user plaintext log of EVERY PowerShell command ever typed in a PSReadLine-enabled session. No opt-in required on Windows 10+; it's on by default. Lives under the user's AppData\Roaming.

Unique value: captures commands the user typed even when the SESSION failed or the commands had syntax errors. Sees typos, aborted commands, command history even when more formal logging (4104) was off.

## No per-command timestamps is the catch
The file is append-only text — each line = one command. Individual commands have no per-line timestamps. The file's last-modified time is your only temporal anchor (and only for the most recent command).

## Anti-forensic caveats
Trivially deletable. User-editable. Should be treated as corroborative evidence, not standalone. Cross-reference with:
- Security-4688 / Sysmon-1 for actual process executions
- PowerShell-4104 for decoded script-block content of those executions

## Practice hint
Open PowerShell, type a few commands, close the window. Inspect `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`. Each line is one command. Note the file's mtime is updated on each command save, but the individual lines are undated.
