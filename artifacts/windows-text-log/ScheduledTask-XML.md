---
name: ScheduledTask-XML
title-description: "Scheduled Task XML definitions (System32\\Tasks\\) — richer view than registry Scheduled-Tasks"
aliases:
- Scheduled Task XML
- System32\\Tasks XML files
- Task Scheduler task definitions
link: persistence
tags:
- persistence-primary
- xml-artifact
- itm:PR
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: ScheduledTask-XML
platform:
  windows:
    min: Vista
    max: '11'
    note: "Vista introduced the XML-based Task Scheduler 2.0 format. Prior-Windows uses the .job binary format (System32\\Tasks\\*.job) — rare on modern hosts but may appear on heavily-upgraded systems."
  windows-server:
    min: '2008'
    max: '2022'
location:
  path: "%WINDIR%\\System32\\Tasks\\ (recursive; subdirectories mirror task folder hierarchy)"
  companion-registry: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree and \\Tasks (GUID-keyed)"
  addressing: file-path
  note: "Every registered Scheduled Task is a plain XML file at %WINDIR%\\System32\\Tasks\\<folder>\\<task-name> (NO file extension). Sibling registry entries under TaskCache keep a GUID index + per-task metadata. The XML is the AUTHORITATIVE definition — it holds the full trigger / action / principal configuration including fields that registry TaskCache does not preserve. This artifact is distinct from the existing Scheduled-Tasks registry-focused artifact and complements it by surfacing the XML-only fields."
fields:
- name: actions-exec-command
  kind: path
  location: "XML //Actions/Exec/Command element"
  encoding: utf-16le (XML)
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Executable path the task runs. For attacker-authored tasks, commonly points to cmd.exe / powershell.exe with an encoded-command argument in the sibling <Arguments> element. Also common: rundll32.exe invocations and direct script-interpreter calls (wscript, cscript, mshta)."
- name: actions-exec-arguments
  kind: content
  location: "XML //Actions/Exec/Arguments element"
  encoding: utf-16le (XML)
  note: "Command-line arguments. Attacker tasks routinely encode the payload here (PowerShell -enc <base64>, mshta javascript: URL, etc.). The registry TaskCache does NOT preserve full Arguments in a single accessible value — the XML is where the complete command-line lives."
- name: principals-user-id
  kind: identifier
  location: "XML //Principals/Principal/UserId element"
  encoding: utf-16le (account name or SID)
  note: "Account the task runs as. Tasks running as SYSTEM, LOCAL SERVICE, NETWORK SERVICE, or a specific domain-admin account are higher-privilege execution — always check Principal for each task. Attacker persistence tasks frequently specify SYSTEM for maximum impact."
- name: principals-runlevel
  kind: label
  location: "XML //Principals/Principal/RunLevel element"
  encoding: "'LeastPrivilege' or 'HighestAvailable'"
  note: "HighestAvailable = elevated (run with full admin token if the UserId supports it). LeastPrivilege = restricted. Attacker tasks almost always use HighestAvailable."
- name: triggers
  kind: content
  location: "XML //Triggers element (LogonTrigger, TimeTrigger, CalendarTrigger, BootTrigger, EventTrigger, IdleTrigger, RegistrationTrigger, SessionStateChangeTrigger)"
  encoding: utf-16le (XML)
  note: "The conditions that fire the task. BootTrigger + SYSTEM UserId = boot-persistence equivalent of a service. LogonTrigger + specific UserId = per-user-logon persistence. EventTrigger referencing a specific EVTX channel + event ID = rare but powerful (fires on arbitrary system events — e.g., on every Security-4624 of a target user)."
- name: registration-info-author
  kind: label
  location: "XML //RegistrationInfo/Author element"
  encoding: utf-16le (XML)
  note: "Author field recorded at task creation. Legitimate Microsoft-shipped tasks have 'Microsoft' or 'Microsoft Corporation'. Attacker-authored tasks frequently leave this blank, copy the Microsoft value to blend, or set it to a computer-name + account tuple (e.g., DESKTOP-ABC123\\user) — which directly reveals the creating account."
- name: registration-info-date
  kind: timestamp
  location: "XML //RegistrationInfo/Date element"
  encoding: xs:dateTime (ISO-8601)
  clock: system
  resolution: 1s
  note: "Task creation timestamp embedded in the XML. Joins with the XML file's NTFS mtime for cross-verification. Discrepancy between embedded Date and file mtime = potential tampering (Date is typically set at creation and not updated)."
- name: security-descriptor
  kind: flags
  location: "Sibling registry HKLM\\...\\TaskCache\\Tasks\\{GUID}\\SD value (REG_BINARY)"
  note: "Task's security descriptor lives in the sibling registry, NOT in the XML. Governs who can read/modify/delete the task. Attacker tasks sometimes have overly permissive or contradictory SDs — included here as a cross-reference note."
- name: file-mtime
  kind: timestamp
  location: XML file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime — updated on task modification (including UpdateExistingTask API). Comparison against the embedded RegistrationInfo/Date gives create-vs-modify visibility that registry TaskCache alone does not offer."
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'The XML file at %WINDIR%\\System32\\Tasks\\ is the AUTHORITATIVE
    definition of every Scheduled Task on the system and holds fields
    that are not equivalently accessible in the sibling registry
    TaskCache entries (full Arguments string, Author, exact Triggers
    XML). For DFIR, parsing these XMLs directly surfaces attacker
    tasks that blend into the registry view — an attacker task with
    a Microsoft-sounding name but unusual Arguments, or an
    anomalous Author, is obvious in XML and subtle in registry.
    Always parse the XMLs alongside TaskCache for full coverage.'
  qualifier-map:
    setting.file: field:actions-exec-command
    setting.command: field:actions-exec-arguments
    actor.user: field:principals-user-id
    time.start: field:registration-info-date
anti-forensic:
  write-privilege: admin
  integrity-mechanism: XML is plain text; no signing
  known-cleaners:
  - tool: schtasks /Delete or Unregister-ScheduledTask
    typically-removes: the XML file AND the TaskCache entry in one operation (clean uninstall)
  - tool: direct file deletion of the XML
    typically-removes: XML only — orphan registry TaskCache entry remains (signature of partial cleanup)
  survival-signals:
  - Task XML file present with no corresponding TaskCache registry entry (or vice versa) = partial cleanup — investigate
  - Task XML Author field = '<DOMAIN>\\<attacker-user>' = direct attribution if the account is otherwise unexplained
  - Arguments containing base64 / IEX / mshta javascript: / suspicious URLs = encoded payload
  - Triggers configuration that fires at unusual times (3am daily, specific event IDs on Security channel) = targeted persistence
  - Mismatch between RegistrationInfo/Date and XML file mtime > small delta = task has been modified (not just registered)
provenance:
  - ms-task-scheduler-2-0-xml-schema-refer
  - mitre-t1053-005
---

# Scheduled Task XML files

## Forensic value
Every Scheduled Task on a modern Windows host (Vista+) exists as a plain-XML file at:

`%WINDIR%\System32\Tasks\<folder>\<task-name>` (no file extension)

The file mirrors the folder hierarchy visible in Task Scheduler MMC (e.g., `\Microsoft\Windows\ApplicationData\appuriverifierdaily` lives at `%WINDIR%\System32\Tasks\Microsoft\Windows\ApplicationData\appuriverifierdaily`).

Companion registry metadata under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` and `\Tasks` indexes the tasks by GUID. The existing `Scheduled-Tasks` registry artifact covers the registry side. This artifact covers the XML side — which holds fields the registry version does not surface cleanly.

## Fields the XML holds that registry TaskCache doesn't
- **Full `Arguments` string** — TaskCache stores a marshalled blob; XML has clean text
- **`Author` field** — attribution evidence at task creation time
- **`RegistrationInfo/Date`** — embedded timestamp independent of file mtime
- **Full `Triggers` XML** — complex event-trigger conditions not easily inspectable from TaskCache
- **`Description` element** — free-text field attackers sometimes populate with misleading content

## Why you must parse both
Registry-only parsing misses:
- Attacker tasks whose full command-line is only in the XML
- Author attribution
- Date discrepancies (mtime vs. embedded Date)

XML-only parsing misses:
- Security descriptor (SD blob lives in registry)
- Last Run Time / Next Run Time (live values only in registry)
- TaskCache tree hierarchy metadata

## Concept reference
- ExecutablePath (the Actions/Exec/Command path)

## Triage
```powershell
# Find all task XMLs under System32\Tasks
Get-ChildItem "$env:WINDIR\System32\Tasks" -Recurse -File | ForEach-Object {
    $xml = [xml](Get-Content $_.FullName -Raw)
    [PSCustomObject]@{
        Path = $_.FullName
        Author = $xml.Task.RegistrationInfo.Author
        Date = $xml.Task.RegistrationInfo.Date
        Command = $xml.Task.Actions.Exec.Command
        Arguments = $xml.Task.Actions.Exec.Arguments
        RunAs = $xml.Task.Principals.Principal.UserId
        FileMTime = $_.LastWriteTime
    }
} | Sort-Object Date -Descending | Format-Table -AutoSize
```

Red flags in output:
- Author = `<HOSTNAME>\<username>` (a user-created task masquerading under Microsoft-looking path)
- Author blank + task under Microsoft\Windows\ path = Microsoft-path impersonation
- Arguments with base64 / `-enc` / `IEX` / `javascript:` / URLs
- RunAs = SYSTEM with non-standard Command path
- FileMTime >> Date = task has been modified post-creation

## Cross-reference
- Registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` (GUID mapping)
- Registry `TaskCache\Tasks\{GUID}\SD` (security descriptor)
- `Microsoft-Windows-TaskScheduler/Operational` EVTX channel — events 106/140 (created/updated), 129 (started), 141 (deleted)
- `Security-4698` — task registered (Security channel)
- `Security-4702` — task updated

## Practice hint
```powershell
# Create a test task
$action = New-ScheduledTaskAction -Execute "notepad.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "DFIRTest" -Action $action -Trigger $trigger
# Inspect the resulting XML
cat "$env:WINDIR\System32\Tasks\DFIRTest"
# Remove
Unregister-ScheduledTask -TaskName "DFIRTest" -Confirm:$false
```
Observe the XML layout — Author = current user, Date = creation time, Actions/Exec/Command = notepad.exe. This is the exact structure you'll be parsing to separate attacker tasks from legitimate enterprise deployments.
