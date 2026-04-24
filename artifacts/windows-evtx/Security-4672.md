---
name: Security-4672
title-description: "Special privileges assigned to new logon"
aliases:
- Special privileges assigned
- Admin logon
link: security
tags:
- authentication
- privilege-elevation
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows:
    min: Vista
    max: '11'
location:
  channel: Security
  event-id: 4672
  provider: Microsoft-Windows-Security-Auditing
  log-file: "%WINDIR%\\System32\\winevt\\Logs\\Security.evtx"
fields:
- name: SubjectUserSid
  kind: identifier
  location: EventData → SubjectUserSid
  type: S-1-5-string
  note: SID being granted special privileges
  references-data:
  - concept: UserSID
    role: actingUser
- name: SubjectUserName
  kind: label
  location: EventData → SubjectUserName
  type: string
  note: account name being elevated
- name: SubjectDomainName
  kind: label
  location: EventData → SubjectDomainName
  type: string
- name: SubjectLogonId
  kind: identifier
  location: EventData → SubjectLogonId
  type: hex-quadword
  note: ties this privilege assignment to a specific 4624 logon session; critical pivot
  references-data:
  - concept: LogonSessionId
    role: sessionContext
- name: PrivilegeList
  kind: flags
  location: EventData → PrivilegeList
  type: space-separated privilege names
  note: "Windows audits 13 sensitive privileges at logon per MS Learn. Corpus enumerates all 13 for reference (not a completeness claim about whether they fire every session): SeAssignPrimaryTokenPrivilege, SeAuditPrivilege, SeBackupPrivilege, SeCreateTokenPrivilege, SeDebugPrivilege, SeEnableDelegationPrivilege, SeImpersonatePrivilege, SeLoadDriverPrivilege, SeRestorePrivilege, SeSecurityPrivilege, SeSystemEnvironmentPrivilege, SeTakeOwnershipPrivilege, SeTcbPrivilege. Forensically most-interesting for detection: SeDebugPrivilege (process memory access), SeTcbPrivilege (act-as-OS), SeCreateTokenPrivilege (token forgery — rare even on admin), SeEnableDelegationPrivilege (Kerberos delegation — often a hunting signal when appearing on service accounts that shouldn't have it)."
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: PRIVILEGED_SESSION
  ceiling: C3
  note: Admin/SYSTEM logon marker. Pair with 4624 by SubjectLogonId for full session context.
  qualifier-map:
    actor.user.sid: field:SubjectUserSid
    actor.session.id: field:SubjectLogonId
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: service
  known-cleaners:
  - tool: wevtutil clear-log Security
    typically-removes: emits 1102 audit-cleared event
detection-priorities:
  - non-domain-admin SIDs acquiring SeDebugPrivilege/SeTcbPrivilege — lateral movement or credential access precursor
  - Service accounts appearing as SubjectUserName — legitimate but flag if unexpected
provenance: [ms-event-4672, uws-event-4672]
---

# Security-4672

## Forensic value
Every privileged logon generates 4672 immediately after the 4624 that granted the session. Distinct from 4624 in semantic:
- 4624 = "this user authenticated and got a session"
- 4672 = "this session got one or more sensitive/administrative privileges"

For an attacker impersonating a privileged account, 4672 is the audit pin — you cannot privilege-escalate within a session without one firing.

## Privilege taxonomy
The `PrivilegeList` names Windows privilege constants. Key attacker-interest ones:
- **SeDebugPrivilege** — LSASS memory access precursor (credential dumping)
- **SeTcbPrivilege** — "act as part of the operating system"; rare, powerful
- **SeBackupPrivilege** / **SeRestorePrivilege** — allow bypass of file ACLs
- **SeImpersonatePrivilege** — lateral movement via token impersonation
- **SeLoadDriverPrivilege** — kernel-driver load (BYOVD attack primitive)

## Correlation
- **SubjectLogonId** is the join key. Given a 4672, find the corresponding 4624 with matching TargetLogonId; that tells you *how* the session was created (logon type 3 = network, 10 = RDP, etc.).
- **4634** / **4647** (logoff) closes the logon pair; sessions without a closing logoff are either still active or were forcibly terminated.

## Practice hint
PowerShell triage:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -MaxEvents 100 |
  ForEach-Object { [xml]$x = $_.ToXml(); [pscustomobject]@{
    Time = $_.TimeCreated
    User = $x.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName' | Select -Expand '#text'
    LogonId = $x.Event.EventData.Data | Where-Object Name -eq 'SubjectLogonId' | Select -Expand '#text'
  }}
```
