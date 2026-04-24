---
name: Security-5140
title-description: "A network share object was accessed"
aliases:
- Network share accessed
- SMB share connection
link: network
tags:
- lateral-movement
- share-access
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows:
    min: '7'
    max: '11'
location:
  channel: Security
  event-id: 5140
  provider: Microsoft-Windows-Security-Auditing
  log-file: "%WINDIR%\\System32\\winevt\\Logs\\Security.evtx"
fields:
- name: SubjectUserSid
  kind: identifier
  location: EventData → SubjectUserSid
  references-data:
  - concept: UserSID
    role: actingUser
- name: SubjectUserName
  kind: label
  location: EventData → SubjectUserName
- name: SubjectDomainName
  kind: label
  location: EventData → SubjectDomainName
- name: SubjectLogonId
  kind: identifier
  location: EventData → SubjectLogonId
  note: join key back to the 4624 session
  references-data:
  - concept: LogonSessionId
    role: sessionContext
- name: ObjectType
  kind: label
  location: EventData → ObjectType
  note: typically 'File' for share access
- name: IpAddress
  kind: address
  location: EventData → IpAddress
  note: source IP of the connecting host
  references-data:
  - concept: IPAddress
    role: sourceIp
- name: IpPort
  kind: port
  location: EventData → IpPort
- name: ShareName
  kind: path
  location: EventData → ShareName
  note: UNC-style share identifier (\\\\*\\IPC$, \\\\*\\C$, \\\\*\\<custom>)
- name: ShareLocalPath
  kind: path
  location: EventData → ShareLocalPath
  note: local filesystem path backing the share (C:\, C:\shares\..., etc.)
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: ACCESSED_SHARE
  ceiling: C3
  note: Inbound SMB share-access audit on the FILE SERVER side. Captures every session-level share connection with source IP and user SID. Essential for lateral-movement reconstruction.
  qualifier-map:
    actor.user.sid: field:SubjectUserSid
    actor.source.ip: field:IpAddress
    object.share.name: field:ShareName
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: service
  requirement: "'File Share' audit subcategory must be enabled — off by default"
  known-cleaners:
  - tool: wevtutil clear-log Security
    typically-removes: emits 1102
detection-priorities:
  - "ShareName in (\\\\*\\C$, \\\\*\\ADMIN$, \\\\*\\IPC$) from non-administrative source IPs — lateral-movement indicator"
  - "SubjectUserName with rapid share access to multiple servers — SMB credential-spray or domain-recon"
  - "Off-hours share access from unusual source IPs"
provenance: [ms-event-5140, uws-event-5140]
---

# Security-5140

## Forensic value
Emitted on the **file server** (the machine hosting the share) whenever an SMB client establishes a share-level connection. Captures:

- **Who** — SubjectUserSid + SubjectUserName
- **From where** — IpAddress + IpPort
- **To what** — ShareName (UNC form) + ShareLocalPath (server-local path)

Pair with **Security-4624** (logon) for the same SubjectLogonId on the same timestamp for the full entry sequence: network logon → share connect.

## Audit policy requirement
Event 5140 requires the **"Audit File Share"** subcategory under the "Object Access" audit policy. **Off by default** on Windows client and server builds. On production file servers it's typically enabled by GPO (per CIS Level 1 or similar); on workstations and random member servers, usually not.

Absence of 5140 doesn't mean "no share access happened" — it means "audit wasn't on." Cross-reference with Security-4624 logon type 3 events as a coverage fallback.

## Object-access granularity
5140 is **share-level** — it fires on share connect, not per-file-inside-the-share. For file-level access within a share, enable **Security-5145** (share with object access requested) — much noisier but file-granular.

## Lateral-movement signature
Attacker SMB session pattern:
1. Connect to ADMIN$ on target (5140 with ShareName=\\\\*\\ADMIN$)
2. Drop binary via WriteFile (5145 if audited)
3. Open Service Control Manager (typically via IPC$)
4. Install service (7045 / 4697 on target)
5. Start service → execution

Each step emits 5140 on the target if audit is on. Absence of 5140 but presence of 7045 implies either SMB-free lateral movement (WMI, WinRM) or audit-off on the target.

## Cross-references
- **Security-4624** logon-type-3 — the network logon that preceded this share connection
- **Security-5145** — object-access-requested inside the share (file-level)
- **Sysmon-3** on the source — the outbound SMB connection event, if Sysmon is deployed
- **Sysmon-11** on the target — file creation if the attacker dropped a payload

## Practice hint
Share-access triage on a domain file server:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140; StartTime=(Get-Date).AddHours(-24)} |
  Select-Object TimeCreated,
    @{N='User';E={$_.Properties[1].Value}},
    @{N='IP';E={$_.Properties[5].Value}},
    @{N='Share';E={$_.Properties[7].Value}}
```
