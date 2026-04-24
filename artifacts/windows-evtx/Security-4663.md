---
name: Security-4663
title-description: "An attempt was made to access an object"
aliases:
- Object access attempted
- SACL hit
link: security
tags:
- object-access
- audit-policy-dependent
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
  event-id: 4663
  provider: Microsoft-Windows-Security-Auditing
fields:
- name: SubjectUserSid
  kind: identifier
  location: EventData → SubjectUserSid
  references-data:
  - concept: UserSID
    role: actingUser
- name: SubjectUserName
  kind: identifier
  location: EventData → SubjectUserName
- name: SubjectDomainName
  kind: identifier
  location: EventData → SubjectDomainName
- name: SubjectLogonId
  kind: identifier
  location: EventData → SubjectLogonId
  references-data:
  - concept: LogonSessionId
    role: sessionContext
- name: ObjectType
  kind: label
  location: EventData → ObjectType
  note: "'File' | 'Key' | 'Process' | 'Token' | ..."
- name: ObjectName
  kind: path
  location: EventData → ObjectName
  note: filesystem or registry path of the accessed object; absolute path for files
- name: ProcessId
  kind: identifier
  location: EventData → ProcessId
  encoding: hex-uint32
  references-data:
  - concept: ProcessId
    role: actingProcess
  note: "PID of the process performing the access. Joins backward to the 4688 with NewProcessId==this value to identify when/how this process was created, its parent, its command line, and its SubjectLogonId."
- name: ProcessName
  kind: path
  location: EventData → ProcessName
  references-data:
  - concept: ExecutablePath
    role: actingProcess
- name: HandleId
  kind: identifier
  location: EventData → HandleId
  encoding: hex-uint64
  references-data:
  - concept: HandleId
    role: accessHandle
  note: "Kernel handle identifier. Joins to the 4656 that opened this handle (same HandleId + ProcessId) and the 4658 that will close it. Same ObjectName accessed via two different HandleIds = two distinct open-access-close lifecycles on the same logical object."
- name: AccessList
  kind: flags
  location: EventData → AccessList
  note: "Symbolic list of rights ACTUALLY USED (%%N tokens — %%4416 ReadData, %%4417 WriteData, %%1537 DELETE, etc.). Distinct from 4656's AccessList which is rights REQUESTED at open. Difference between the two indicates 'what was asked' vs 'what was exercised'."
- name: AccessMask
  kind: flags
  location: EventData → AccessMask
  note: "hex bitmask of requested access rights — 0x1 = ReadData, 0x2 = WriteData, 0x4 = AppendData, 0x100 = ReadAttributes, 0x80 = WriteDAC, etc."
- name: ObjectServer
  kind: label
  location: EventData → ObjectServer
  note: "kernel subsystem handling the object — 'Security' for file/registry, 'SC Manager' for service-related, etc. Usually 'Security'."
- name: ResourceAttributes
  kind: identifier
  location: EventData → ResourceAttributes (Win10+)
  note: "Dynamic Access Control claims attached to the resource, if configured. Usually absent outside domain environments with DAC."
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: ACCESSED
  ceiling: C3
  note: "File / registry-key / kernel-object access audit. Requires the matching Object-Access subcategory per ObjectType (Audit File System, Audit Registry, Audit Kernel Object, Audit SAM, Audit Removable Storage) + SACL on the specific object. Noisy without scoped auditing but surgical when properly scoped."
  qualifier-map:
    actor.user.sid: field:SubjectUserSid
    actor.session.id: field:SubjectLogonId
    actor.process.pid: field:ProcessId
    actor.process.image: field:ProcessName
    actor.handle: field:HandleId
    object.path: field:ObjectName
    object.access.mask: field:AccessMask
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: service
  requirement: "Matching Object-Access subcategory per ObjectType (Audit File System / Audit Registry / Audit Kernel Object / Audit SAM / Audit Removable Storage) + SACL on target object — all OFF by default"
provenance: [ms-event-4663, uws-event-4663]
---

# Security-4663

## Forensic value
Per-access audit of files, registry keys, and other kernel objects with an enabled SACL. When scoped correctly (auditing on specific sensitive paths, not everything), 4663 provides granular per-file access evidence with the acting process and the exact access mask.

## Join-key use
Three orthogonal join keys make 4663 the pivot event in session-level activity reconstruction:

| Join key | Joins to | Establishes |
|---|---|---|
| **SubjectLogonId** | Security-4624 TargetLogonId | The session window (user, logon type, source) |
| **ProcessId** | Security-4688 NewProcessId | The acting process (image, parent, command-line) |
| **HandleId** | Security-4656 / 4658 | The per-access open-close lifecycle |
| **ObjectName** | NTFS $MFT / Registry tree | The target object's lifecycle in the filesystem/registry |

Given a suspicious 4663, you can fan out four ways:
- back to 4624 via SubjectLogonId → who was logged in
- back to 4688 via ProcessId → what binary was running, with what arguments
- to bracketing 4656/4658 via HandleId → when the handle opened/closed
- out to MFT/Registry via ObjectName → what the target object is and what other artifacts mention it

That's what makes 4663 the **convergence point** for forensic activity reconstruction. Pair it with Firewall-2004/2005/2006 for the same acting process (via ProcessName match on ModifyingApplication) and you have logon → exec → firewall-change → registry-write documented end-to-end.
