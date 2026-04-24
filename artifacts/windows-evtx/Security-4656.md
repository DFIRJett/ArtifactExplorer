---
name: Security-4656
title-description: "A handle to an object was requested"
aliases:
- Handle to an object was requested
- SAM_AUDIT_HANDLE_REQUESTED
- object handle open
link: security
tags:
- object-access
- audit-policy-dependent
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: {min: Vista, max: '11'}
location:
  channel: Security
  event-id: 4656
  provider: Microsoft-Windows-Security-Auditing
  log-file: '%WINDIR%\System32\winevt\Logs\Security.evtx'
  addressing: channel+event-id
fields:
- name: time-created
  kind: timestamp
  location: System\TimeCreated SystemTime
  encoding: iso8601-utc
  clock: system
  resolution: 1us
- name: SubjectUserSid
  kind: identifier
  location: EventData\SubjectUserSid
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: actingUser
- name: SubjectUserName
  kind: identifier
  location: EventData\SubjectUserName
  encoding: utf-16le
- name: SubjectDomainName
  kind: identifier
  location: EventData\SubjectDomainName
  encoding: utf-16le
- name: RestrictedSidCount
  kind: counter
  location: EventData\RestrictedSidCount
  encoding: uint32
  note: number of restricted SIDs in the subject's token; non-zero indicates the caller is using a write-restricted / sandbox token — forensic signal for sandboxed code paths
- name: SubjectLogonId
  kind: identifier
  location: EventData\SubjectLogonId
  encoding: hex-uint64
  references-data:
  - concept: LogonSessionId
    role: sessionContext
- name: ObjectServer
  kind: label
  location: EventData\ObjectServer
  note: "kernel subsystem — 'Security' for file/registry, 'SC Manager' for services, etc. Usually 'Security'."
- name: ObjectType
  kind: label
  location: EventData\ObjectType
  note: "'File' | 'Key' (registry) | 'Process' | 'Token' | 'Thread' | 'Mutant' | 'SAM' | ..."
- name: ObjectName
  kind: path
  location: EventData\ObjectName
  note: "Full object path — filesystem absolute path for Files (including \\Device\\HarddiskVolumeN\\... form for raw-device handles) or full registry key path (\\REGISTRY\\MACHINE\\SOFTWARE\\...) for Keys. NT-object-namespace form, not drive-letter."
- name: HandleId
  kind: identifier
  location: EventData\HandleId
  encoding: hex-uint64
  references-data:
  - concept: HandleId
    role: openedHandle
  note: "The handle value the kernel just assigned. This HandleId threads all subsequent 4663/4657 events on this open; the matching 4658 will close it."
- name: TransactionId
  kind: identifier
  location: EventData\TransactionId
  encoding: guid-string
  note: "KTM transaction ID if the handle was opened as part of a transacted operation; typically all-zero GUID."
- name: AccessList
  kind: flags
  location: EventData\AccessList
  note: "Requested access rights — symbolic list like '%%1537 %%4416 %%4417' (each %%N resolves to a named right: ReadData, WriteData, Delete, ReadAttributes, ReadEA, WriteEA, WriteDAC, etc.). Richer than 4663's AccessMask because 4656 captures the FULL set requested at open, even if subsequent 4663s only report the per-operation subset."
- name: AccessReason
  kind: label
  location: EventData\AccessReason (Win7+)
  note: "Per-right reason string explaining why each requested right was granted or denied (e.g., 'ReadData: Granted by ACL'). Populated only when 'Audit Handle Manipulation' subcategory is enabled alongside 'Audit Object Access'. Extremely verbose but authoritative for access-decision forensics."
- name: AccessMask
  kind: flags
  location: EventData\AccessMask
  encoding: hex-uint32
  note: "Bitmask form of AccessList — 0x1=ReadData, 0x2=WriteData, 0x4=AppendData, 0x80=WriteDAC, 0x100=ReadAttributes, 0x10000=Delete, etc. AccessList and AccessMask encode the same data."
- name: PrivilegeList
  kind: flags
  location: EventData\PrivilegeList
  note: "Privileges used during the access check (SeSecurityPrivilege, SeTakeOwnershipPrivilege, etc.). Non-empty PrivilegeList with SeSecurity / SeTakeOwnership = admin doing explicit ACL-bypass access."
- name: ProcessId
  kind: identifier
  location: EventData\ProcessId
  encoding: hex-uint32
  references-data:
  - concept: ProcessId
    role: actingProcess
- name: ProcessName
  kind: path
  location: EventData\ProcessName
  references-data:
  - concept: ExecutablePath
    role: actingProcess
- name: ResourceAttributes
  kind: identifier
  location: EventData\ResourceAttributes (Win10+ with DAC)
  note: "Dynamic Access Control claims attached to the resource. Typically absent outside domain environments with DAC configured."
observations:
- proposition: ACCESSED
  ceiling: C3
  note: "Handle REQUESTED — establishes intent-to-access with full access-rights set. 4663 reports per-operation subsets; 4656 captures the umbrella open. Pair with 4658 for the complete open/close lifecycle window on a specific object."
  qualifier-map:
    actor.user.sid: field:SubjectUserSid
    actor.session.id: field:SubjectLogonId
    actor.process.pid: field:ProcessId
    actor.process.image: field:ProcessName
    actor.handle: field:HandleId
    object.path: field:ObjectName
    object.type: field:ObjectType
    object.access.requested: field:AccessList
    time.observed: field:time-created
  preconditions:
  - "Object-Access subcategory enabled per ObjectType — Audit File System (File/Directory), Audit Registry (Key), Audit Kernel Object (Mutant/Section/etc.), Audit SAM (SAM DB), Audit Removable Storage (volumes with RemovableStorage classification). All under the Audit Object Access category; all OFF by default"
  - SACL configured on the target object (by object type)
  - "Optional — Audit Handle Manipulation subcategory enabled for AccessReason detail"
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX record/chunk checksums
  requirement: "SACL required on target object — MOST objects have no SACL by default, so 4656 is surgical when scoped but invisible when not"
  known-cleaners:
  - tool: wevtutil clear-log Security
    typically-removes: full
    note: emits Security 1102 counter-signal
  - tool: audit-policy disable (Object Access subcategory)
    typically-removes: prospective
    note: suppresses new 4656; look for recent 4719 (audit policy change)
  survival-signals:
  - "4656 for a sensitive path (SAM, SYSTEM, NTDS.dit) with SubjectUserSid NOT in expected-admin list = credential-dump tool in action"
  - "4656 AccessList including WriteDAC on SAM/Security hives = attacker modifying ACLs for subsequent privileged access"
provenance: [ms-event-4656, uws-event-4656]
---

# Security Event 4656 — Handle Requested

## Forensic value
The OPENING event of every object-access lifecycle on a SACL-enabled object. While 4663 reports the per-access operation and 4658 reports the close, 4656 is the one that records the FULL set of access rights requested at open — which 4663 alone cannot tell you.

Noise profile depends entirely on SACL scoping. A system with "audit full volume" SACLs produces thousands of 4656s per minute and is unusable. A system with SACL scoped to `\HKLM\SECURITY`, `\HKLM\SAM`, `\Windows\System32\config\*`, `\Users\*\NTUSER.DAT`, and `ntds.dit` produces ~dozens per day and is surgical.

## Join-key position
4656 is the ROOT of the handle-scoped forensic chain:

```
4656 (OPEN)          HandleId=H, ObjectName=X, AccessList=full   ← this event
  └─ 4663 (access)    HandleId=H, AccessMask=subset              (one per operation)
  └─ 4663 (access)    HandleId=H, AccessMask=subset
  └─ 4657 (reg write) HandleId=H, ObjectValueName=..., NewValue=...  (for registry)
4658 (CLOSE)          HandleId=H                                  ← lifecycle end
```

Filter the Security channel on ProcessId + HandleId + session-time-window = one complete "this process's use of this handle" block. 4656's AccessList is richer than 4663's AccessMask because it captures every right requested, not just rights exercised on a given operation.

## AccessList decoding (partial)
Windows EventViewer resolves the %%N tokens via `winevt.dll` message strings. Common values:
| %%N | Name | Meaning |
|---|---|---|
| %%1537 | DELETE | 0x00010000 |
| %%1538 | READ_CONTROL | 0x00020000 |
| %%1539 | WRITE_DAC | 0x00040000 — modify ACL |
| %%1540 | WRITE_OWNER | 0x00080000 — take ownership |
| %%4416 | ReadData / ListDirectory | 0x0001 |
| %%4417 | WriteData / AddFile | 0x0002 |
| %%4418 | AppendData / AddSubdir | 0x0004 |
| %%4419 | ReadEA | 0x0008 |
| %%4420 | WriteEA | 0x0010 |
| %%4423 | ReadAttributes | 0x0080 |
| %%4424 | WriteAttributes | 0x0100 |

`WRITE_DAC` (%%1539) requested on sensitive system objects = classic ACL-modification attack pattern.

## Known quirks
- **ObjectName uses NT-object-namespace form**, not drive-letter paths. `C:\Windows\System32\config\SAM` appears as `\Device\HarddiskVolume3\Windows\System32\config\SAM` or `\??\Volume{guid}\...`. Normalize with GetMountManagerInformation or tool-level path resolution for cross-referencing.
- **ObjectType "Key"** paths use `\REGISTRY\MACHINE\...` or `\REGISTRY\USER\<SID>\...` form — not `HKLM\` or `HKCU\`.
- **PrivilegeList when non-empty** often indicates admin-path access. `SeSecurityPrivilege` = opened with `AUDIT` intent; `SeTakeOwnershipPrivilege` = bypassing DACL via ownership.
- **TransactionId** is almost always `{00000000-0000-0000-0000-000000000000}`. When non-zero, the operation is part of a KTM transaction — rare on modern Windows.

## Cross-references
- **Security-4663** — per-operation access events sharing this HandleId
- **Security-4657** — registry value modifications sharing this HandleId (Key-type handles only)
- **Security-4658** — closes this HandleId
- **Security-4660** — object DELETED via this handle (if DELETE right was granted)
- **Security-4688** — joins via ProcessId to identify the acting process's image and parent

## Practice hint
On a Win10 VM with `AuditPol /set /subcategory:"Kernel Object" /success:enable` and a SACL set on `C:\temp\secrets.txt` (`icacls` + `/setowner`, then Properties → Security → Advanced → Auditing), open the file in Notepad. You should see a 4656 for notepad.exe's HandleId, then 4663s for each ReadData/WriteAttributes operation, then a 4658 when Notepad closes the file. Filter by the HandleId to see only this open's events.
