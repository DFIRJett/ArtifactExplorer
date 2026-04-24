---
name: Security-4657
title-description: "A registry value was modified"
aliases:
- Registry value was modified
- registry-write audit
- registry value set
link: security
tags:
- object-access
- audit-policy-dependent
- registry-write
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: {min: Vista, max: '11'}
location:
  channel: Security
  event-id: 4657
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
- name: SubjectLogonId
  kind: identifier
  location: EventData\SubjectLogonId
  encoding: hex-uint64
  references-data:
  - concept: LogonSessionId
    role: sessionContext
- name: ObjectName
  kind: path
  location: EventData\ObjectName
  note: "Full NT-namespace registry key path — `\\REGISTRY\\MACHINE\\SOFTWARE\\...` or `\\REGISTRY\\USER\\<SID>\\...`. Strip the `\\REGISTRY\\MACHINE\\` prefix to get the HKLM\\... form; replace `\\REGISTRY\\USER\\<SID>` with HKU\\<SID>."
- name: ObjectValueName
  kind: label
  location: EventData\ObjectValueName
  note: "Name of the specific REGISTRY VALUE modified (or empty for default-value writes). 4657 is UNIQUE among audit events in carrying this — 4663 only reports the KEY, not the value within."
- name: HandleId
  kind: identifier
  location: EventData\HandleId
  encoding: hex-uint64
  references-data:
  - concept: HandleId
    role: accessHandle
  note: "Ties this write to the preceding 4656 that opened the key handle. ProcessId + HandleId + same-session yields the full context: which process, which session, what key was opened with what rights, what value was written."
- name: OperationType
  kind: enum
  location: EventData\OperationType
  note: |
    Resolves to one of:
      %%1904 = New registry value created
      %%1905 = Existing registry value modified
      %%1906 = Registry value deleted
    The %%N tokens resolve via winevt.dll localization. Parsers should normalize to 'New' / 'Modify' / 'Delete'.
- name: OldValueType
  kind: enum
  location: EventData\OldValueType
  note: "REG_NONE (0), REG_SZ (1), REG_EXPAND_SZ (2), REG_BINARY (3), REG_DWORD (4), REG_MULTI_SZ (7), REG_QWORD (11), etc. `%%1872` = REG_SZ (Vista+ localization token form). Absent/irrelevant for OperationType=New."
- name: OldValue
  kind: content
  location: EventData\OldValue
  note: "Prior value of the field being modified. PRESERVED in the event even though the registry itself has been overwritten — this is the PRIMARY forensic advantage of 4657 over registry-state analysis: historical value recovery without hive transaction logs."
- name: NewValueType
  kind: enum
  location: EventData\NewValueType
  note: "Registry type of the new value. Type change (OldValueType != NewValueType) is an anomaly worth investigating — unusual legitimate reason to change a value's type."
- name: NewValue
  kind: content
  location: EventData\NewValue
  note: "Post-modification value. For REG_BINARY and large REG_SZ, the event truncates with EventData-level limits — full payload may be in the transaction log or hive snapshot rather than the event."
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
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: |
    Registry write — the canonical Windows configuration-change proposition.
    C4 because: kernel-logged, carries both OLD and NEW values (historical
    reconstruction without hive forensics), carries actor user + session +
    process + handle + exact key + exact value name — the densest
    single-artifact attribution in Security.evtx.
  qualifier-map:
    setting: "field:ObjectName + '\\\\' + field:ObjectValueName"
    value: field:NewValue
    value-prior: field:OldValue
    change-type: field:OperationType
    actor.user.sid: field:SubjectUserSid
    actor.session.id: field:SubjectLogonId
    actor.process.pid: field:ProcessId
    actor.process.image: field:ProcessName
    actor.handle: field:HandleId
    time: field:time-created
  preconditions:
  - Audit Registry subcategory success auditing enabled (under Audit Object Access category; OFF by default)
  - SACL configured on the target registry key (by default, NONE of the registry has auditing — must be explicit)
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX record/chunk checksums
  requirement: "SACL required on target key — by default NO registry keys have SACLs; must be configured via `Advanced Security Settings → Auditing` or scripted via `Set-Acl`"
  known-cleaners:
  - tool: wevtutil clear-log Security
    typically-removes: full
    note: emits 1102
  - tool: audit-policy disable (Object Access)
    typically-removes: prospective
  survival-signals:
  - "4657 for HKLM\\System\\...\\Services\\<name>\\ImagePath with a ProcessName of powershell.exe / cmd.exe / wscript.exe during an incident window = scripted service installation; cross-reference System-7045"
  - "4657 for HKLM\\SOFTWARE\\...\\Run or RunOnce with OperationType=New + non-standard ProcessName = persistence implant"
  - "4657 for Defender preferences key (DisableAntiSpyware, DisableRealtimeMonitoring) = tamper"
  - "OldValueType != NewValueType for the same ObjectValueName = unusual pattern; most legitimate writers preserve type"
provenance: [ms-event-4657, uws-event-4657]
---

# Security Event 4657 — Registry Value Modified

## Forensic value
The **unique** Windows audit event that records a registry WRITE with both the old and new values. No other native audit event carries this. 4663 reports "the key was accessed" without the per-value detail; registry hive transaction logs contain historical state but require offline parsing; only 4657 emits a per-value "was X, became Y" delta in the Security channel at write time.

This makes 4657 the event for **persistence-implant detection, config-tamper detection, and registry-timeline reconstruction** on hosts where Security.evtx was retained but the registry was subsequently modified or cleaned.

## Why most shops don't have 4657s
By default, NO registry keys have SACLs configured. `Audit Object Access` can be enabled at the subcategory level, but until an actual SACL is set on a registry key, 4657 never fires. Real deployments typically scope SACLs to:
- `HKLM\SYSTEM\CurrentControlSet\Services` (detect service-creation)
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `RunOnce` (persistence)
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` (IFEO hijack)
- `HKLM\SOFTWARE\Microsoft\Windows Defender` (tamper)
- `HKLM\SAM` and `HKLM\SECURITY` (credential store tamper)

Presence of 4657s for these paths = someone deliberately configured auditing; expect it on well-instrumented environments.

## The old-value advantage
4657 preserves `OldValue` in the event record. Even if the registry has been further modified (or the entire key deleted) afterward, the event retains:
- The value AT THE MOMENT OF WRITE (NewValue)
- The value THAT WAS REPLACED (OldValue)
- The write TIMESTAMP (TimeCreated)
- The ACTING CONTEXT (Process, User, Session, Handle)

That's a complete change-record that doesn't rely on registry-hive state at examination time.

## Join-key role
4657 is the critical terminal event in the handle-scoped registry-write chain:

```
4624 (logon)      TargetLogonId=LUID
  └─ 4688 (process created)   SubjectLogonId=LUID, NewProcessId=PID
        └─ 4656 (handle open) SubjectLogonId=LUID, ProcessId=PID, HandleId=H, ObjectName=HKLM\...
              └─ 4657 (value write)  HandleId=H, ObjectValueName=X, OldValue=..., NewValue=...   ← THIS
        └─ 4658 (handle close) HandleId=H
```

Every layer carries LUID; process layers add PID; handle-scoped events add HandleId. Filtering Security.evtx on any single LUID+PID+HandleId triple isolates one handle's complete lifecycle — including the specific value writes performed through it.

## Known quirks
- **%%N operation-type tokens**. Parsers need to resolve `%%1904` → 'New', `%%1905` → 'Modify', `%%1906` → 'Delete'. Raw XML shows the token; EventViewer + ParseEvent() resolve it via winevt.dll.
- **Empty ObjectValueName** means the DEFAULT value of the key was written. Both key-default and named-value writes emit 4657.
- **Truncation on large values**. REG_BINARY values above an event-size threshold (typically 64KB) are truncated. The full payload is in the hive + transaction logs; the event documents THAT the write happened with a summary value.
- **Type change is suspicious**. Clean software rewrites values preserving type. A REG_SZ → REG_BINARY transformation on a known key suggests tampering or decoy-data injection.
- **Bulk writes from a single handle**: One 4656 → many 4657s → one 4658 is common during settings-dialog saves. Group by HandleId when presenting to analysts.

## Cross-references
- **Security-4656** — the open event that precedes this write (same HandleId, ProcessId)
- **Security-4658** — the close event that ends this handle's lifecycle
- **Security-4688** — joins via ProcessId to identify the acting process's command line
- **Sysmon-13** — Sysmon's equivalent; lighter-weight but no OldValue field
- **Registry hive transaction logs** (SYSTEM.LOG1/2, SOFTWARE.LOG1/2, etc.) — overlap evidence source when 4657 wasn't enabled

## Practice hint
Enable auditing on `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`:
```powershell
$sddl = "O:BAG:SYD:(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)S:AR(AU;OICISA;KA;;;WD)"
$acl = (Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
$acl.SetSecurityDescriptorSddlForm($sddl)
Set-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" $acl
AuditPol /set /subcategory:"Registry" /success:enable
```
Then:
```powershell
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "TestEntry" -Value "C:\fake\payload.exe" -PropertyType String
```
Inspect the resulting Security.evtx: you should see 4656 (handle open with WriteData), 4657 (new value with OperationType=%%1904, NewValue=C:\fake\payload.exe, OldValue empty), 4658 (close). Filter by HandleId to isolate this specific write's trace.
