---
name: Security-4658
title-description: "The handle to an object was closed"
aliases:
- Handle to an object was closed
- handle released
- object handle close
link: security
tags:
- object-access
- audit-policy-dependent
- lifecycle-terminator
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: {min: Vista, max: '11'}
location:
  channel: Security
  event-id: 4658
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
- name: ObjectServer
  kind: label
  location: EventData\ObjectServer
  note: "kernel subsystem — mirrors the value from the matching 4656 ('Security' for file/registry, 'SC Manager' for services, etc.)"
- name: HandleId
  kind: identifier
  location: EventData\HandleId
  encoding: hex-uint64
  references-data:
  - concept: HandleId
    role: closedHandle
  note: "The handle being released. After this event, this HandleId value is DEAD — the kernel may reuse it for a future 4656 in the same process, so any subsequent event carrying this HandleId in the same ProcessId is a NEW handle lifecycle, not a continuation."
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
- proposition: ACCESSED
  ceiling: C2
  note: |
    Handle closed — end of a 4656-opened object-access lifecycle. C2 as a
    standalone proposition because 4658 alone carries no object reference
    (only HandleId). It is FORENSICALLY LOAD-BEARING as the terminator of
    a chain: pair with the matching 4656 to establish the access window's
    duration, and to confirm the handle is no longer reusable for
    identification purposes.
  qualifier-map:
    actor.user.sid: field:SubjectUserSid
    actor.session.id: field:SubjectLogonId
    actor.process.pid: field:ProcessId
    actor.handle: field:HandleId
    time.closed: field:time-created
  preconditions:
  - Audit Handle Manipulation subcategory success auditing enabled (under Audit Object Access category; OFF by default; separate from the Object-Access subcategories that generate 4656/4663)
  - Matching 4656 present in the log for correlation (otherwise only a handle-close of unknown target)
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX record/chunk checksums
  requirement: "Requires Audit Handle Manipulation subcategory. This is a SEPARATE subcategory from Audit Object Access — many sites enable Object Access (for 4656/4663/4657) but NOT Handle Manipulation, which means 4658 events are absent and the lifecycle terminators disappear."
  known-cleaners:
  - tool: wevtutil clear-log Security
    typically-removes: full
  survival-signals:
  - "4656 present + 4658 absent for same HandleId at end-of-session: either the handle leaked (process held past session) or Handle Manipulation subcategory wasn't enabled. Check AuditPol for the subcategory setting before concluding handle-leak."
  - "Process terminates without emitting 4658 for its still-open handles: Windows closes handles implicitly at process exit and typically does NOT emit 4658 for kernel-cleaned handles. Lack of closing 4658 at process termination is expected, NOT anomalous."
provenance: [ms-event-4658, uws-event-4658]
---

# Security Event 4658 — Handle Closed

## Forensic value
The LIFECYCLE TERMINATOR for 4656-opened handles. Establishes the exact moment a handle was released — bounds the object-access window and confirms the HandleId is no longer reusable for identification purposes.

On its own, 4658 carries no object reference. Its forensic value is entirely RELATIONAL: paired with its opening 4656 via matching HandleId + ProcessId, it closes the access window. Unpaired 4658s (no corresponding 4656) are either from cross-boot correlation noise or from a 4656 outside the log-retention window.

## Audit-policy trap
4658 fires under the `Audit Handle Manipulation` subcategory, which is SEPARATE from `Audit Object Access` (the subcategory for 4656/4663/4657). Many production deployments enable Object Access for 4656/4663/4657 but skip Handle Manipulation. Consequence: the chain has open+access events but no close events. Forensic impact: object-access WINDOWS cannot be computed; you know when something was opened but not when it was released.

If you need handle-lifecycle analysis, both subcategories must be enabled:
```
AuditPol /set /subcategory:"Kernel Object" /success:enable
AuditPol /set /subcategory:"Handle Manipulation" /success:enable
```

## Join-key role
4658 completes the handle-scoped chain:

```
4656 (OPEN)    HandleId=H, ObjectName=X, AccessList=full
  └─ 4663      HandleId=H, AccessMask=subset   (n events)
  └─ 4657      HandleId=H, ObjectValueName=V, OldValue=..., NewValue=...   (for registry)
4658 (CLOSE)   HandleId=H   ← window closes here
```

Duration of open = `time(4658) - time(4656)`. Useful for:
- **Rapid-open-close** patterns (milliseconds) indicating programmatic access sweeps (credential-dump tools)
- **Long-hold** patterns (hours) indicating long-running queries or forgotten handles
- **Open-held-through-session-end** patterns indicating processes persisting across logout

## Handle reuse caveat
Once a HandleId is closed, the kernel may reuse that integer value for a subsequent 4656 in the same process. Any event carrying the same HandleId AFTER a 4658 is a NEW handle lifecycle, not a continuation. Correlation logic must:
1. Pair 4656+4658 by HandleId within a single process's event stream
2. Treat post-4658 HandleIds as logically-distinct from prior opens
3. Anchor handle-identity comparisons in (ProcessId, HandleId, time-range) tuples, never HandleId alone

Without this discipline, correlating handle events across long sessions produces spurious joins.

## Process-termination behavior
When a process terminates, Windows implicitly closes all outstanding handles. 4658 events are NOT reliably emitted for these kernel-cleaned handles — Windows skips audit generation during fast process teardown. Lack of a closing 4658 for every open handle at process exit is EXPECTED behavior, not handle-leak evidence. To verify process lifecycle termination, correlate the owning 4688 with a Security-4689 (process termination) event.

## Cross-references
- **Security-4656** — the opening event; same HandleId, ProcessId; 4658 closes 4656's lifecycle
- **Security-4663** — per-access events within this handle's lifetime
- **Security-4657** — registry value writes within this handle's lifetime (Key-type handles)
- **Security-4660** — object-delete events that may precede a 4658 when DELETE access was used
- **Security-4689** — process termination; implicit handle cleanup anchor

## Practice hint
With both Object Access + Handle Manipulation subcategories enabled, and a SACL on `C:\temp\test.txt`, open the file in Notepad. Observe:
1. **4656** with HandleId=H, AccessList including ReadData, WriteData
2. **4663** events with HandleId=H as Notepad reads and writes
3. Close Notepad → **4658** with HandleId=H

Compute `time(4658) - time(4656)` for the observed open duration. Re-open the file — a NEW 4656 will emit with a different HandleId (or the same value if reused; verify via event-sequence ordering). This re-open must NOT be collapsed with the first open when analyzing handle lifetimes.
