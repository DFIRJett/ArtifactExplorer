---
name: HandleId
kind: value-type
lifetime: runtime
link-affinity: security
description: |
  Windows kernel object handle identifier — a numeric value the kernel
  assigns when a process opens a handle to an object (file, registry
  key, process, token, etc.). Correlates events within a single
  open-access-close lifecycle: 4656 (handle requested) and 4663 (object
  access) and 4658 (handle closed) — or 4657 (registry value set) and
  Sysmon-13 — share the same HandleId when they describe operations on
  the same opened handle. Intra-process + intra-logon scope ONLY.
canonical-format: "hex uint64 or uint32 (build-dependent); e.g., 0x1a4c"
aliases: [ObjectHandle, Handle, ObjectHandleId]
roles:
  - id: accessHandle
    description: "The handle identifier during a single access event (4663, 4657) — ties this access to the 4656 that opened the handle and the 4658 that will close it"
  - id: openedHandle
    description: "The handle identifier emitted when a handle is first requested (4656) — starts the lifecycle"
  - id: closedHandle
    description: "The handle identifier on a close event (4658) — ends the lifecycle; HandleId no longer references a valid handle after this point"

known-containers:
  # Object-access audit — uses HandleId as the per-access token
  - Security-4656     # handle requested (openedHandle)
  - Security-4657     # registry value modified (accessHandle)
  - Security-4658     # handle closed (closedHandle)
  - Security-4663     # access attempted (accessHandle)
provenance: [ms-learn-audit-handle-manipulation]
---

# Handle Id

## What it is
When a process opens a kernel object (file, registry key, process, token, etc.), the kernel assigns it a HANDLE — an index into that process's handle table. The HandleId appearing in audit events is that index, typically displayed as a hex value. Two facts about handle IDs:

1. **Per-process scope**. HandleId 0x1a4c in process A is unrelated to HandleId 0x1a4c in process B. Always pair HandleId with ProcessId.
2. **Per-handle-lifetime scope**. Once a handle is closed, its HandleId can be reused for a subsequent open. Always pair HandleId comparison with event-time proximity — AND ideally with the bracketing 4656/4658 pair to establish the lifetime.

## The object-access-lifecycle join key
HandleId connects audit events that describe operations on the **same opened handle** rather than on the same logical object. The distinction matters:

- `ObjectName` ties events to the same logical object (same file, same registry path) regardless of which handle opened it
- `HandleId` ties events to the **same open session** of that object — the same 4656/4658-bracketed access

A file opened twice (two successive 4656s) produces two distinct HandleIds. Events 4663 referencing HandleId-1 describe operations during the first open; HandleId-2 describes the second. ObjectName is the same in both — only HandleId distinguishes the per-open access streams.

## Typical lifecycle

```
4656 (SAM_AUDIT_HANDLE_REQUESTED)      HandleId=0x1a4c  ObjectName=...  ← open
  └─ 4663 (access attempted)            HandleId=0x1a4c  AccessMask=...  ← read/write
  └─ 4663 (access attempted)            HandleId=0x1a4c  AccessMask=...  ← another op
4658 (HANDLE_CLOSED)                    HandleId=0x1a4c                  ← close
```

Filtering all four on HandleId=0x1a4c + same ProcessId yields one complete "this process's use of this handle" block. Cross-referencing to 4688 on ProcessId yields the acting process's image. Cross-referencing to 4624 on SubjectLogonId yields the session + user.

## Registry-write relevance
Event 4657 (registry value set) uses HandleId to reference the registry-key handle that was open during the write. Joining 4657 on HandleId with the preceding 4656 yields:
- Which registry key was opened (4656.ObjectName)
- What value was set (4657.ObjectValueName + NewValue/OldValue)
- How long the handle was held (4656 time → 4658 time)

That is the full registry-write-with-context picture. Tools that summarize "4657 = registry change" without re-linking to 4656 miss the key-path context (4657 alone carries KeyName; 4656 carries the fuller ObjectName path).

## Not forensically resolvable across reboot
HandleIds are transient runtime values. They do NOT persist across reboots, process restarts, or handle closures. HandleId is strictly a within-a-single-evtx-batch correlation tool — never as a long-term identifier.

## Cross-process comparison is meaningless
If you see HandleId 0x200 in two different 4663s with two different ProcessIds, those are unrelated handles in unrelated processes. Never compare HandleIds across ProcessId boundaries.

## Not exit-node
Handles are ephemeral runtime state. The HandleId resolves (within its lifetime) to an ObjectName — exit via the ObjectName, not via the handle number itself.
