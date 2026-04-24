---
name: ProcessId
kind: value-type
lifetime: runtime
link-affinity: application
description: |
  Windows process identifier — an OS-assigned 32-bit integer that uniquely
  identifies a running process within a single boot session. Appears in
  security audit events as NewProcessId (4688, the process just created),
  ProcessId (4663/4657, the actor process accessing an object), and
  SubjectProcessId (various). The numeric join key that threads 4688
  process-creation events to the 4663/4657 object-access events the
  resulting process generates.
canonical-format: "hex uint32 (Windows native); also shown as decimal in some tools"
aliases: [PID, NewProcessId, SubjectProcessId, ActorProcessId]
roles:
  - id: createdProcess
    description: "The process identifier assigned to a newly-created process (4688.NewProcessId — the process that just came into existence)"
  - id: parentProcess
    description: "The identifier of the process that spawned a child (4688.ProcessId — the parent field in process-creation events)"
  - id: actingProcess
    description: "The process identifier of the process performing an action (4663.ProcessId, 4657.ProcessId, Firewall events' modifying-process) — the runtime actor"
  - id: targetProcess
    description: "The process identifier of the object being accessed by cross-process events (Sysmon-8.TargetProcessId on CreateRemoteThread, Sysmon-10.TargetProcessId on ProcessAccess, Security-4688.TargetProcessId on CreateProcessAsUser)"
  - id: sessionContext
    description: "PID captured as context of a broader session / memory snapshot — e.g., process-list embedded in a hibernation file, crash-dump process list — not as the actor of a specific event"

known-containers:
  # Process-creation source — assigns PIDs that later appear as join keys
  - Security-4688
  # Object-access events using PID as actor identity
  - Security-4656
  - Security-4657
  - Security-4658
  - Security-4663
  # Sysmon process-create — parallel to 4688 with more fields
  - Sysmon-1
  # Sysmon network connection — actor process PID
  - Sysmon-3
  # Sysmon image load
  - Sysmon-7
  # Sysmon CreateRemoteThread
  - Sysmon-8
  # Sysmon registry value set — requires PID + HandleId to chain
  - Sysmon-13
  # Process termination (parallel to 4689 which we haven't authored)
  - Sysmon-10
provenance: [hartong-2024-sysmon-modular-10-process-acce]
---

# Process Id (PID)

## What it is
The OS-assigned numeric identifier for a running process. Unique within a single boot session — after reboot, PIDs are re-issued from a low pool (typically under 100 for system processes, higher for user processes). Windows may reuse PIDs aggressively on systems with short process lifecycles, so PID alone does NOT uniquely identify a process across time.

## The process-chain join key
PID is the join key that turns a process-creation event and a stream of subsequent audit events into a coherent activity record:

- **4688.NewProcessId** → this is the PID assigned when the process was created
- **4663.ProcessId** (object access) → the same PID when that process accessed a file/registry/object
- **4657.ProcessId** (registry value write) → the same PID during a registry modification
- **Sysmon-13.ProcessId** → the same PID during a registry-set event
- **4688.ProcessId** (on a later event) → this PID as the PARENT of a child process

Given any suspicious 4663 with a target ObjectName, filter 4688 events on NewProcessId==that 4663's ProcessId. You get the 4688 that created the acting process — with its full image path, command line, parent, and SubjectLogonId. Walk backward through 4688 parent-chains and you have the complete process tree leading to the object access.

## Cross-event chain with LogonSessionId

```
4624 (logon)
  └─ TargetLogonId = LUID-A
        │
        ├─ 4688 (process creation)
        │     SubjectLogonId = LUID-A        ← same session
        │     NewProcessId    = PID-X         ← new process born
        │     ProcessId       = PID-Parent    ← parent PID
        │         │
        │         ├─ 4663 (file access)
        │         │     SubjectLogonId = LUID-A   ← same session
        │         │     ProcessId      = PID-X    ← same process
        │         │     HandleId       = H-1      ← per-access handle
        │         │     ObjectName     = C:\...
        │         │
        │         ├─ 4657 (registry write)
        │         │     ProcessId = PID-X         ← same process
        │         │     HandleId  = H-2           ← different handle
        │         │
        │         └─ Firewall-2004/2006
        │               ModifyingApplication = <path from 4688.NewProcessName>
        │               ModifyingUser        = <SID from 4688.SubjectUserSid>
        │               (no LogonId/PID field — join by path+user+time)
        │
        └─ 4634/4647 (logoff)
              TargetLogonId = LUID-A    ← same session closing
```

Three concepts chain the whole activity: **LogonSessionId** for the session window, **ProcessId** for the process identity within that session, **HandleId** for per-object-access correlation within a process.

## Re-use caveat
PIDs re-issue on reboot AND can re-issue during a boot session on busy servers (Windows wraps the PID pool at ~65,000). Always pair PID comparison with:
1. Event-time proximity (PID reuse happens seconds to minutes apart; a week-long gap with matching PID is coincidence, not correlation)
2. LogonSessionId match (events with same PID but different LUIDs are different sessions — different processes by definition)
3. Process image path consistency (4663.ProcessName should match the 4688.NewProcessName for the same PID)

## Not exit-node
PID is a session-scoped join key, not an identity terminus like UserSID. A PID resolves to a process image path (ExecutablePath) — that's one exit-node hop further. The forensic chain treats PID as a plumbing concept rather than a resolvable real-world subject.
