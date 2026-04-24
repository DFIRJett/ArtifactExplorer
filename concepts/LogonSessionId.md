---
name: LogonSessionId
kind: identifier
lifetime: session-scoped
link-affinity: user
description: |
  Windows logon session identifier (LUID). Assigned by the Local Security
  Authority when a user session is created (Security-4624) and referenced
  by every subsequent audit event that occurs within that session until
  the matching 4634 or 4647 logoff. Format: 0xHEXHEX - a pair of DWORDs.
canonical-format: "0x<8hex>:0x<8hex> OR combined 0x<16hex> — LSA-assigned LUID"
aliases: [LUID, TargetLogonId, SubjectLogonId]
roles:
  - id: identitySubject
    description: "The logon event that ASSIGNS this LUID — Security-4624 TargetLogonId, Security-4648 TargetLogonId"
  - id: sessionContext
    description: "The LUID recorded on in-session events (4688 SubjectLogonId, 4663, 4672, 5140, 4647, 4634)"

known-containers:
  - Security-4624
  - Security-4625
  - Security-4634
  - Security-4647
  - Security-4648
  - Security-4672
  - Security-4688
  - Security-4656
  - Security-4657
  - Security-4658
  - Security-4663
  - Security-5140
---

# Logon Session Id (LUID)

## What it is
A Locally Unique Identifier issued by LSASS the moment a user's session is created. In Security audit events, it appears as `TargetLogonId` on the logon itself (4624, 4648) and as `SubjectLogonId` on every later event that happens INSIDE that session (process creation, object access, privileges assigned, share access, logoff).

## The most useful intra-evtx join key
Every security event in a Windows session can be grouped by LogonId. Given a suspicious process in 4688, joining on SubjectLogonId yields:
- The 4624 that started the session (who, from where, what logon type)
- The 4672 if privileged (what special privileges)
- The 4663 / 5140 events they generated (what they touched)
- The 4634 / 4647 that closed the session (when they left)

That's a complete session trace.

## Registry bridge
LUIDs are NOT stored in the Registry. But they define the TEMPORAL WINDOW during which any NTUSER.DAT artifact's last-write timestamp is authentic. A key last-write outside all authenticated logon windows for that SID is anomalous — timestamp tampering, scheduled-task-driven writes, or remote-without-interactive-logon (e.g., PsExec).

## Re-use caveat
LUIDs are unique per REBOOT. After restart, LUIDs re-issue from zero — a LUID from an old log is NOT the same session as a LUID from a current log, even if numerically identical. Always pair LUID comparison with event-time proximity.
