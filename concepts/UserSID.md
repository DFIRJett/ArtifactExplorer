---
name: UserSID
kind: identifier
lifetime: permanent
link-affinity: user
link-affinity-secondary: security
description: |
  Windows Security Identifier for a user principal. Persistent across
  rename and password-change; the canonical cross-artifact key for user
  attribution.
canonical-format: "S-1-5-21-<machine-id>-<RID>"
aliases: [user-sid, security-identifier, principal-SID, NT-SID]
roles:
  - id: identitySubject
    description: "SID is the definition of a user identity (ProfileList entry, SAM account)"
  - id: authenticatingUser
    description: "SID of the account being authenticated in a logon event"
  - id: actingUser
    description: "SID of the user subject performing an audited action"
  - id: targetUser
    description: "SID of the account that is the target of an administrative action"
  - id: profileOwner
    description: "SID of the user whose NTUSER profile owns this per-user artifact"

known-containers:
  - ProfileList
  - MountPoints2
  - Security-4624
  - Security-4625
  - Security-4634
  - Security-4648
  - Security-4688
  - Security-4720
  - Security-1102
  - SAM
  - UserAssist
  - BAM
  - PartitionDiagnostic-1006
  - PowerShell-4104
  - Credentials-cached
  - Run-Keys
  - Scheduled-Tasks
  - SRUM-Process
provenance:
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
---

# User SID

## What it is
A variable-length binary identifier assigned by Windows to every principal (user, group, machine, service account). Unlike usernames, SIDs do not change when the account is renamed — they're the durable cross-artifact key for attributing activity to a specific principal.

## Forensic value
- **The only reliable user-identity pivot** across Windows artifacts. Usernames appear in many places; SIDs are the authoritative resolution.
- **Per-user hive attribution.** NTUSER.DAT and UsrClass.dat are tied to a SID via `ProfileList\<SID>`. Without this linkage, per-user artifacts (MountPoints2, UserAssist, shellbags) cannot be attributed to a specific human account.
- **Multi-user session disambiguation.** Security event 4624 carries SubjectUserSid and TargetUserSid; essential for resolving who was active when a given event occurred.

## Encoding variations

| Artifact | Where |
|---|---|
| ProfileList | subkey name under `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` |
| MountPoints2 | derived from the owning NTUSER.DAT hive (via ProfileList) |
| Security-4624 | `TargetUserSid` and `SubjectUserSid` event fields |
| SAM | user account RIDs mapped to machine SID |
| UserAssist | NTUSER.DAT owner's SID |
| Partition/Diagnostic 1006 | `UserSid` event field (Win10 1803+, kernel-logged) |
