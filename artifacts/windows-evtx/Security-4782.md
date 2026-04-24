---
name: Security-4782
title-description: "The password hash of an account was accessed (ADMT password migration)"
aliases: [4782, password hash accessed, ADMT password migration]
link: user
link-secondary: persistence
tags: [ad-audit, account-lifecycle]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows-server: {min: '2008', max: '2025'}
location:
  channel: Security
  event-id: 4782
  provider: Microsoft-Windows-Security-Auditing
  addressing: evtx-record
  note: "Fires on a DC (DC-role-only; does NOT fire on workstations or member servers) when the Active Directory Migration Toolkit (ADMT) PasswordMigrationFilter API extracts an account's password hash for inter-forest migration. Subcategory: 'Audit Other Account Management Events' (distinct from 'Audit User Account Management'). ON by default on DCs. IMPORTANT: 4782 is NOT a DCSync indicator despite widespread community claims — DCSync uses the DRS replication API (DRSGetNCChanges with Replicating-Directory-Changes-All GUID) which triggers Security-4662 (DS-Access subcategory), not 4782. See ms-event-4782 + uws-event-4782 for authoritative clarification."
fields:
- name: target-user-sid
  kind: identifier
  location: "EventData → TargetSid"
  encoding: SID
  references-data:
  - concept: UserSID
    role: identitySubject
  note: "Account whose password hash was extracted by ADMT. In legitimate use: source-domain account whose credential material is being migrated to the target forest."
- name: target-username
  kind: label
  location: "EventData → TargetUserName + TargetDomainName"
  encoding: utf-16le
  note: "SAM account name of the target. Anomalous if target is a privileged account (domain admin, krbtgt) outside a documented migration plan."
- name: subject-user-sid
  kind: identifier
  location: "EventData → SubjectUserSid"
  encoding: SID
  references-data:
  - concept: UserSID
    role: actingUser
  note: "Account that invoked the ADMT PasswordMigrationFilter. For legitimate use: the administrator running ADMT. Any 4782 with a non-admin, non-migration-service SubjectUserSid is suspicious but should be triaged as unauthorized ADMT / misuse-of-migration-tooling rather than DCSync."
- name: subject-logon-id
  kind: identifier
  location: "EventData → SubjectLogonId"
  encoding: hex LUID
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: "Session LUID of the acting account on the DC."
- name: event-time
  kind: timestamp
  location: "System/TimeCreated"
  encoding: xs:dateTime UTC
  clock: DC system
  resolution: 1ms
  note: "Timestamp of the ADMT password-migration API call."
observations:
- proposition: ACCOUNT_CREDENTIAL_MIGRATED
  ceiling: C3
  note: 'Security-4782 records ADMT password migration, not DCSync. Legitimate use is a planned inter-forest migration event with ADMT tooling. Absence in normal operations is expected — most environments never fire 4782. Any 4782 on a non-migration DC, or outside a documented migration window, warrants investigation as misuse-of-migration-tooling. Tier-3 analysts pursuing DCSync detection should pivot to Security-4662 (DS-Access subcategory, Replicating-Directory-Changes-All GUID) — the authoritative DCSync signal — rather than 4782.'
  qualifier-map:
    actor.user: field:subject-user-sid
    object.user: field:target-user-sid
    time.start: field:event-time
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX-level; replicated across DCs
  survival-signals:
  - 4782 firing on a DC that has no documented ADMT migration plan = misuse-of-migration-tooling or unauthorized ADMT install
  - Bulk 4782 events for many privileged accounts = possible credential-harvesting via ADMT (rare attacker pattern; noisier than DCSync — attackers usually prefer 4662-invisible replication instead)
  - 4782 TargetUserName = krbtgt in any context is a red-alert event (no legitimate ADMT migration migrates krbtgt) — but DO NOT assume DCSync; investigate the ADMT install and SubjectUserSid's session provenance
provenance: [ms-event-4782, ms-audit-other-account-management, uws-event-4782, eventsentry-event-4782]
---

# Security-4782 — Password Hash Migrated (ADMT)

## Forensic value
Fires on DCs when the Active Directory Migration Toolkit's `PasswordMigrationFilter` API extracts an account's password hash. Used in inter-forest migrations to carry credential material from a source domain to a target domain. Most environments never fire 4782.

## NOT a DCSync indicator

Historical community sources — including older SIEM rule sets and blog posts — incorrectly conflate 4782 with DCSync detection. **This is wrong.** MS Learn, Ultimate Windows Security, and EventSentry all confirm 4782 fires only during ADMT password migration. The actual DCSync technique (MITRE T1003.006, Mimikatz `lsadump::dcsync`, Impacket `secretsdump.py -just-dc-ntlm`) uses the DRS replication API `DRSGetNCChanges` with the Replicating-Directory-Changes-All extended right, which triggers **Security-4662** (Directory Service Access subcategory) — not 4782.

Detection logic that alerts on all 4782 events as "DCSync" produces zero-true-positive alerts in DCSync-targeted environments and distracts from the real signal at 4662.

## Triage

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4782} | ForEach-Object {
    $x = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time = $_.TimeCreated
        Target = ($x.Event.EventData.Data | ? Name -eq 'TargetUserName').'#text'
        Subject = ($x.Event.EventData.Data | ? Name -eq 'SubjectUserName').'#text'
        SubjectDomain = ($x.Event.EventData.Data | ? Name -eq 'SubjectDomainName').'#text'
    }
}
```

Alert triage: any 4782 on a DC with no documented ADMT migration plan warrants investigation as unauthorized ADMT use or misuse of migration tooling. For DCSync hunting, pivot to Security-4662 instead.

## Cross-references
- **Security-4662** — Directory Service Access: this is the correct DCSync signal (Replicating-Directory-Changes-All GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`). Not currently in this corpus — queued as high-value authoring target.
- **MITRE T1003.006** — applies to 4662, NOT 4782. Removed from 4782 provenance 2026-04-23.

## Corpus correction history
2026-04-23: full rewrite from "DCSync signature" framing to "ADMT password migration" per source-audit (see `tools/_security_4782_audit.yaml`). 8 MAJOR viewer-critical findings resolved: title, aliases, tags, location.note, platform (workstation-key removed, server-min 2008R2→2008, max 2022→2025), observation body, anti-forensic survival signals, provenance (mitre-t1003-006 removed). Prior framing was consistent with mid-2010s community DCSync-detection writeups but contradicts primary MS Learn documentation and three independent community sources (UWS, EventSentry, Metcalf/ADSecurity).
