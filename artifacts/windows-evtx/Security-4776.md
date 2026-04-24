---
name: Security-4776
title-description: "The computer attempted to validate the credentials for an account"
aliases:
- 4776
- NTLM credential validation
- MSV1_0 validation
link: user
link-secondary: network
tags:
- authentication-audit
- ntlm-visibility
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows:
    min: '7'
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  channel: Security
  event-id: 4776
  provider: "Microsoft-Windows-Security-Auditing"
  addressing: evtx-record
  note: "Fires on the validating machine whenever the Microsoft_Authentication_Package_V1_0 (MSV1_0) validates an account's NTLM credentials. For domain accounts, the DC is the validator and logs 4776 — giving a domain-wide NTLM-authentication audit trail that neither 4624 nor 4625 alone provides. For local-account auth, the local host logs 4776. Subcategory: 'Audit Credential Validation' — usually ON by default on DCs."
fields:
- name: workstation-name
  kind: identifier
  location: "EventData → Workstation"
  encoding: NetBIOS hostname
  references-data:
  - concept: MachineNetBIOS
    role: trackerMachineId
  note: "NetBIOS name of the workstation attempting authentication — the CLIENT. Crucial for pass-the-hash detection: a workstation name that does NOT exist in the domain is a tell that an attacker forged the name. Also the same-workstation-many-accounts pattern reveals credential spraying."
- name: target-username
  kind: label
  location: "EventData → TargetUserName"
  encoding: utf-16le
  references-data:
  - concept: UserSID
    role: targetUser
  note: "Account being validated. Multiple 4776 events for the same account from the same workstation in close time = normal. Many DIFFERENT accounts from ONE workstation = spray / enumeration. One account from MANY workstations = credential reuse / lateral movement."
- name: status
  kind: flags
  location: "EventData → Status"
  encoding: NTSTATUS hex
  note: "0x0 = validation succeeded. Non-zero = failed. Common failure codes: 0xC0000064 (no such user), 0xC000006A (wrong password), 0xC0000234 (account locked), 0xC0000072 (account disabled), 0xC0000234 (locked-out). Pattern of 0xC000006A across many accounts from same workstation = password-spray."
- name: error-code
  kind: flags
  location: "EventData → Status (duplicate of status on this event)"
  encoding: NTSTATUS
  note: "Same as Status. NTLM validation does not report sub-status — unlike 4625 which has both Status and SubStatus. Use Status alone for classification."
- name: event-time
  kind: timestamp
  location: "System/TimeCreated"
  encoding: xs:dateTime UTC
  clock: system (DC or local host acting as validator)
  resolution: 1ms
  note: "Validation moment. On a DC, 4776 timestamp precedes the 4624 / 4625 on the target server — joining them gives the full path (validator → target) of the NTLM auth."
observations:
- proposition: AUTHENTICATED
  ceiling: C3
  note: 'Security-4776 is the definitive NTLM-authentication audit event
    on Windows. For enterprises with DC-side Credential Validation
    auditing, 4776 provides domain-wide visibility into every NTLM
    auth attempt — regardless of which workstation initiated the
    auth or which target server accepted it. Key for: (1) pass-the-
    hash detection (forged Workstation names), (2) password-spray
    detection (one WS + many accounts + many 0xC000006A status),
    (3) credential-sharing detection (one account from many WS).
    For modern environments using Kerberos preferentially, 4776 still
    fires for local-account auth, NTLM fallback, and legacy protocol
    usage — its absence indicates potentially-misconfigured auditing
    rather than absence of auth.'
  qualifier-map:
    actor.user: field:target-username
    actor.source: field:workstation-name
    time.start: field:event-time
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX-level
  survival-signals:
  - 4776 events for a single account from an unfamiliar Workstation name = candidate pass-the-hash or credential-replay
  - Cluster of 4776 events for DIFFERENT accounts from same Workstation in short time = password spray
  - Same account 4776 from multiple Workstations simultaneously = credential sharing / token replay
  - 4776 for accounts that should never authenticate via NTLM (admin accounts restricted to Kerberos-only) = downgrade-attack signal
provenance: [ms-event-4776, mitre-t1110-003]
---

# Security-4776 — NTLM Credential Validation

## Forensic value
Fires on the VALIDATING machine (DC for domain accounts, local host for local accounts) whenever MSV1_0 validates NTLM credentials. Captures:

- Workstation name of the CLIENT attempting auth (NetBIOS)
- Target account username
- NTSTATUS result (0x0 = success, various failure codes)

Critical for enterprise-wide visibility of NTLM auth that Security-4624/4625 (per-target-host) alone doesn't provide.

## Concept references
- MachineNetBIOS, UserSID

## Typical triage patterns
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4776} -MaxEvents 5000 |
    ForEach-Object {
        $x = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time      = $_.TimeCreated
            Account   = ($x.Event.EventData.Data | ? Name -eq 'TargetUserName').'#text'
            Workstation = ($x.Event.EventData.Data | ? Name -eq 'Workstation').'#text'
            Status    = ($x.Event.EventData.Data | ? Name -eq 'Status').'#text'
        }
    } | Group-Object Workstation | Sort Count -Desc | Select -First 20
```

## Cross-reference
- **Security-4624** — target-host logon success following successful 4776
- **Security-4625** — target-host logon failure
- **Security-4768** — Kerberos AS-REQ (Kerberos alternative)
- **NTDS-dit** — account lookup for TargetUserName → SID translation
- **UAL-Database** — Server 2012+ per-client-IP aggregation for long-retention NTLM activity
