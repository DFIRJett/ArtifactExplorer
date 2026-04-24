---
name: Security-4624
title-description: "An account was successfully logged on"
aliases:
- successful logon event
- Windows 4624
- logon audit
link: user
tags:
- timestamp-carrying
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2025'
location:
  channel: Security
  event-id: 4624
  log-file: '%WINDIR%\System32\winevt\Logs\Security.evtx'
  addressing: channel+event-id
fields:
- name: time-created
  kind: timestamp
  location: System\TimeCreated SystemTime
  encoding: iso8601-utc
  clock: system
  resolution: 1us
- name: subject-user-sid
  kind: identifier
  location: EventData\SubjectUserSid
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: actingUser
  note: typically SYSTEM (S-1-5-18) for interactive logons; represents the authority that requested the logon
- name: subject-user-name
  kind: identifier
  location: EventData\SubjectUserName
  encoding: utf-16le
  note: account name of the subject — usually the machine account ending in $ or SYSTEM
- name: subject-domain-name
  kind: identifier
  location: EventData\SubjectDomainName
  encoding: utf-16le
  note: domain / workgroup / computer name of the subject
- name: subject-logon-id
  kind: identifier
  location: EventData\SubjectLogonId
  encoding: hex-uint64
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: logon ID of the session that REPORTED the logon (usually 0x3e7 for SYSTEM); distinct from TargetLogonId which is the session being created
- name: target-user-sid
  kind: identifier
  location: EventData\TargetUserSid
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: authenticatingUser
  note: the account being logged on — the forensic target
- name: target-user-name
  kind: identifier
  location: EventData\TargetUserName
  encoding: utf-16le
- name: target-domain-name
  kind: identifier
  location: EventData\TargetDomainName
  encoding: utf-16le
- name: target-logon-id
  kind: identifier
  location: EventData\TargetLogonId
  encoding: hex-uint64
  references-data:
  - concept: LogonSessionId
    role: identitySubject
  note: "THE LUID — unique session identifier assigned by LSASS at logon. Appears as SubjectLogonId on every in-session 4688/4663/4657/4672/5140, and as TargetLogonId on the matching 4634/4647 logoff. The single most important session-scope join key in Security.evtx."
- name: logon-type
  kind: enum
  location: EventData\LogonType
  encoding: uint32
  note: "Per MS Learn documentation, 13 values: 0=System, 2=interactive, 3=network, 4=batch, 5=service, 7=unlock, 8=networkCleartext, 9=newCredentials, 10=remoteInteractive(RDP), 11=cachedInteractive, 12=cachedRemoteInteractive (not widely observed in practice — documented Win8+), 13=cachedUnlock. Types 0, 12, and 13 are rarely-surfaced in day-to-day analysis but worth recognizing for edge-case triage."
- name: logon-process-name
  kind: identifier
  location: EventData\LogonProcessName
  encoding: utf-16le
  note: e.g., 'User32', 'Advapi', 'NtLmSsp', 'Kerberos'
- name: authentication-package
  kind: identifier
  location: EventData\AuthenticationPackageName
  encoding: utf-16le
  note: NTLM / Kerberos / Negotiate — the auth protocol used
- name: logon-guid
  kind: identifier
  location: EventData\LogonGuid
  encoding: guid-string
  note: "Kerberos correlation key — non-zero only for Kerberos logons. Ties 4624 to related 4769 (TGS) / 4648 (explicit creds) / 4964 (special group) events for the same logon. All zeros (00000000-...) when NTLM or local. Caveat per UWS: LogonGuid↔4769 correlation is frequently unreliable in practice — LogonGuid may be all-zero on 4624 even when Kerberos was used, and 4769 events may not always carry a matching GUID. Fall back to correlating via TargetUserName + workstation + time-proximity when GUID-based correlation fails."
- name: lm-package-name
  kind: identifier
  location: EventData\LmPackageName
  encoding: utf-16le
  note: "NTLM version: 'NTLM V1' / 'NTLM V2' / 'LM' (deprecated). Populated only when AuthenticationPackageName == NTLM. '-' for Kerberos. NTLM V1 in a modern environment is a strong anomaly — hunting signal for downgrade attacks."
- name: key-length
  kind: counter
  location: EventData\KeyLength
  encoding: uint32
  note: NTLM session key length (128 bits typical). Always 0 for Kerberos — don't interpret as weak crypto.
- name: transmitted-services
  kind: identifier
  location: EventData\TransmittedServices
  encoding: utf-16le
  note: "Kerberos S4U (constrained/protocol-transition) delegation chain. '-' when no delegation. Populated entries indicate the logon traversed one or more delegation hops — critical signal for analyzing Kerberoasting / S4U2Self / S4U2Proxy abuse."
- name: impersonation-level
  kind: enum
  location: EventData\ImpersonationLevel
  encoding: utf-16le
  note: "Anonymous / Identification / Impersonation / Delegation. Delegation on a non-network logon is anomalous — examine the 4648 that spawned the token. (Added in v1 / Win8+.)"
- name: restricted-admin-mode
  kind: flags
  location: EventData\RestrictedAdminMode
  encoding: "'Yes' / 'No' / '-'"
  note: "Populated only on LogonType 10 (RemoteInteractive / RDP). 'Yes' means RDP used Restricted Admin mode (no credential materialization on target) — a hunting signal for either admin defense hygiene OR RDP-RestrictedAdmin pass-the-hash technique. Added v2 / Win10+."
- name: target-outbound-user-name
  kind: identifier
  location: EventData\TargetOutboundUserName
  encoding: utf-16le
  note: "'Network Account Name' — populated on LogonType 9 (NewCredentials = runas /netonly). Shows the alternate credential set the spawned process will use for outbound network auth. v2 / Win10+."
- name: target-outbound-domain-name
  kind: identifier
  location: EventData\TargetOutboundDomainName
  encoding: utf-16le
  note: domain for target-outbound-user-name. v2 / Win10+.
- name: virtual-account
  kind: flags
  location: EventData\VirtualAccount
  encoding: "'Yes' / 'No'"
  note: "'Yes' indicates the logon is for a Managed Service Account (MSA/gMSA) or virtual service account. v2 / Win10+."
- name: target-linked-logon-id
  kind: identifier
  location: EventData\TargetLinkedLogonId
  encoding: hex-uint64
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: "LUID of the paired logon session for UAC split-token scenarios (standard + elevated). Same interactive user produces two 4624s — their TargetLogonIds reference each other via TargetLinkedLogonId. v2 / Win10+."
- name: workstation-name
  kind: identifier
  location: EventData\WorkstationName
  encoding: utf-16le
  note: NetBIOS name of the host the logon came from; blank for local interactive
- name: source-ip
  kind: identifier
  location: EventData\IpAddress
  encoding: ip-address-string
  note: source IP for network/RDP logons; '-' for local
- name: source-port
  kind: counter
  location: EventData\IpPort
  encoding: uint16
- name: process-id
  kind: identifier
  location: EventData\ProcessId
  encoding: hex-uint64
  note: PID of the process that requested the logon. Cross-check with 4688.NewProcessId for the logon-requesting process.
- name: process-name
  kind: path
  location: EventData\ProcessName
  encoding: utf-16le
  note: process that initiated the logon (lsass.exe, winlogon.exe, svchost.exe, etc.)
- name: elevated-token
  kind: flags
  location: EventData\ElevatedToken (Win10+)
  encoding: '''Yes'' / ''No'''
  note: whether the session is running with full admin token — UAC elevation signal
- name: remote-credential-guard
  kind: flags
  location: EventData\RemoteCredentialGuard (Windows Server 2025+)
  encoding: "'Yes' / 'No' / '-'"
  note: "Windows Server 2025 added a Remote Credential Guard field — 'Yes' indicates the logon leveraged RCG to keep credentials on the originating host (no token materialization at the target). Normally '-' on pre-2025. Presence of 'Yes' on a sensitive target is a defense-posture signal; absence where policy required it is an investigation signal."
observations:
- proposition: AUTHENTICATED
  ceiling: C4
  note: 'Kernel-logged, tamper-hard at the service level. Carries enough detail

    (target SID, logon type, source, process) to serve as the primary

    session anchor for downstream user-attribution claims.


    Historical equivalence: 4624 succeeds legacy events 528 (successful

    logon) and 540 (network logon) from pre-Vista Windows. When ingesting

    archived logs from Win2000/XP/2003 hosts, treat 528/540 as the same

    event class for investigation purposes — field names and structure

    differ but semantics are equivalent.

    '
  qualifier-map:
    principal: field:target-user-sid
    target: this-system
    result: success
    method: field:authentication-package
    source: field:source-ip
    time.start: field:time-created
  preconditions:
  - Security.evtx retained and not cleared (check for 1102)
  - Audit policy has 'Logon' success auditing enabled
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: record checksum + chunk CRC (EVTX-native)
  known-cleaners:
  - tool: wevtutil clear-log Security
    typically-removes: full
    note: emits Security 1102 on this clear — counter-signal
  - tool: service-stop + offline edit
    typically-removes: full
    note: high-skill technique; leaves EventLog service outage pattern
  survival-signals:
  - Security 1102 present = channel was cleared, known gap
  - 4624 events for a user SID + no corresponding 4634 = session still open OR logoff events cleared selectively
  - "Type-10 (RDP) 4624 events roll off QUICKLY in circular-buffer Security.evtx on busy RDP hosts — a quiet RDP session can generate hundreds of 4624/4634 per day (disconnect/reconnect, credential refresh). When investigating historical RDP activity on a busy host, assume 4624 coverage extends back days-to-weeks, not months. Cross-corroborate with TS-LSM-21/TS-LSM-25 + TerminalServices-RDPClient-1024 on the source host (Carvey 2022)."
cross-references:
  registered-processes:
  - "LogonProcess values in EventData\\LogonProcessName (e.g., 'User32', 'Advapi', 'NtLmSsp', 'Kerberos', 'Seclogo') correlate with Security 4611 ('trusted logon process registered') events. 4611 fires when a logon process registers with LSA at boot; subsequent 4624 events list the registered process names. A 4624 referencing a LogonProcess NOT matching any 4611 is anomalous (e.g., an unofficial logon-process module)."
  known-siblings:
  - Security-4625
  - Security-4634
  - Security-4647
  - Security-4648
  - Security-4672
  - Security-4769
  - Security-5140
  - TS-LSM-21
provenance: [ms-event-4624, uws-event-4624]
---

# Security Event 4624 — Successful Logon

## Forensic value
Primary Windows authentication audit event. Every successful logon (interactive, RDP, network, service, etc.) emits a 4624. For any per-user attribution question, 4624 is the canonical "when did this user have an active session" anchor.

Logon type is the critical filter: type 2 = someone physically at the keyboard or console, type 10 = RDP, type 3 = network share access, type 5 = service runs under the account. Each type implies a different threat model.

## Known quirks
- **SubjectUserSid usually SYSTEM**, not the user logging in. The user is in `TargetUserSid`. Easy off-by-one for new examiners.
- **Blank / hyphen fields for local interactive** — `WorkstationName` and `IpAddress` often absent for console logons; don't interpret absence as missing data.
- **TargetLogonId is the session bridge** — correlate across other events using this hex ID to reconstruct what happened in the session.
- **Elevated-token field** (Win10+) — `"Yes"` indicates the session has admin-token; `"No"` is standard user even if the account is Administrators-group member (UAC-split scenarios).
- **Kerberos vs NTLM via `AuthenticationPackageName`** — often investigative signal in lateral movement.

## Practice hint
Parse a Security.evtx over a known-active workday. Filter to 4624, then group by TargetUserSid + TargetLogonId. Each distinct LogonId is one session. Cross-reference with 4634 to find session-close times.
