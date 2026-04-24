---
name: Kerberos-Tickets-Cache
title-description: "In-memory Kerberos ticket cache (LSASS) — TGTs and service tickets per logon session"
aliases:
- Kerberos ticket cache
- TGT cache
- service tickets cache
- LSASS ticket store
link: user
link-secondary: persistence
tags:
- credential-material
- lateral-movement
- itm:ME
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: Kerberos-Tickets-Cache
platform:
  windows:
    min: NT5.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  live-ram: "LSASS.exe process memory — Kerberos LSA provider (kerberos.dll) data structures"
  extraction-evidence: "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\\ (machine-cert-related); %WINDIR%\\debug\\PASSWD.LOG (legacy debug); memory dump"
  addressing: memory-address / process-memory
  note: "Kerberos tickets (TGTs, service tickets, referral tickets) are NOT persisted to disk by default — they live in LSASS memory associated with each active logon session. For DFIR, Kerberos ticket cache acquisition requires a memory dump (live-system MiniDump of lsass.exe, Magnet RAM Capture of full RAM, or hiberfil.sys analysis). Offline, Kerberos tickets are extractable from memory images with Volatility (windows.lsadump.Kerberos plugin) or mimikatz sekurlsa::tickets / kerberos::list. Once extracted, tickets can be replayed (mimikatz kerberos::ptt) or analyzed for attack-chain reconstruction."
fields:
- name: tgt-ticket
  kind: content
  location: "LSASS memory — KERB_TICKET structures per logon session"
  encoding: ASN.1 Kerberos Ticket (RFC 4120)
  note: "Ticket-Granting Ticket for the user. Includes: client principal (username@REALM), target principal (krbtgt/REALM), encrypted flags, service-ticket-validity-window, and encrypted session key. Exporting a TGT enables 'pass-the-ticket' (PtT) attacks — the attacker replays the TGT on a different host to impersonate the user without needing their password or NTLM hash. Canonical lateral-movement technique."
- name: service-ticket
  kind: content
  location: "LSASS memory — one per service accessed"
  encoding: ASN.1 Kerberos Ticket
  note: "Service ticket for a specific SPN the user has authenticated to. Target principal format: <service>/<hostname>[@REALM] (e.g., cifs/fileserver.corp.example.com, HTTP/sharepoint.corp.example.com, LDAP/dc01.corp.example.com). Enumeration reveals every service the user's session has touched. For lateral-movement tracing: each service ticket = one access event."
- name: session-key
  kind: content
  location: "inside each ticket structure — EncryptionKey field"
  encoding: AES-256 / AES-128 / RC4 key (algorithm-dependent)
  note: "Per-ticket session key used to sign requests and responses. Exporting enables ticket replay. Modern domain functional levels prefer AES encryption (aes256-cts-hmac-sha1-96); legacy default was RC4-HMAC (MD5) which is now flagged."
- name: logon-session-id
  kind: identifier
  location: "KERB_LOGON_SESSION_DATA → LogonId field"
  encoding: LUID (8-byte)
  references-data:
  - concept: LogonSessionId
    role: sessionContext
  note: "Locally-unique identifier for the Windows logon session that holds this ticket. Joins to Security-4624 LogonID field. Multiple tickets under the same LogonID = tickets acquired during the same user-session."
- name: client-principal
  kind: identifier
  location: "ticket → cname field"
  encoding: Kerberos principal-name string
  references-data:
  - concept: UserSID
    role: authenticatingUser
  note: "User principal name (user@REALM) or NT-format username. The authenticated identity this ticket represents."
- name: ticket-flags
  kind: flags
  location: "ticket → flags field"
  encoding: Kerberos flag bitmap
  note: "Forwardable, Renewable, Initial, Pre-Authenticated, Proxiable, May-Postdate, and others. Attackers creating Golden Tickets (forged TGTs) or Silver Tickets (forged service tickets) often set anomalous flag combinations — 'all flags set' or missing Pre-Authenticated flag are classic forged-ticket signatures."
- name: renew-till
  kind: timestamp
  location: "ticket → renew-till field"
  encoding: ASN.1 GeneralizedTime (UTC)
  clock: system (issued by KDC)
  resolution: 1s
  note: "Maximum time the ticket can be renewed. Golden Tickets forged by attackers commonly have extremely distant renew-till values (10 years from creation) — a classic forgery signature. Legitimate tickets typically have renew-till ≤ 7 days from start-time per standard domain policy."
- name: start-end-time
  kind: timestamp
  location: "ticket → starttime + endtime fields"
  encoding: ASN.1 GeneralizedTime (UTC)
  clock: system (issued by KDC)
  resolution: 1s
  note: "Validity window. Standard domain tickets are valid 10 hours. Golden Tickets / Silver Tickets often have abnormal windows. Delta between starttime and endtime not matching domain policy = forgery signal."
observations:
- proposition: AUTHENTICATED
  ceiling: C4
  note: 'The Kerberos ticket cache is the authoritative record of every
    authentication the user''s session has performed against Kerberos-
    protected services. Each service ticket is direct evidence of
    access to that service. TGT export enables pass-the-ticket lateral
    movement — one of the canonical post-compromise techniques. Forged
    tickets (Golden / Silver / Diamond / Sapphire) are detectable by
    comparing issued fields against domain policy norms: unusual
    renew-till, anomalous ticket-flag combinations, client-principal
    that doesn''t exist in AD, service-principal against a host the
    user has no business touching. Requires memory acquisition —
    prioritize live lsass dump OR hiberfil.sys / memory image
    acquisition for any intrusion with Kerberos-relevant scope.'
  qualifier-map:
    actor.user: field:client-principal
    actor.session: field:logon-session-id
    object.service: field:service-ticket
    time.start: field:start-end-time
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: Kerberos signature (PAC checksum) validates ticket integrity; forged tickets without valid KDC signature fail PAC validation on modern Windows
  known-cleaners:
  - tool: klist purge (per-session)
    typically-removes: current session's ticket cache — new auth requires re-acquiring tickets
  - tool: logoff
    typically-removes: all of that session's tickets
  survival-signals:
  - TGT with renew-till > 7 days past start-time on a standard domain = likely Golden Ticket forgery
  - Service ticket for an SPN / host the user has no documented business with = lateral pivot evidence
  - LogonSession tickets exist for a LogonID that has no corresponding Security-4624 = injected session (post-compromise access smuggling)
provenance:
  - ietf-2005-rfc-4120-the-kerberos-network
  - mitre-t1558
  - foundation-2021-volatility-hibernate-address-s
exit-node:
  is-terminus: true
  primary-source: mitre-t1558
  attribution-sentence: 'Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket (MITRE ATT&CK, n.d.).'
  terminates:
    - ACCESSED_SERVICE
  sources:
    - ietf-2005-rfc-4120-the-kerberos-network
    - mitre-t1558
  reasoning: >-
    Each Kerberos service ticket is a cryptographically-bound, KDC-issued credential naming the client principal and target service principal. For the question 'did this user access that service,' the ticket itself is the self-contained proof — no further correlation to service-side logs or network captures is needed to establish authenticated access occurred.
  implications: >-
    Defensible attribution for service access in Kerberos-authenticated environments. Ticket-granting-ticket (TGT) presence proves initial authentication; service tickets prove subsequent service access. Golden/Silver ticket forgery detection leans on anomalies in these records — signature mismatches, unusual lifetimes, orphan SPNs.
  preconditions: "Ticket cache accessible (live kernel extraction, memory dump carving, or LSASS-dump minikatz extraction)."
  identifier-terminals-referenced:
    - UserSID
    - ServiceName
---

# Kerberos Ticket Cache

## Forensic value
Every authenticated Kerberos session on Windows holds its TGT and accumulated service tickets in LSASS memory, scoped per logon session. Tickets are NOT persisted to disk by default — forensic access requires:

- Live memory dump (MiniDump of lsass.exe, `procdump lsass.exe`)
- Full RAM capture (Magnet RAM Capture, WinPMEM)
- hiberfil.sys analysis
- VSC snapshot of lsass memory via specialized tooling

Once extracted, tickets reveal:
- **Which services the user session authenticated to** (one service ticket per SPN)
- **User principal** the tickets represent
- **Session keys** (enable pass-the-ticket replay)
- **Forgery indicators** (anomalous renew-till, missing pre-auth, impossible timestamps)

## Attack techniques surfaced
- **Pass-the-Ticket (PtT)** — attacker exports TGT or service ticket, replays on another host to impersonate the user
- **Golden Ticket** — attacker with KRBTGT hash forges a TGT for any user with arbitrary privileges; detectable by renew-till > domain policy and missing PAC signature
- **Silver Ticket** — attacker with service-account password forges a service ticket bypassing KDC; detectable by PAC validation failure
- **Kerberoasting** — attacker requests service tickets for SPNs, extracts RC4-encrypted portions, cracks offline for service-account passwords

## Concept references
- LogonSessionId (LogonID links ticket to logon session)
- UserSID (via client-principal → SID translation in PAC)

## Acquisition
```powershell
# Live lsass dump (elevated, requires SeDebugPrivilege + LSA Protection off or bypass)
procdump.exe -ma lsass.exe lsass.dmp
# OR MiniDumpWriteDump via PowerShell

# Full memory capture
# MagnetRAMCapture.exe / WinPMEM / FTK Imager memory acquisition

# Offline memory image — best evidence
```

## Parsing
```
mimikatz
> sekurlsa::tickets /export
> kerberos::list

# Or offline
vol.py -f memory.raw windows.lsadump.Kerberos
```

## Cross-reference
- **Security-4624 LogonID** — join to ticket LogonID for session-context
- **Security-4768** — TGT request event on KDC side
- **Security-4769** — service ticket request event on KDC side
- **Security-4771** — Kerberos pre-authentication failure (AS-REP roasting detection)
- **DPAPI-MasterKeys** — LSASS memory also holds DPAPI secrets; acquire alongside tickets
- **Hiberfil** — ticket cache survives in hibernation image

## Attack-chain example
Attacker has initial access to endpoint A. Dumps lsass.exe memory. Extracts TGT for a privileged user whose session was active on endpoint A. On endpoint B (which the attacker can reach but doesn't have creds for), injects the TGT via mimikatz kerberos::ptt. Now authenticates to domain resources as the privileged user. No password was ever cracked; no failed-login events generated. Pure lateral movement via stolen ticket.

Forensic tracing: memory acquired from endpoint A shows the original ticket cache. Endpoint B's Security-4769 events show service-ticket requests using the stolen TGT but with endpoint B's IP — contradiction reveals the ticket theft.

## Practice hint
On a domain-joined lab VM, authenticate to a few network services. Run `klist` — your session's tickets enumerate. Now run mimikatz `sekurlsa::tickets /export` — each ticket exported as a .kirbi file. Those files are what an attacker would exfil for offline pass-the-ticket. This end-to-end extraction is what DFIR has to reconstruct in memory-forensics cases.
