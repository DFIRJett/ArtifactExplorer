---
name: UAL-Database
title-description: "User Access Logging (UAL) — Server 2012+ 24-month per-user service-access history"
aliases:
- User Access Logging
- UAL database
- SystemIdentity.mdb / Current.mdb
link: user
tags:
- server-only
- client-ip-history
- authentication-audit
volatility: persistent
interaction-required: none
substrate: windows-ess
substrate-instance: User-Access-Logging
platform:
  windows-server:
    min: '2012'
    max: '2022'
  windows:
    min: 'N/A — Server-only feature (not on client SKUs)'
location:
  path: '%WINDIR%\System32\LogFiles\Sur\'
  addressing: file-path
  note: "Directory holds: SystemIdentity.mdb (the identity-to-GUID map), Current.mdb (active year-to-date log), and {GUID}.mdb archives (one per previous year). All three are ESE databases — parse with esedbexport, libesedb, or the KAPE UAL module. On a Server host that has been running for 2+ years, expect SystemIdentity.mdb + Current.mdb + 1–2 archive .mdb files."
fields:
- name: client-ip
  kind: identifier
  location: Current.mdb CLIENTS table → Address column
  encoding: ip-address-string (IPv4 or IPv6 text form)
  references-data:
  - concept: IPAddress
    role: authSourceIp
  note: "Source IP address of the client contacting a UAL-instrumented server role (AD FS, IIS, RDP, DHCP, DNS, File Services, etc.). Per-row granularity keyed on (role, client IP, username, date)."
- name: user-name
  kind: identifier
  location: Current.mdb CLIENTS table → UserName column
  note: "NT-format user name (DOMAIN\\user) authenticating to the instrumented role. Combined with client-ip gives (who, from where) per access — a forensic gem not otherwise available on the server side."
- name: activity-date
  kind: timestamp
  location: Current.mdb CLIENTS table → FirstSeen + LastSeen + ActivityCount columns
  encoding: ole-date (double) or filetime
  clock: system
  resolution: 1s
  note: "FirstSeen and LastSeen bracket the activity window for this (role, IP, user) triple for the day. ActivityCount = number of role-accesses that day. Data is aggregated per day, not per event."
- name: role-guid
  kind: identifier
  location: SystemIdentity.mdb ROLE_IDS table → GUID column
  encoding: guid-string
  note: "Unique identifier of the Windows server role generating the access entry. Cross-reference against ROLE_IDS → RoleName to translate (e.g., {ad495fc3-0eaa-413d-ba7d-8b13fa7ec598} = 'File Server', {10a9226f-50ee-49d8-a393-9a501d47ce04} = 'Active Directory Domain Services')."
- name: tenant-identifier
  kind: identifier
  location: SystemIdentity.mdb TENANTS table
  note: "For Windows Server 2016+ hosting multiple tenants (typically Hyper-V / RDS virtualization). Usually unused on stand-alone servers."
- name: chassis-serial
  kind: identifier
  location: SystemIdentity.mdb SYSTEM_IDENTITY table → ChassisSerialNumber
  note: "Hardware chassis serial. Aids in verifying the UAL data wasn't transplanted from a different host."
- name: os-version
  kind: label
  location: SystemIdentity.mdb SYSTEM_IDENTITY table → OSBuildNumber + OSMajor + OSMinor
  note: "OS version on the host when UAL was initialized. Informational; helps select the right ESE schema version for parsing."
observations:
- proposition: AUTHENTICATED_TO_ROLE
  ceiling: C4
  note: 'UAL is the single most valuable per-client forensic artifact on
    Windows Server. It preserves 24 months (2 x yearly archives +
    current) of (role, client IP, user, date, count) tuples per server
    role instrumented with UAL. For lateral-movement investigations, UAL
    answers "what IPs connected to which services on this server as
    which users in which time window" without depending on EVTX
    retention. No client-SKU equivalent exists — Windows 10/11 does NOT
    have UAL.'
  qualifier-map:
    actor.user: field:user-name
    actor.source.ip: field:client-ip
    object.role: field:role-guid
    time.start: field:activity-date
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: ESE page-level checksums + transactional write
  known-cleaners:
  - tool: stop + delete Current.mdb
    typically-removes: prospective (next day rebuilds current; does not recover archives)
  - tool: delete archive {GUID}.mdb files
    typically-removes: one year of historical data per file deleted
  survival-signals:
  - UAL files missing on a Server 2012+ host with uptime > 1 year = evidence has been deleted (rare outside deliberate sanitization)
  - Current.mdb FirstSeen dates much more recent than the host install date = UAL was reset
provenance:
  - ms-user-access-logging-ual
  - koroshec-2021-user-access-logging-ual-a-uniq
  - zimmerman-2023-kape-ual-compound-target-sqlec
---

# User Access Logging (UAL)

## Forensic value
UAL is the best-kept forensic secret on Windows Server. Introduced in Server 2012 for license compliance tracking, it aggregates per-day access records for every instrumented role (AD DS, AD FS, IIS, DHCP, DNS, File Services, RDP, Print Services, etc.) and keeps them for up to **24 months**. For incident response on a server, UAL answers questions that Security.evtx cannot because the events retained are aggregate, not per-authentication:

- "Which IPs accessed the file shares on this server in the last 18 months?"
- "Did this domain admin's SID ever authenticate from this previously-unseen IP?"
- "When did this server first see this client hostname?"

None of this is obtainable from Security.evtx once logs roll, and UAL retention far exceeds typical EVTX retention on production servers.

**Not present on client SKUs.** Windows 10 / 11 do not have UAL.

## Concept reference
- IPAddress (client-ip)

## File layout
`%WINDIR%\System32\LogFiles\Sur\`
- `SystemIdentity.mdb` — role-GUID-to-name map, tenant info, system identity
- `Current.mdb` — year-to-date aggregated access records
- `{GUID}.mdb` — archive per prior year (1 per year, older rolls off at 2 years)

All three are ESE databases. Acquire the whole `Sur\` directory — the MDBs reference each other.

## Parsing
```cmd
esedbexport.exe -t .\ual_export SystemIdentity.mdb
esedbexport.exe -t .\ual_export Current.mdb
```

Then join CLIENTS table (from Current.mdb / archive.mdb) with ROLE_IDS (from SystemIdentity.mdb) on `RoleGuid` to translate GUIDs to human-readable role names. Zimmerman's SQLECmd has a UAL map that does this automatically.

## Practice hint
On a Windows Server lab (Server 2019 DC): wait for at least 24 hours of uptime with some file-share / RDP activity from another host. Copy `SystemIdentity.mdb` and `Current.mdb` offline (stop the `User Access Logging Service` first). Run esedbexport + join. Verify the client IP of your test machine appears in CLIENTS with ActivityCount reflecting your test connections.
