---
name: AnyDesk-Logs
title-description: "AnyDesk remote-access logs (ad.trace, ad_svc.trace, connection_trace.txt, service.conf)"
aliases:
- AnyDesk logs
- AnyDesk connection trace
- ad.trace
link: network
link-secondary: application
tags:
- ransomware-tell
- remote-access
- itm:IF
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: AnyDesk-Logs
platform:
  windows:
    min: '7'
    max: '11'
    note: "AnyDesk runs on every modern Windows client and server release. Not pre-installed on Windows — presence of AnyDesk is itself a signal in enterprise contexts that don't officially deploy it (attacker-installed remote-access tooling is extremely common in ransomware cases from ~2021 onward: BlackBasta, LockBit 3.0, Akira, Play)."
  windows-server:
    min: '2008R2'
    max: '2022'
location:
  path-user: "%APPDATA%\\AnyDesk\\ad.trace and connection_trace.txt"
  path-service: "%PROGRAMDATA%\\AnyDesk\\ad_svc.trace and service.conf"
  addressing: file-path
  note: "Two log scopes: user-scope (AppData, records outbound connections from this user) and service-scope (ProgramData, records service activity including inbound listener). Both scopes are plain-text log files that persist across reboots and are not rotated by default. Attackers portable-run AnyDesk (no install, no admin) from %TEMP% or a USB; in that case only the user-scope logs exist."
fields:
- name: ad-id
  kind: identifier
  location: "connection_trace.txt — each line is 'YYYY-MM-DD HH:MM:SS UTC <AD-ID>'"
  encoding: ascii text
  note: "The AnyDesk ID (9-10 digit number assigned to this AnyDesk instance) of the remote peer that connected or was connected to. For an attacker using AnyDesk as C2, this ID is their endpoint's AnyDesk ID — an IOC that joins to threat intel (many ransomware crews reuse AnyDesk IDs across intrusions). CONNECTION_TRACE IS ONE OF THE MOST VALUABLE SINGLE FILES IN A RANSOMWARE INVESTIGATION."
- name: connection-timestamp
  kind: timestamp
  location: "connection_trace.txt — per-line timestamp"
  encoding: "YYYY-MM-DD HH:MM:SS (UTC)"
  clock: system (reported as UTC)
  resolution: 1s
  note: "Exact moment of each inbound/outbound connection. Build per-session timeline directly from this file."
- name: peer-ip-address
  kind: identifier
  location: "ad.trace or ad_svc.trace — 'connecting to <IP>' / 'accepted from <IP>' log lines"
  encoding: ascii (dotted decimal or IPv6)
  references-data:
  - concept: IPAddress
    role: authSourceIp
  note: "Source or destination IP of remote AnyDesk peer. May be the attacker's VPN egress, a residential proxy, or a compromised host. For ransomware cases, cross-reference against threat-intel feeds of known attacker infrastructure."
- name: trace-event
  kind: content
  location: "ad.trace / ad_svc.trace — timestamped log lines"
  encoding: ascii text (AnyDesk-proprietary log format)
  note: "Per-operation log lines: session-start, session-end, file-transfer events, clipboard syncs, input events. Session-file-transfer lines identify data exfil (attacker uploads a file to the compromised host; attacker downloads a file off the host)."
- name: file-transfer-events
  kind: content
  location: "ad.trace — 'file_transfer' / 'upload' / 'download' log lines"
  encoding: ascii text
  note: "ALSO HIGH-VALUE: AnyDesk's built-in file-transfer tool is the attacker's exfil / tool-delivery channel. Every file transfer is logged with filename, direction, and timestamp. Correlates with payload-drop and data-exfil indicators elsewhere (Prefetch of tool binaries, UsnJrnl of exfil staging directories)."
- name: service-conf-id
  kind: identifier
  location: "service.conf — 'ad.anynet.id=<AD-ID>'"
  encoding: ini text
  note: "THIS host's AnyDesk ID. In a case where the victim was reached via an attacker's AnyDesk session, this ID is the victim's own — useful for validating which host of many is 'the one the attacker connected to.'"
- name: service-conf-password
  kind: content
  location: "service.conf — 'ad.anynet.passwd_salt', 'ad.anynet.passwd_hash'"
  encoding: base64
  note: "AnyDesk unattended-access password hash. Attackers who set an unattended password to guarantee re-entry leave this artifact; the hash is a detectable forensic footprint even if the attacker deletes the live service."
- name: file-mtimes
  kind: timestamp
  location: each log file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime = most recent log write time. Brackets the most recent AnyDesk session."
observations:
- proposition: COMMUNICATED
  ceiling: C4
  note: 'AnyDesk logs are gold-standard evidence in ransomware cases
    because the tool has become a near-universal remote-access choice
    across ransomware operators since 2021. Key forensic properties:
    plain text, persisted in both user (AppData) and service
    (ProgramData) scopes, includes remote AnyDesk IDs that frequently
    appear in multiple intrusions attributable to the same operator,
    records file transfers (both directions), and survives AnyDesk
    uninstall unless the attacker explicitly clears AppData/ProgramData
    directories. For any suspected ransomware engagement with remote-
    access lateral-movement component, AnyDesk-Logs should be the
    first artifact acquired and parsed.'
  qualifier-map:
    direction: bidirectional
    peer.id: field:ad-id
    peer.address: field:peer-ip-address
    time.start: field:connection-timestamp
anti-forensic:
  write-privilege: user
  integrity-mechanism: none (plain text)
  known-cleaners:
  - tool: "delete AppData\\AnyDesk\\ and ProgramData\\AnyDesk\\"
    typically-removes: all log content (attacker cleanup would need to remove BOTH scopes; they frequently miss ProgramData)
  survival-signals:
  - AnyDesk presence on a workstation with no documented enterprise AnyDesk deployment = investigate
  - connection_trace.txt with AD IDs that cross-reference to threat-intel-known ransomware operators = direct attribution signal
  - File-transfer log entries for archive files (.zip, .7z, .tar) immediately followed by an outbound session end = likely exfil pattern
  - service.conf with a set unattended-access password on a host where AnyDesk was 'portable-run only' = attacker persistence plant
provenance:
  - anydesk-2023-anydesk-log-file-locations-and
  - aa24-131a-2024-anydesk-in-ransomware-incident
  - research-2023-blackbasta-lockbit-use-of-anyd
---

# AnyDesk Logs

## Forensic value
AnyDesk (remote-access application by AnyDesk Software) maintains plaintext log files in two scopes:

**Per-user**: `%APPDATA%\AnyDesk\`
- `ad.trace` — detailed session trace
- `connection_trace.txt` — compact per-connection summary

**Service / machine-wide**: `%PROGRAMDATA%\AnyDesk\`
- `ad_svc.trace` — service-mode detailed trace (includes inbound listener)
- `service.conf` — service configuration including unattended-password hash and the local AnyDesk ID

Because AnyDesk has become the de-facto remote-access choice for ransomware operators (BlackBasta, LockBit 3.0, Akira, Play, 8Base) since ~2021, the presence and contents of these logs on an enterprise host are one of the highest-signal indicators in modern ransomware DFIR.

## Why `connection_trace.txt` matters so much
```
2026-04-15 03:14:22 UTC 123456789
2026-04-15 03:15:47 UTC 987654321
```

Two lines, two connections. The 9-10-digit AnyDesk IDs are globally unique. Many ransomware operators reuse their AnyDesk IDs across intrusions because they cost effort to rotate. Threat-intel feeds track known-attacker AD IDs. A single matching line in connection_trace.txt = attribution to a specific ransomware operator.

## Concept references
- IPAddress (peer IPs from ad.trace)

## Triage
```powershell
# Per-user scope (all users)
Get-ChildItem "C:\Users\*\AppData\Roaming\AnyDesk\*" -File -ErrorAction SilentlyContinue | Select FullName, LastWriteTime

# Service scope
Get-ChildItem "$env:ProgramData\AnyDesk\*" -File -ErrorAction SilentlyContinue | Select FullName, LastWriteTime

# Extract AD IDs
Get-Content "C:\Users\*\AppData\Roaming\AnyDesk\connection_trace.txt" | Select-String -Pattern '\d{9,10}$'
```

Parse ad.trace / ad_svc.trace for file-transfer lines:
```powershell
Select-String -Path "C:\Users\*\AppData\Roaming\AnyDesk\ad.trace" -Pattern 'file_transfer|upload|download'
```

## Acquisition
Copy the entire AnyDesk directory from each scope. Files are NOT locked on a running service in most cases but stop the AnyDesk service first for a clean snapshot.

## Cross-reference
- **Amcache / Prefetch** — AnyDesk.exe execution evidence (confirms binary ran; gives path to the AnyDesk binary the attacker used)
- **Sysmon-3** — outbound connections to AnyDesk rendezvous servers (`*.net.anydesk.com`) and direct peer IPs
- **Security-4624 type 10 / type 3** — remote-session-equivalent events if the attacker transitioned from AnyDesk to RDP after gaining foothold
- **UsnJrnl** — AnyDesk.exe creation time on disk = attacker first-drop timestamp

## Attack-chain example
Attacker phishes initial-access credentials. Uses them to RDP in. Drops AnyDesk.exe (portable, no install) to `C:\Users\user\AppData\Local\Temp\`. Runs it — establishes AnyDesk session from their own AnyDesk client. Uses AnyDesk for persistent, stealthier access going forward. Runs ransomware encryption tool.

Forensic recovery months later (post-RDP-session logs rolled):
- `%APPDATA%\AnyDesk\connection_trace.txt` contains the attacker's AD ID
- `ad.trace` documents file-transfer of ransomware binaries in to the host
- `ad_svc.trace` documents inbound session duration

## Practice hint
On a lab VM: install AnyDesk, accept the default un-attended access prompt. Connect to another AnyDesk instance (your phone's AnyDesk, a second VM). Transfer a test file. Close. Inspect `connection_trace.txt` (your peer's AD ID is there), `ad.trace` (file-transfer line for your test file). Delete AnyDesk from Apps list — the AppData and ProgramData directories and logs REMAIN (unless you manually delete). That persistence-after-uninstall is the forensic property DFIR relies on.
