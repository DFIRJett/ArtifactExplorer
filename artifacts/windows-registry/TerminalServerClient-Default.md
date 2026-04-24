---
name: TerminalServerClient-Default
aliases:
- RDP default username
- Terminal Server Client Default
- mstsc defaults
link: network
tags:
- per-user
- tamper-easy
- lateral-movement
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: XP
    max: '11'
location:
  hive: NTUSER.DAT
  path: Software\Microsoft\Terminal Server Client\Default
  companion-paths:
    - Software\Microsoft\Terminal Server Client\Servers\<server-name>
  addressing: hive+key-path
fields:
- name: MRU-server-slot
  kind: hostname
  location: values named 'MRU0', 'MRU1', ..., 'MRU9' at the Default key
  type: REG_SZ
  note: hostname or IP of a server the user connected to via mstsc.exe
  references-data:
  - concept: MachineNetBIOS
    role: trackerMachineId
- name: UsernameHint
  kind: label
  location: Software\Microsoft\Terminal Server Client\Servers\<server>\UsernameHint
  type: REG_SZ
  references-data:
  - concept: RegistryKeyPath
    role: subjectKey
  note: last username entered for THAT specific server — attacker credentials left behind
- name: CertHash
  kind: hash
  location: Software\Microsoft\Terminal Server Client\Servers\<server>\CertHash
  type: REG_BINARY
  note: trusted-certificate fingerprint for the server — user accepted this certificate for subsequent connections
- name: key-last-write-default
  kind: timestamp
  location: Default subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: on MRU update (new connection or reconnect)
- name: key-last-write-per-server
  kind: timestamp
  location: per-server subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: on each connection to THAT specific server
observations:
- proposition: CONNECTED_VIA_RDP
  ceiling: C3
  note: User initiated outbound RDP sessions to these servers. Per-server subkey retains UsernameHint — the literal username they typed. Critical for lateral-movement attribution.
  qualifier-map:
    actor.user: NTUSER.DAT owner
    object.destination.host: field:MRU-server-slot
    actor.credential.username: field:UsernameHint
    time.last_connect: field:key-last-write-per-server
anti-forensic:
  write-privilege: user
  known-cleaners:
  - tool: mstsc UI 'Clear history' in connection dialog
    typically-removes: MRU list only (per-server subkeys often survive)
  - tool: CCleaner
    typically-removes: full
  - tool: manual reg delete of Servers subkey
    typically-removes: cert + username hints
detection-priorities:
  - UsernameHint = 'administrator' / 'svc_*' / 'backup' — evidence of privileged-credential typing from this workstation
  - MRU entries pointing at servers not in the user's normal scope (domain controllers, jump boxes, DMZ hosts)
  - MRU entries with IPs rather than hostnames — often indicates targeted RDP outside DNS name resolution
provenance: []
provenance: [libyal-libregf, regripper-plugins]
---

# TerminalServerClient-Default

## Forensic value
Companion to TS-Client-MRU. Where TS-Client-MRU records the *list* of recent servers, TerminalServerClient-Default holds the **per-server metadata** the user's mstsc client cached:

- **UsernameHint** — the last username typed for that server. Cached to pre-fill the logon box on the next connection. Forensic value: reveals credentials the user used, per-target. If `UsernameHint = "administrator"` and the server is a domain controller, you've got high-value evidence of privileged RDP.
- **CertHash** — trusted-certificate fingerprint the user accepted. Mismatches between observed cert hash and CertHash indicate MitM or server cert change.

## Per-server structure
```
HKCU\Software\Microsoft\Terminal Server Client\
  Default\
    MRU0 = "fileserver.corp.local"
    MRU1 = "10.50.2.14"
    MRU2 = "jump.internal"
  Servers\
    fileserver.corp.local\
      UsernameHint = "alice"
      CertHash = <20-byte SHA-1 thumbprint>
    10.50.2.14\
      UsernameHint = "administrator"     ← pivot-worthy
      CertHash = <...>
    jump.internal\
      UsernameHint = "DOMAIN\svc_deploy" ← service-account usage from user workstation
```

## Per-server last-write is high-signal
The key last-write on each `Servers\<server>` subkey fires ONLY when that specific server is connected to. Unlike the Default subkey (which updates on any MRU reorder), per-server subkeys give reliable **per-connection timestamps**.

## Lateral-movement attribution
Given a known pivot host and timeline:
1. Acquire TerminalServerClient-Default from the suspect user's NTUSER.DAT
2. Enumerate Servers\* subkeys
3. For each server: subkey last-write = last outbound RDP to that target
4. UsernameHint = credential the attacker/user typed
5. Cross-reference server-side Security-4624 logon-type-10 (remote interactive) with matching timestamps

This chain goes from "user's workstation" → "target server at time T" → "with username X" → validated by server-side logon event.

## Cross-references
- **TS-Client-MRU** (container-level) — the aggregate MRU list without per-server metadata
- **TS-RCM-1149** on the TARGET server — inbound RDP connection received
- **TS-LSM-21** on the TARGET — session logon
- **TS-RDPClient-1024** on THIS host — outbound client-initiated RDP

## Practice hint
```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Terminal Server Client\Servers' -EA 0 | ForEach-Object {
  $p = Get-ItemProperty $_.PSPath
  [pscustomobject]@{
    Server = $_.PSChildName
    Username = $p.UsernameHint
    LastConnect = $_.LastWriteTime
  }
}
```
