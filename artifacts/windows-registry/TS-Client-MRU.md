---
name: TS-Client-MRU
aliases:
- mstsc MRU
- RDP client history
- Terminal Services Client recently-connected
link: network
tags:
- per-user
- recency-ordered
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
  also: Software\Microsoft\Terminal Server Client\Servers\<hostname>
  addressing: hive+key-path
fields:
- name: recent-target
  kind: identifier
  location: Default\MRU<N> values (MRU0, MRU1, MRU2...)
  type: REG_SZ
  encoding: utf-16le
  note: each MRU<N> value holds one recently-connected target (hostname or IP)
  references-data:
  - concept: DomainName
    role: httpRequestHost
  - concept: IPAddress
    role: destinationIp
- name: username-hint
  kind: identifier
  location: Servers\<hostname>\UsernameHint value
  type: REG_SZ
  encoding: utf-16le
  note: the username the user typed for this target — indicates WHAT credential they used
- name: cert-hash
  kind: hash
  location: Servers\<hostname>\CertHash value
  type: REG_BINARY
  note: accepted RDP certificate thumbprint — if user accepted a 'new' cert warning, this records what they trusted
- name: key-last-write
  kind: timestamp
  location: Default key or per-server subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: updated on MRU change
observations:
- proposition: CONNECTED
  ceiling: C2
  note: 'Per-user record of RDP targets typed into mstsc.exe. Establishes

    WHICH hosts the user attempted to reach via RDP — useful for lateral-

    movement investigation. Username-hint reveals the account used.

    '
  qualifier-map:
    peer: field:recent-target
    actor.user: NTUSER.DAT owner
    method: RDP
    time.start: field:key-last-write
anti-forensic:
  write-privilege: user
  known-cleaners:
  - tool: manually clear via mstsc UI (no built-in option; requires reg-delete)
    typically-removes: false
    note: no UI clears this — must use reg-delete manually
  - tool: CCleaner
    typically-removes: partial
provenance: []
provenance: [libyal-libregf, regripper-plugins]
---

# Terminal Server Client MRU

## Forensic value
Per-user history of RDP targets. Every hostname or IP the user typed into `mstsc.exe` gets an MRU entry. Per-server subkeys record username hints (what account they used) and cert hashes (what RDP server certificate they accepted).

For lateral-movement analysis: TS-Client-MRU on workstation A shows which remote hosts the user logged into. Combined with Security-4648 on workstation A (explicit credential use) and Security-4624 on the remote host (logon with source IP = workstation A), closes the full lateral chain.

## Concept references
- DomainName (recent-target when hostname)
- IPAddress (recent-target when IP)

## Known quirks
- **MRU0 through MRU<9>** (typically ten most-recent). Wraps around as new targets are added.
- **No per-connection timestamp.** The Default key's LastWrite is the ONLY temporal anchor — approximates most-recent MRU update time.
- **Username-hint + CertHash per Server** — distinct subkey per host offers more detail than the flat MRU list.
- **No clearing UI.** mstsc.exe has no "clear history" option; the registry keys are sticky. For forensic analysts, this is good news.

## Practice hint
From a test VM, `mstsc /v:some-remote-host` (even to a non-existent host). Cancel the prompt. Check `Software\Microsoft\Terminal Server Client\Default` — the host is recorded even though the connection failed. Type-mistakes produce MRU entries.
