---
name: ComputerName
aliases:
- HostName
- NetBIOS name (registry)
link: system-state-identity
tags:
- system-wide
- tamper-easy
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: XP
    max: '11'
location:
  hive: SYSTEM
  path: ControlSet00x\Control\ComputerName\ComputerName
  addressing: hive+key-path
fields:
- name: ComputerName
  kind: identifier
  location: ComputerName value
  type: REG_SZ
  encoding: UTF-16LE
  note: current NetBIOS computer name; also mirrored under ActiveComputerName
  references-data:
  - concept: MachineNetBIOS
    role: trackerMachineId
- name: ActiveComputerName
  kind: identifier
  location: ComputerName\ActiveComputerName\ComputerName
  type: REG_SZ
  note: runtime value (may differ from persistent ComputerName after rename-pending)
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: touched only on hostname change
observations:
- proposition: IDENTITY
  ceiling: C4
  note: Authoritative host-identity source; survives profile wipe, domain change.
  qualifier-map:
    object.machine.name: field:ComputerName
    time.modified: field:key-last-write
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - tool: manual reg.exe write
    typically-removes: replacement-only (no clean way to erase)
provenance: []
exit-node:
  is-terminus: false
  terminates:
    - SYSTEM_IDENTITY
  sources:
    - libyal-libregf
  reasoning: >-
    ComputerName / ActiveComputerName + TcpipParameters\Hostname hold the
    machine's NetBIOS name and DNS hostname — the authoritative identity
    for "what is this machine called." No upstream relay: the values are
    set at OS install and modified only by SetComputerName. Pairs with
    the MachineNetBIOS concept as its on-host terminus. Cross-host
    forensic correlation (lateral-movement reconstruction, log-source
    attribution) pivots through these values.
  implications: >-
    Mismatch between ComputerName and ActiveComputerName = rename in-flight
    (reboot pending). Mismatch between registry hostname and the hostname
    embedded in Kerberos tickets / certificates / event-log ComputerName
    field = evidence of impersonation or artifact from a different host.
  preconditions: >-
    Read access to HKLM\SYSTEM\CurrentControlSet\Control\ComputerName.
    No cryptographic chain.
  identifier-terminals-referenced:
    - MachineNetBIOS
---

# ComputerName

## Forensic value
Authoritative hostname for the machine. Distinct from AD `sAMAccountName$` or DNS hostname — this is the NetBIOS name that every LNK TrackerDataBlock, every Security-4624 "WorkstationName" field, and every SMB session advertises.

The key last-write timestamp is a high-signal anchor: it moves only on rename. A recent last-write on ComputerName with no corresponding domain-join sequence in System.evtx is suspicious.

## Cross-references
- **MachineNetBIOS concept** — populates LNK / jumplist TrackerDataBlock.
- **Security-4624** — logon records include the originating WorkstationName (often this value).
- **Hostname divergence** — compare against DNS name, AD computer object, and DHCP lease host. Mismatches are a forensic finding.

## Practice hint
`reg query HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName /v ComputerName` on a running host; compare against `hostname` and `[System.Net.Dns]::GetHostName()` in PowerShell — divergence indicates a pending rename.
