---
name: Extended-Attributes
title-description: "NTFS Extended Attributes ($EA / $EA_INFORMATION) — named key/value pairs attached to a file"
aliases: [$EA, $EA_INFORMATION, NTFS EA, extended attributes]
link: file
tags: [ntfs-metadata, wsl-storage, rootkit-hiding]
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: Extended-Attributes
substrate-hub: NTFS Metadata
platform:
  windows: {min: NT4.0, max: '11'}
  windows-server: {min: '2000', max: '2022'}
location:
  path: "<file MFT record>\\$EA + $EA_INFORMATION attributes"
  addressing: mft-attribute
  note: "NTFS Extended Attributes are separate from Alternate Data Streams. EAs are small key/value pairs attached to a file's MFT record (max ~64KB each, ~64KB total per file). Windows uses EAs for: WSL file metadata (Linux mode/uid/gid when a file lives on NTFS via \\\\wsl$), ReparseTag extensions, and some legacy OS/2 compatibility data. ATTACKER USE: hide payload bytes in an EA (less commonly enumerated than ADS), or leverage the ProxyNotShell-class Exchange CVEs that abuse EA handling. Rootkits occasionally hide config data in EAs to evade file-system scanning."
fields:
- name: ea-name
  kind: label
  location: "$EA attribute — EaName field"
  encoding: ascii-8bit
  note: "Name of the EA entry. Well-known Windows EAs: $KERNEL.PURGE.ESBCACHE, $TXF_DATA (Transactional NTFS), WSL-related ($LXATTRB). Attacker EAs use custom names — any unfamiliar EA name on a user-writable file = investigate."
- name: ea-value
  kind: content
  location: "$EA attribute — EaValue field"
  encoding: raw-bytes
  note: "The key/value data. Limited to ~64KB per entry but attackers can split payload across multiple EAs on one file. Reading requires NTFS-aware parser (standard file APIs expose EAs only via specialized APIs — most analyst tools miss them unless explicitly requested)."
- name: ea-size
  kind: counter
  location: "$EA attribute — Value length"
  encoding: uint16
  note: "Size of the value. Total EA data per file tracked in $EA_INFORMATION attribute (UnpackedEaSize + PackedEaSize fields). Large or anomalous EA size on a benign-looking file = suspicion."
- name: ea-information
  kind: identifier
  location: "separate $EA_INFORMATION attribute"
  encoding: fixed-size struct (PackedEaSize + NeedEaCount + UnpackedEaSize)
  note: "Aggregate header attribute summarizing EA state on the file. Required for certain OS/2 compatibility behaviors; exists only when file has EAs. Presence = file has EAs."
observations:
- proposition: HAS_METADATA
  ceiling: C3
  note: 'EAs are a widely-overlooked NTFS metadata surface. Most DFIR tools focus on ADS and miss EAs entirely. Key scenarios: (1) WSL file attribution — $LXATTRB EA holds Linux mode/uid/gid for files created/modified via WSL, letting you confirm a file was touched from the Linux subsystem; (2) Payload hiding — attacker stashes shellcode / config in an EA; (3) CVE-leveraging — some NTFS-EA-handling CVEs (ProxyNotShell class) abuse EA parsing. Always enumerate EAs on files of forensic interest.'
  qualifier-map:
    object.name: field:ea-name
    time.start: "inherited from MFT $SI of the parent file"
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: none beyond NTFS consistency
  survival-signals:
  - Files with unfamiliar custom EA names in user-writable directories = candidate payload hiding
  - Large cumulative EA size (PackedEaSize > few KB) on executables / scripts = candidate embedded payload
  - $LXATTRB EAs on files in non-WSL paths = unusual WSL footprint on the Windows side
provenance:
  - ms-ntfs-extended-attributes-file-syste
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - velociraptor-2024-windows-forensics-ntfs-extende
---

# NTFS Extended Attributes ($EA)

## Forensic value
NTFS-native metadata surface distinct from Alternate Data Streams. EAs are name/value pairs attached to a file's MFT record, capped at ~64KB per entry and ~64KB total per file. Commonly-ignored DFIR surface — most tools focus on ADS and miss EAs entirely.

## Practical use cases
- **WSL attribution**: `$LXATTRB` EA preserves Linux permissions on WSL-created files; its presence on a file confirms WSL touched it
- **Rootkit hiding**: attacker stashes small config / shellcode payloads in an EA to evade file-content scanning
- **CVE leverage**: ProxyNotShell / other Exchange / NTFS-parsing bugs abuse EA handling

## Parsing
Requires NTFS-aware reader:
- `libfsntfs` — open-source, EA-aware
- FTK Imager — browse MFT attributes including $EA
- Velociraptor `Windows.Forensics.NTFS` artifact includes EA enumeration

Standard Windows file APIs: `NtQueryEaFile` / `NtSetEaFile` expose EAs; most analyst tools don't call these unless explicitly configured.

## Cross-reference
- **AlternateDataStream-Generic** — sibling NTFS metadata surface; NOT the same as EAs
- **MFT** — parent of the $EA attribute
- **WSL-Lxss** — when $LXATTRB EAs appear, cross-reference with WSL install state

## Practice hint
On a WSL VM: `touch ~/test.txt` inside WSL to create a file on the backing ext4.vhdx OR on /mnt/c. For /mnt/c files, check the corresponding Windows-side file's EAs — `$LXATTRB` is present with Linux metadata. This is the attribution path.
