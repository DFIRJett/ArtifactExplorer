---
name: OS-Version
aliases:
- CurrentVersion
- Windows NT CurrentVersion
- OS build info
link: system-state-identity
tags:
- system-wide
- tamper-easy
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: XP
    max: '11'
location:
  hive: SOFTWARE
  path: Microsoft\Windows NT\CurrentVersion
  addressing: hive+key-path
fields:
- name: ProductName
  kind: label
  location: ProductName value
  type: REG_SZ
  note: human-readable OS name (e.g. 'Windows 10 Pro'); still reads 'Windows 10' on Win11 due to MS preserving the string
- name: CurrentBuild
  kind: version
  location: CurrentBuild value
  type: REG_SZ
  note: build number — authoritative distinguisher for Win10 vs Win11 (22000+)
- name: DisplayVersion
  kind: version
  location: DisplayVersion value
  type: REG_SZ
  note: marketing version label (21H2, 22H2, 23H2, 24H2...)
- name: InstallDate
  kind: timestamp
  location: InstallDate value
  type: REG_DWORD
  encoding: unix-epoch-seconds
  clock: system
  resolution: 1s
  update-rule: set at OS install; reset by in-place upgrade
- name: InstallTime
  kind: timestamp
  location: InstallTime value
  type: REG_QWORD
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: higher-resolution install timestamp (Win10+)
- name: RegisteredOwner
  kind: label
  location: RegisteredOwner value
  type: REG_SZ
  note: user-provided at setup; often default or org placeholder
- name: RegisteredOrganization
  kind: label
  location: RegisteredOrganization value
  type: REG_SZ
- name: EditionID
  kind: label
  location: EditionID value
  type: REG_SZ
  note: edition token (Professional, Enterprise, Core, CoreN, ...)
observations:
- proposition: IDENTITY
  ceiling: C4
  note: Authoritative OS-version and install-timeline; baseline for every artifact-dating question.
  qualifier-map:
    object.os.name: field:ProductName
    object.os.version: field:CurrentBuild
    time.created: field:InstallDate
anti-forensic:
  write-privilege: admin
  known-cleaners:
  - tool: manual reg.exe write
    typically-removes: no full-cleanup tool targets it
provenance: []
exit-node:
  is-terminus: false
  terminates:
    - SYSTEM_IDENTITY
  sources:
    - ms-windows-install-registry-values-cur
  reasoning: >-
    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion holds the
    authoritative OS identity — ProductName, CurrentBuild, DisplayVersion
    (21H2 / 22H2 / 23H2 / 24H2), InstallDate, InstallTime. Downstream
    artifacts that infer OS version (UA strings, WER metadata, Setupapi
    logs) all derive from this key. Terminus for "what OS is this host
    running?" forensic questions.
  implications: >-
    Mismatch between CurrentBuild / DisplayVersion and Winver output at
    time of acquisition = registry tampering or registry-hive mismatch
    (hive copied from a different host). InstallDate differs from
    Setupapi.upgrade.log's first-feature-upgrade timestamp = clean-
    install vs in-place-upgrade distinction, driver persistence
    implications.
  preconditions: >-
    Read access to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion.
  identifier-terminals-referenced: []
---

# OS-Version

## Forensic value
The canonical OS-identity artifact. Every timeline question bottoms out here: what OS is this, what build, when was it installed, was it an upgrade?

- **Build number** is the real version identifier. `CurrentBuild >= 22000` means Win11 regardless of ProductName string.
- **InstallDate** resets on in-place upgrade (Win7→10, Win10 feature updates). To find the *original* install, walk NTFS $MFT creation time on `C:\Windows\System32` or `setupapi.dev.log` earliest entry.
- **DisplayVersion** is the human-friendly "23H2"/"24H2" label; use `CurrentBuild` for parsing decisions.

## Cross-references
- **Setupapi-dev-log** — first entry is usually the OEM install of Windows itself; crossref to InstallDate
- **Amcache** — program records are only useful if the OS version supports Amcache (Win8+)
- **Feature-update telemetry** via `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\Source OS (Updated on ...)` — keys preserving prior-OS snapshots across upgrade

## Practice hint
`Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select ProductName,CurrentBuild,DisplayVersion,InstallDate,RegisteredOwner` — one-liner for baseline OS-identity.
