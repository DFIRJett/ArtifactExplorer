---
name: GroupPolicy-Registry-Pol
title-description: "Registry.pol files — on-disk Group Policy registry-settings cache applied on every logon / gpupdate"
aliases:
- Registry.pol
- GPT Registry.pol
- Group Policy cached policy
- GPO registry settings
link: persistence
link-secondary: system
tags:
- enterprise-persistence
- policy-enforcement
- itm:PR
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: GroupPolicy-Registry-Pol
platform:
  windows:
    min: '2000'
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  path-machine-cache: "%WINDIR%\\System32\\GroupPolicy\\Machine\\Registry.pol"
  path-user-cache: "%WINDIR%\\System32\\GroupPolicy\\User\\Registry.pol"
  path-sysvol-gpo: "\\\\<domain>\\SYSVOL\\<domain>\\Policies\\{<GPO-GUID>}\\{Machine,User}\\Registry.pol"
  companion-gpt-ini: "\\\\<domain>\\SYSVOL\\<domain>\\Policies\\{<GPO-GUID>}\\gpt.ini (+ local cache under Machine\\gpt.ini)"
  addressing: file-path
  note: "Group Policy's registry-settings-storage format. Binary PReg format (magic 'PReg', version 1) containing a stream of registry-setting records: (hive-key-path, value-name, value-type, value-data). On a domain-joined host, Registry.pol files are downloaded from SYSVOL to the local %WINDIR%\\System32\\GroupPolicy\\ cache on every gpupdate / logon / scheduled refresh. The Group Policy Client Service reads the local cache and applies each setting to the runtime registry. For DFIR, the Registry.pol cache is a RELIABLE record of the enforced-policy baseline — independent of the runtime registry state which may have been tampered with."
fields:
- name: policy-record
  kind: content
  location: "Registry.pol body — sequence of PReg records"
  encoding: "[\\[Key;Value;Type;Size;Data\\]*] format with UTF-16LE strings"
  note: "Each record specifies: (1) registry-key-path the policy writes to (e.g., 'SOFTWARE\\Microsoft\\Windows Defender'), (2) value-name (e.g., 'DisableAntiSpyware'), (3) value-type (REG_DWORD / REG_SZ / etc.), (4) value-data. GPE (Group Policy Editor) produces this file from ADMX template selections. Attacker-modified Registry.pol on a compromised DC's SYSVOL would push malicious registry settings to every client that refreshes policy — a high-impact enterprise persistence path."
- name: policy-target-path
  kind: path
  location: "inside each PReg record"
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Target HKLM or HKCU path that the policy writes. Enumeration of all target-paths = complete enforced-registry-setting baseline. Attacker-authored policies targeting Defender exclusion paths, LSA Run Level, Credential Delegation settings, or audit-policy-disable flags = persistence-enforcement plant."
- name: policy-target-value
  kind: label
  location: "inside each PReg record — value-name field"
  encoding: utf-16le
  note: "Target value-name. Joins with policy-target-path to fully-identify the setting. E.g., '(SOFTWARE\\Policies\\...\\Windows Defender\\Exclusions\\Paths, \\\\attacker-share\\)' = Defender-exclusion policy plant."
- name: policy-data
  kind: content
  location: "inside each PReg record — value-data field"
  encoding: per-value-type (DWORD as uint32 le; SZ as utf-16le; etc.)
  note: "Actual value data enforced. For DWORD policy flags, the value is the enforced integer (1 = on, 0 = off). Attacker-written DisableAntiSpyware=1 in Registry.pol enforces Defender-disable across every domain-joined host that receives the policy."
- name: file-mtime
  kind: timestamp
  location: Registry.pol file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime = last policy refresh write time on the local cache. Domain side: SYSVOL Registry.pol mtime = when the GPO was last edited by an admin. Compare local cache mtime vs SYSVOL mtime to determine policy-refresh freshness."
- name: gpt-ini-version
  kind: counter
  location: "gpt.ini — Version= line"
  encoding: integer (version)
  note: "GPT version counter. Every time a GPO is edited on the domain side, version increments; clients compare their local gpt.ini version against SYSVOL's and fetch a fresh Registry.pol when they differ. Version mismatches between observed local cache and SYSVOL reveal partial / failed policy-refresh state."
- name: gpt-ini-displayname
  kind: label
  location: "gpt.ini — [General] section keys"
  encoding: ini text
  note: "GPO display name and scope. Sibling metadata to Registry.pol — use together for full policy-object identity."
observations:
- proposition: CONFIGURED_BY_POLICY
  ceiling: C4
  note: 'Group Policy Registry.pol files are one of the most overlooked
    enterprise-persistence artifacts. An attacker who compromises a
    Domain Controller (or a delegated GPO admin account) can modify
    Registry.pol files in SYSVOL and push arbitrary registry
    settings to every domain-joined client. Defensive teams
    frequently audit the runtime registry of endpoints but do NOT
    audit SYSVOL Registry.pol content and do NOT diff local policy
    cache against expected baselines. For lateral-movement / mass-
    persistence / mass-evasion cases, comparing local Registry.pol
    caches against known-good GPO baselines reveals attacker-added
    or attacker-modified enforcement records.'
  qualifier-map:
    setting.registry-path: field:policy-target-path
    setting.value-name: field:policy-target-value
    time.start: field:file-mtime
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: PReg-format internal checksum (weak); SYSVOL replication (DFSR) provides cross-DC consistency
  known-cleaners:
  - tool: "delete local %WINDIR%\\System32\\GroupPolicy\\ contents"
    typically-removes: local cache (re-downloaded on next gpupdate from SYSVOL)
  - tool: "modify SYSVOL Registry.pol on DC"
    typically-removes: n/a (this is the ATTACK, not a cleanup) — but restoration requires a known-good backup
  survival-signals:
  - Local Registry.pol policy-target-path touching Defender exclusions / AV-disable flags / audit-policy-disable / Credential-Delegation / LSA Protection disable = candidate attacker-pushed policy
  - SYSVOL Registry.pol mtime matching a compromised-DC-admin timeframe = DC-side GPO tamper window
  - Local cache mtime significantly older than SYSVOL mtime = client's policy refresh is broken (possibly deliberately)
provenance:
  - ms-group-policy-registry-extension-and
  - mitre-t1484-001
---

# Group Policy Registry.pol

## Forensic value
`Registry.pol` is the on-disk representation of the **registry-settings** portion of a Group Policy Object. Every domain-joined Windows host caches Registry.pol files locally and re-applies them on every Group Policy refresh (default 90 min + 30 min random offset) and on every logon.

Two local paths:
- **Machine policy**: `%WINDIR%\System32\GroupPolicy\Machine\Registry.pol` — applies to HKLM settings
- **User policy**: `%WINDIR%\System32\GroupPolicy\User\Registry.pol` — applies to HKCU settings

Domain-side master copies live on DC SYSVOL:
- `\\<domain>\SYSVOL\<domain>\Policies\{<GPO-GUID>}\Machine\Registry.pol`
- `\\<domain>\SYSVOL\<domain>\Policies\{<GPO-GUID>}\User\Registry.pol`

## Why this is a high-impact artifact
An attacker with Domain Admin or SYSVOL-write access can modify GPO Registry.pol files to push arbitrary registry settings — mass-enforcing:
- Defender exclusions
- DisableAntiSpyware=1
- Scheduled Tasks (via separate ScheduledTasks.xml in SYSVOL)
- Shortcuts (via Shortcuts.xml)
- LSA Protection disable
- Credential delegation (CredSSP) to attacker hosts
- Audit-policy disable

Every domain-joined host fetches the modified GPO on next refresh and applies the settings. Mass-persistence. Mass-evasion. Mass-lateral-movement enablement.

## PReg format
Binary format (magic bytes `PReg`, version 1). Each record:
```
[Key_Path;Value_Name;Type;Data_Size;Data]
```
All strings UTF-16LE. Parsable with Microsoft's Group-Policy-ADMX toolkit or open-source parsers (python-gpp).

## Concept reference
- None direct — policy-enforcement artifact.

## Triage
```cmd
:: Local cache
dir /a /t:w %WINDIR%\System32\GroupPolicy\Machine\Registry.pol
dir /a /t:w %WINDIR%\System32\GroupPolicy\User\Registry.pol

:: SYSVOL (domain-joined analyst station with DC access)
dir /s \\<domain>\SYSVOL\<domain>\Policies\*.pol
```

Parse:
- `LGPO.exe /parse` (Microsoft Security Compliance Toolkit)
- `Parse-PolFile` (PowerShell module)
- Hex editor + magic-byte recognition for one-off analysis

## Cross-reference
- **gpt.ini** — sibling version-counter + display-name file
- **Security-5136** (directory service object modified) on DC = GPO attribute change event
- **Security-4739** (domain policy changed)
- **Microsoft-Windows-GroupPolicy/Operational** EVTX — policy-refresh events on client side
- **SYSVOL DFS-Replication logs** — replication of modified GPO files across DCs

## Attack-chain example
Ryuk / Conti / LockBit operators on an enterprise intrusion:
1. Escalate to Domain Admin
2. Modify existing "Default Domain Policy" Registry.pol to add Defender exclusions for their ransomware binary path
3. Wait for next GPO refresh (90 min) OR force via `gpupdate /force` through PsExec
4. Every endpoint now has the Defender exclusion — ransomware runs unimpeded
5. Drop ransomware via SYSVOL-distributed scheduled-task GPO
6. Mass encrypt

All enabled by attacker-modified Registry.pol. Defensive SOCs that audit only host registry miss the GPO layer.

## Practice hint
On a lab DC: edit a test GPO via gpedit.msc, add a registry policy (e.g., set an obscure HKLM value). Observe SYSVOL Registry.pol mtime updates. Run `gpupdate /force` on a client — observe client-side `%WINDIR%\System32\GroupPolicy\Machine\Registry.pol` mtime updates to match. Parse both files, confirm the policy record appears. This is the enforcement chain attackers hijack.
