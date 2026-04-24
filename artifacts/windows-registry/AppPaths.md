---
name: AppPaths
aliases: [App Paths registry key, Run-dialog launch map]
link: application
tags: [system-wide, tamper-easy]
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows: {min: XP, max: '11'}
location:
  hive: SOFTWARE
  path: "Microsoft\\Windows\\CurrentVersion\\App Paths\\<exe-name.exe>"
  addressing: hive+key-path
fields:
- name: exe-subkey
  kind: identifier
  location: "<exe-name.exe> subkey name"
- name: default-path
  kind: path
  location: "default value of exe subkey"
  type: REG_SZ
  note: "full path of the executable; registered app launcher. Start → Run or Win+R resolves exe name via App Paths."
  references-data:
  - {concept: ExecutablePath, role: configuredPersistence}
- name: Path
  kind: path
  location: Path value
  type: REG_SZ or REG_EXPAND_SZ
  note: "PATH prepended during launch — lets a registered app override process PATH"
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
observations:
- proposition: LAUNCHED_BY_NAME_MAP
  ceiling: C2
  note: "App Paths entries are indirect persistence — typing an exe name in Run or shell resolves via this map. Attacker can plant a subkey pointing a common name (e.g. 'notepad.exe') at a malicious binary."
  qualifier-map:
    object.exe.name: field:exe-subkey
    object.exe.path: field:default-path
    time.last_mutation: field:key-last-write
anti-forensic:
  write-privilege: admin
provenance: []
provenance: [libyal-libregf, regripper-plugins]
---

# AppPaths

## Forensic value
Registered-app launch map. When a user types a bare exe name in Run or in a shell prompt, Windows looks here before PATH. Attackers plant entries for common names (notepad.exe, calc.exe) pointing at attacker-controlled paths — invisible from command-line tools that don't inspect this key.

## Cross-references
- **ImageFileExecutionOptions** — stronger execution-hijack primitive (Debugger value)
- **RunMRU** — typed Run commands that resolve via App Paths
- **Amcache-InventoryApplication** — program-install catalog that partly overlaps
