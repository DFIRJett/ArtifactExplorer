---
name: AppCertDlls
aliases: [AppCertDlls persistence]
link: persistence
tags: [system-wide, tamper-hard, persistence-primary]
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows: {min: XP, max: '11'}
location:
  hive: SYSTEM
  path: ControlSet00x\Control\Session Manager\AppCertDlls
  addressing: hive+key-path
fields:
- name: dll-value
  kind: path
  location: "REG_SZ values under AppCertDlls key; value name is arbitrary, data is a DLL path"
  type: REG_SZ
  note: "Every DLL listed here is loaded into ANY process that calls CreateProcess / CreateProcessAsUser / WinExec. Broadest-reach DLL-injection persistence in Windows."
  references-data:
  - {concept: ExecutablePath, role: configuredPersistence}
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: PERSISTED
  ceiling: C3
  note: "AppCertDlls forces the listed DLL into every new process. Dormant on default installs — any entry is suspicious."
  qualifier-map:
    object.persistence.dll: field:dll-value
    time.last_mutation: field:key-last-write
anti-forensic:
  write-privilege: admin
  known-cleaners:
  - {tool: manual reg delete, typically-removes: surgical}
provenance:
  - mitre-t1546
  - mitre-t1546-009
  - online-2021-registry-hive-file-format-prim
---

# AppCertDlls

## Forensic value
Dormant-by-default persistence key. Any DLL listed here gets injected into every process that calls `CreateProcess*` — universal DLL hijack. Default installs contain NO values; the mere presence of any entry is high-signal.

## Cross-references
- **AppInit-DLLs** — similar but hooks USER32 load (slightly narrower reach)
- **Security-4657** (registry value modified) — audit event when AppCertDlls is written
- **Sysmon-13** — real-time registry-set event for detection
