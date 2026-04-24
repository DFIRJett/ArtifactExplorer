---
name: ETW-Autologger
title-description: "ETW Autologger registry — persistent Event Tracing for Windows trace sessions (EDR / Defender / attacker-blinding)"
aliases:
- ETW Autologger
- Event Tracing Autologger
- WMI Autologger
- persistent ETW sessions
link: persistence
link-secondary: system
tags:
- edr-blinding
- tamper-signal
- itm:AF
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: '2000'
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SYSTEM
  path: "CurrentControlSet\\Control\\WMI\\Autologger\\<session-name>"
  addressing: hive+key-path
  note: "Each subkey under Autologger\\ is a persistent Event Tracing for Windows (ETW) trace session that starts automatically at boot. These power: Microsoft Defender (via Microsoft-Windows-Threat-Intelligence provider), third-party EDR agents (CrowdStrike, Carbon Black, SentinelOne, etc.) that use ETW for kernel-level telemetry, and core Windows tracing (EventLog-System, DefenderAuditLogger, DiagLog, etc.). An attacker with admin can DISABLE specific Autologger sessions (Start=0) or UNREGISTER providers from a session (delete provider subkeys) to silently blind EDR / Defender / Windows native-auditing telemetry WITHOUT disabling the security product's user-mode service. One of the most subtle and high-impact tamper techniques on modern Windows."
fields:
- name: session-start
  kind: flags
  location: "Autologger\\<session>\\Start value"
  type: REG_DWORD
  note: "1 = session starts on boot (default for active sessions). 0 = session disabled at boot. Attacker setting this to 0 on an EDR-critical session silently stops that session from recording telemetry — the security product may still RUN but its ETW data source is empty. Classic blinding technique (T1562.002)."
- name: session-guid
  kind: identifier
  location: "Autologger\\<session>\\GUID value"
  type: REG_SZ
  encoding: guid-string
  note: "Session's GUID. Joins with runtime ETW session enumeration (logman query -ets) for live-state comparison."
- name: provider-subkeys
  kind: identifier
  location: "Autologger\\<session>\\{provider-guid}\\ subkey — one per enabled provider"
  references-data:
  - concept: ServiceName
    role: persistedService
  note: "Each subkey under a session represents an ETW provider enabled for that session. Key name is the provider's GUID. Deleting a provider subkey UNREGISTERS the provider from the session — the provider's events no longer reach this session's consumer. For EDR-blinding, attackers don't disable the whole session (which is noisy) — they remove specific provider subkeys from the session."
- name: provider-enabled
  kind: flags
  location: "Autologger\\<session>\\{provider-guid}\\Enabled value"
  type: REG_DWORD
  note: "1 = provider active in session; 0 = provider present but disabled. More subtle than full deletion; the provider subkey exists (so a casual registry inspection sees it) but is dormant. Attacker blinding vector for providers they want to silently suppress."
- name: provider-matchanykeyword
  kind: flags
  location: "Autologger\\<session>\\{provider-guid}\\MatchAnyKeyword / MatchAllKeyword values"
  type: REG_QWORD
  note: "Bitmask of provider keyword groups this session subscribes to. Setting MatchAnyKeyword=0 effectively disables keyword filtering causing the provider to match NO events — even more subtle blinding, as the provider appears 'enabled' but nothing passes the keyword filter."
- name: known-critical-sessions
  kind: identifier
  location: "well-known Autologger names"
  note: "EventLog-System / EventLog-Application / EventLog-Security — Windows Event Log EVTX ingestion sessions (disabling breaks EVTX!). DefenderAuditLogger / DefenderApiLogger / Microsoft-Antimalware-* — Defender telemetry. DiagLog / WdiContextLog — diagnostic tracing. Third-party: EDR sessions installed by the EDR vendor under names like 'CrowdStrike-Sensor-*', 'CylanceOptics-*', 'CbEventLog-*'. Inventory against expected vendor set."
- name: key-last-write
  kind: timestamp
  location: per-Autologger-session key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on a session's subkey = configuration change time. Disabling a session (Start=0 write) or unregistering a provider (subkey delete) moves this timestamp. Correlate with incident timeline to pinpoint tamper moment."
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'ETW Autologger is the on-disk configuration substrate for
    persistent Event Tracing sessions — including the sessions that
    feed Defender, third-party EDR, and Windows Event Log itself.
    Attacker tampering here silently blinds telemetry without
    stopping the security-product service. Because the runtime
    session state is driven by this registry config at next boot,
    tamper persists across reboots automatically. Extraordinarily
    high-impact: a single Autologger\\<EDR-session>\\<provider-guid>
    delete silently removes a specific telemetry stream from the
    EDR''s visible events without touching the EDR''s user-mode
    agent state. Defensive sweeps that audit EDR process presence
    pass; audits that compare runtime ETW session state against
    registry baseline catch the tamper. (MITRE T1562.002)'
  qualifier-map:
    setting.registry-path: "CurrentControlSet\\Control\\WMI\\Autologger\\<session>"
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none — no signing of Autologger session / provider registrations
  known-cleaners:
  - tool: "restore providers via ETW API / SEtraceFlags"
    typically-removes: restores telemetry (reverse of the tamper)
  survival-signals:
  - Autologger\<EDR-session>\<provider-guid> subkeys missing compared to known-good baseline = provider-level blinding
  - Autologger\<critical-session>\Start=0 = session-level disable (very noisy on audit, less common)
  - Key LastWrite on EDR Autologger session within incident window WITHOUT corresponding EDR-vendor update / reconfiguration event = unauthorized tamper
  - Runtime session enumeration (logman query -ets) shows fewer providers than registry baseline for a session = provider actively unregistered post-boot
provenance:
  - ms-event-tracing-for-windows-etw-autol
  - mitre-t1562-002
  - palantir-2021-etw-attack-surface-disabling-e
---

# ETW Autologger Registry

## Forensic value
`HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\<session-name>\` holds one subkey per persistent Event Tracing for Windows (ETW) session that starts automatically at boot. These sessions power:

- **Windows Event Log** (EventLog-System, EventLog-Application, EventLog-Security — the sessions that feed EVTX!)
- **Microsoft Defender** telemetry (Microsoft-Windows-Threat-Intelligence provider)
- **Third-party EDR agents** (CrowdStrike, SentinelOne, Carbon Black, Cortex XDR — each installs sessions)
- **Diagnostic tracing** (DiagLog, WdiContextLog, Ntfs, etc.)

An attacker with admin can surgically tamper with this tree to blind specific telemetry WITHOUT stopping the security product's process.

## Two levels of attack (MITRE T1562.002)

**Session-level**: `Autologger\<session>\Start = 0` — session doesn't start at boot. Session reappears disabled in `logman query -ets`. Noisier.

**Provider-level**: delete or disable `Autologger\<session>\{provider-guid}` subkeys — specific providers stop feeding the session. Much subtler — session appears active but missing specific event streams. Common against:
- `Microsoft-Windows-Threat-Intelligence` (Defender EDR block detections)
- `Microsoft-Antimalware-Scan-Interface` (AMSI)
- `Microsoft-Windows-DNS-Client` (DNS telemetry)
- EDR-vendor-specific providers

## Why it works
ETW is registry-config-driven for Autologger sessions. At next boot, the Session Manager reads Autologger\\ subkeys and starts sessions as specified. Provider subkeys tell the session which providers to enable. Remove a provider subkey → provider isn't re-enabled → its events simply don't reach the session's consumer (EDR agent / EventLog service / etc.). The USER-MODE agent keeps running — receives empty data.

## Concept reference
- None direct — config-substrate artifact.

## Triage
```cmd
:: Full Autologger enumeration
reg query "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger" /s > autologger-state.txt

:: Session-level disable check
reg query "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System" /v Start
reg query "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v Start

:: Runtime comparison
logman query -ets
```

Diff: registry-Autologger baseline vs runtime (`logman query -ets`). Provider-count mismatches on security-critical sessions = active tamper.

## Critical sessions to baseline
- `EventLog-System` / `EventLog-Application` / `EventLog-Security` — Windows Event Log ingestion
- `DefenderAuditLogger` / `DefenderApiLogger` — Microsoft Defender
- `Microsoft-Antimalware-*` — AMSI / Defender telemetry
- `CircularKernelContextLogger` — kernel tracing
- `DiagLog` — diagnostic tracing
- EDR vendor sessions — known names per installed EDR

## Cross-reference
- **Security-4688** — process that modified the registry (possibly reg.exe / PowerShell with Set-ItemProperty)
- **Security-4657** — registry-value-modified (if SACL set on the target keys; not by default)
- **Sysmon-12/13/14** — registry object modification events (if Sysmon is running and not itself being blinded)
- **Registry transaction logs (.LOG1/.LOG2)** — may preserve pre-tamper state for replay

## Practice hint
Do NOT experiment on real / production systems — disabling ETW sessions can destabilize EDR and Event Log. On an isolated lab VM: inspect `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger\` — note the provider subkeys. Each GUID subkey corresponds to a Microsoft Defender provider. Don't delete any — just observe the structure. Compare to `logman query -ets` output for the running session. The baseline match is what tampering breaks.
