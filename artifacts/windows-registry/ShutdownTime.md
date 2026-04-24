---
name: ShutdownTime
title-description: "Last-clean-shutdown FILETIME under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Windows → ShutdownTime"
aliases:
- ShutdownTime value
- last shutdown registry
link: system
tags:
- timeline-anchor
- system-lifecycle
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: NT5.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SYSTEM
  path: "CurrentControlSet\\Control\\Windows"
  value: ShutdownTime
  addressing: hive+key-path+value
  note: "8-byte FILETIME stored as REG_BINARY under the Windows key. Updated by the Session Manager (smss.exe) at the last CLEAN shutdown of the system. Unmodified on abrupt power-off or system crash — in that case the value reflects the PRIOR clean shutdown, which is itself a signal (delta between ShutdownTime and next boot can reveal crashed-without-shutdown events)."
fields:
- name: last-shutdown
  kind: timestamp
  location: "Control\\Windows\\ShutdownTime value"
  type: REG_BINARY
  encoding: 8-byte filetime-le
  clock: system
  resolution: 100ns
  references-data:
  - concept: FILETIME100ns
    role: absoluteTimestamp
  note: "Timestamp of last clean shutdown. Directly readable as a Windows FILETIME. Canonical source for answering 'when was the machine last cleanly shut down?' — used in incident timelines, 'was the host on at time X?' queries, and cross-reference with System-1074 / System-6006 shutdown events."
- name: key-last-write
  kind: timestamp
  location: Control\\Windows key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  references-data:
  - concept: FILETIME100ns
    role: absoluteTimestamp
  note: "LastWrite on the Windows key updates whenever any child value changes. In normal operation the LastWrite mirrors the ShutdownTime value. Delta between the two is anomalous — suggests a write other than the canonical shutdown updater has touched this key."
observations:
- proposition: SYSTEM_LIFECYCLE
  ceiling: C3
  note: 'A single-value artifact but forensically pivotal for any
    timeline-reconstruction question where "was the machine running
    at this moment?" matters. ShutdownTime provides a definitive
    previous-clean-shutdown anchor. Combined with System-12
    (OS-boot-time), analysts bracket the uptime window between the
    previous shutdown and the current boot — within which all
    real-time artifacts (memory, volatile registry, network sockets)
    must have been captured. Also useful as a crash-detection
    signal: if the current boot followed a ShutdownTime that is
    significantly older than expected, the machine rebooted
    abnormally (crash, power cycle, hard reset).'
  qualifier-map:
    setting.registry-path: "CurrentControlSet\\Control\\Windows\\ShutdownTime"
    time.end: field:last-shutdown
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  survival-signals:
  - ShutdownTime significantly earlier than OS-boot-time of the current session = abnormal last shutdown (crash / power cycle / hard reset)
  - ShutdownTime manually overwritten to a value post-dating actual shutdown = tamper (rare; leaves key LastWrite evidence)
provenance:
  - ms-session-manager-smss-exe-shutdown-w
---

# ShutdownTime value

## Forensic value
`HKLM\SYSTEM\CurrentControlSet\Control\Windows\ShutdownTime` is an 8-byte FILETIME binary value updated by `smss.exe` at the last clean shutdown. It is the authoritative single-value answer to:

> When was this host last cleanly shut down?

## Timeline use
For any investigation asking "was the host running between time X and Y?" — ShutdownTime bounds the prior-running-window on one end. Combine with OS-boot events (System channel event ID 12 / 6005) for the other end of the current uptime window.

If ShutdownTime + current-boot-time >> uptime, the prior session ended abnormally (crash / power off / hard reset). This is itself a forensic signal — attackers sometimes pull power to avoid graceful shutdown (to preserve pagefile / hiberfil content in pre-crash state).

## Concept reference
- None — single-value system-state artifact.

## Triage
```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Windows" /v ShutdownTime
```

Output is 8 hex bytes. Decode as little-endian FILETIME (100-ns ticks since 1601-01-01). PowerShell:
```powershell
$raw = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Windows").ShutdownTime
$ft = [BitConverter]::ToInt64($raw, 0)
[DateTime]::FromFileTime($ft)
```

## Cross-reference
- **System channel EVTX**
  - Event 1074 — clean shutdown by user / process
  - Event 6006 — Event Log service stopped (clean shutdown)
  - Event 6008 — previous shutdown was unexpected
  - Event 41 — Kernel-Power, system rebooted without cleanly shutting down
  - Event 12 — OS start time (BOOT anchor)
- **Pagefile/Hiberfil file mtime** — corroborates by independent clock

## Practice hint
On any Windows VM, inspect the ShutdownTime value, shut down cleanly, boot up, inspect again — value has advanced to the shutdown moment. Now force-power-off a running VM and boot up, inspect — value is UNCHANGED from the last clean shutdown (the abrupt power-off did not update it). That behavior is exactly why it's a reliable last-clean-shutdown anchor.
