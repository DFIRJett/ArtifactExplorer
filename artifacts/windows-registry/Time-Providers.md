---
name: Time-Providers
title-description: "W32Time service Time Provider DLLs (NTP client / server plugins loaded into svchost.exe)"
aliases:
- W32Time providers
- Time Provider hijack
- TimeProviders key
link: persistence
tags:
- persistence-primary
- service-privileged
- itm:PR
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
  path: "CurrentControlSet\\Services\\W32Time\\TimeProviders\\<provider-name>"
  addressing: hive+key-path
  note: "Each subkey represents a time provider (NtpClient, NtpServer, VMICTimeProvider on VMs, optional third-party). Each subkey's DllName value is a DLL loaded by the W32Time service (running in svchost.exe with LOCAL SERVICE account). An attacker-added provider executes attacker DLL code in svchost.exe at every W32Time start — automatic on boot since W32Time is set to Automatic start by default."
fields:
- name: dll-name
  kind: path
  location: "TimeProviders\\<name>\\DllName value"
  type: REG_SZ / REG_EXPAND_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "DLL loaded into W32Time's svchost.exe host. Stock Microsoft providers point to %SystemRoot%\\system32\\w32time.dll (NtpClient / NtpServer both use the same DLL with different provider classes). Third-party / hypervisor providers (VMware, Hyper-V VMICTimeProvider) point to vendor-signed DLLs. Any DllName outside these baselines = candidate persistence plant."
- name: provider-enabled
  kind: flags
  location: "TimeProviders\\<name>\\Enabled value"
  type: REG_DWORD
  note: "0 = disabled (registered but not active), 1 = enabled (loaded at service start). Attacker-registered disabled providers are less noisy but still visible; enabled=1 on a provider with non-stock DllName = active persistence."
- name: provider-input-provider
  kind: flags
  location: "TimeProviders\\<name>\\InputProvider value"
  type: REG_DWORD
  note: "1 = this provider supplies time samples to W32Time (client-style); 0 = this provider consumes / publishes time only (server-style). Attacker providers typically set InputProvider=0 to avoid interfering with actual time sync — the DLL is loaded for persistence, not time-service functionality."
- name: key-last-write
  kind: timestamp
  location: "TimeProviders\\<name> subkey metadata"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite reflects provider-registration time. Correlate with System-7036 (W32Time service status change — restart needed to load new provider) and Security-4697."
- name: event-log-hints
  kind: identifier
  location: "Microsoft-Windows-Time-Service/Operational channel"
  note: "Event ID 35 = time-service started. Event ID 257 / 258 = provider loaded. Event ID 134 / 37 = provider errors. New provider registration shows up as a provider-loaded event at next service start."
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'Time Provider registration (MITRE T1547.003) is a narrow but
    clean persistence primitive: single registry write + one service
    restart = attacker DLL loaded into svchost.exe under the W32Time
    service context. Less powerful than port-monitor persistence
    (SYSTEM vs. LOCAL SERVICE) but triggers at the same reliability
    — W32Time starts automatically on every Windows boot. Often
    missed by Autoruns sweeps that do not expand the Services →
    TimeProviders subtree.'
  qualifier-map:
    setting.registry-path: "Services\\W32Time\\TimeProviders\\<name>\\DllName"
    setting.dll: field:dll-name
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none — DllName is not signature-validated by W32Time
  survival-signals:
  - DllName outside %SystemRoot%\system32 for a TimeProvider subkey = candidate hijack
  - Provider subkey name not matching (NtpClient, NtpServer, VMICTimeProvider, VMwareToolsTimeProvider, a known third-party vendor) = fabricated registration
  - Enabled=1 + InputProvider=0 + non-stock DllName = persistence-only plant (DLL loaded but does not actually participate in time sync)
provenance:
  - ms-windows-time-service-time-providers
  - mitre-t1547-003
---

# Time Providers (W32Time)

## Forensic value
The Windows Time service (`W32Time`, hosted in `svchost.exe`) consults `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\<name>` at service startup. Each subkey's `DllName` value points to a DLL that loads into the W32Time svchost instance. Because W32Time is Automatic-start, every boot re-triggers the load.

Attacker workflow (MITRE T1547.003):
1. Write a new TimeProviders subkey with an attacker-controlled DllName
2. Set Enabled=1, InputProvider=0 (persist but don't interfere with time)
3. Restart W32Time (or wait for next boot) — DLL loads into svchost.exe

The resulting code runs as LOCAL SERVICE. Less privileged than SYSTEM (port monitor hijack) but sufficient for most persistence purposes and triggers as reliably.

## Stock baseline
Typical Windows 10/11 TimeProviders subkeys:
- `NtpClient` → `%SystemRoot%\system32\w32time.dll`
- `NtpServer` → `%SystemRoot%\system32\w32time.dll`
- `VMICTimeProvider` (on Hyper-V VMs) → `%SystemRoot%\System32\vmictimeprovider.dll`
- `VMwareToolsTimeProvider` (on VMware VMs with Tools installed) → vendor DLL

Any subkey outside these with a non-standard DllName = investigation candidate.

## Concept reference
- ExecutablePath (per registered provider DllName)

## Triage
```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders" /s
```

Validate each DllName path + signature:
- Microsoft providers → w32time.dll signed by Microsoft
- VM integration providers → vendor-signed
- Anything else → investigate

## Cross-reference
- `Microsoft-Windows-Time-Service/Operational` — events 257/258 at provider load
- `System-7036` — W32Time service state changes
- `Security-4697` — any companion service plant
- `Sysmon-7` — ImageLoad of the provider DLL into the W32Time svchost.exe on boot

## Practice hint
On a lab VM: observe the existing NtpClient / NtpServer entries pointing to w32time.dll. In an elevated cmd prompt: `reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\TestProvider" /v DllName /t REG_EXPAND_SZ /d "C:\test\fake.dll"`. Restart W32Time (`net stop w32time & net start w32time`). Check `Microsoft-Windows-Time-Service/Operational` — a provider-load error appears. This is the signature EVTX analysts hunt for when a fake provider is registered with a missing or blocked DLL. Clean up with `reg delete`.
