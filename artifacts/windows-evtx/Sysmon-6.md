---
name: Sysmon-6
title-description: "Driver loaded (kernel-mode driver load; signing + hash + path for rootkit detection)"
aliases:
- Sysmon DriverLoad
- Sysmon 6
link: persistence
link-secondary: system
tags:
- driver-load
- kernel-integrity
- itm:ME
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Sysmon-Operational
platform:
  windows:
    min: '7'
    max: '11'
  windows-server:
    min: '2008R2'
    max: '2022'
location:
  channel: "Microsoft-Windows-Sysmon/Operational"
  event-id: 6
  provider: "Microsoft-Windows-Sysmon"
  addressing: evtx-record
  note: "Fires once per kernel-mode driver loaded into the Windows kernel. Captures ImageLoaded (path), hash set (MD5/SHA1/SHA256/IMPHASH per Sysmon config HashAlgorithms), signing state (Signed flag + Signature name + SignatureStatus), and ProcessId context. Default Sysmon config (Olaf Hartong / SwiftOnSecurity) includes DriverLoad events — essential for rootkit detection. T1014 (Rootkit) and T1068 (Exploitation for Privilege Escalation via driver vuln) both surface here."
fields:
- name: image-loaded
  kind: path
  location: "EventData → ImageLoaded"
  encoding: utf-16le (kernel-format path)
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: "Full path of the loaded driver. Microsoft drivers live under %SystemRoot%\\System32\\drivers\\. Third-party drivers in vendor-specific paths (typically Program Files or dedicated driver directories). Attacker-loaded drivers in unusual paths (%TEMP%, user-writable locations) = candidate rootkit. BYOVD (Bring Your Own Vulnerable Driver) attacks load legitimately-signed BUT KNOWN-VULNERABLE drivers to abuse their kernel-mode capabilities — check loaded drivers against Microsoft's known-vulnerable-driver list."
- name: hashes
  kind: hash
  location: "EventData → Hashes"
  encoding: "MD5=... SHA256=... IMPHASH=... (concatenated per Sysmon HashAlgorithms config)"
  references-data:
  - concept: ExecutableHash
    role: contentHash
  note: "Cryptographic hashes of the driver binary. Cross-reference against VirusTotal / MSRC / internal threat intel for attribution. Microsoft's LOLDrivers project maintains a public list of known-vulnerable drivers by hash — Sysmon-6 hashes matching LOLDrivers = BYOVD indicator."
- name: signed
  kind: flags
  location: "EventData → Signed"
  encoding: "true / false"
  note: "true = driver has a valid Authenticode signature. false = unsigned. Modern Windows (10 / 11) refuses to load unsigned kernel drivers by default unless testsigning is on. Unsigned driver loaded = BCD-testsigning-on OR kernel-signing bypass exploit. Pair with BCD-Store registry for context."
- name: signature-name
  kind: label
  location: "EventData → Signature"
  encoding: utf-16le signer string
  note: "Publisher name from the signing certificate (e.g., 'Microsoft Windows Publisher', 'NVIDIA Corporation'). Attacker drivers signed with: stolen legitimate certs (signer = legitimate vendor but hash + filename don't match vendor catalog), purpose-attacker-obtained code-signing certs (signer = unknown entity), self-signed on testsigning hosts."
- name: signature-status
  kind: enum
  location: "EventData → SignatureStatus"
  encoding: status string
  note: "'Valid' / 'Expired' / 'UntrustedRoot' / 'Unknown'. Non-'Valid' status on a loaded driver = integrity issue — either signing cert problems OR attacker bypass."
- name: process-id
  kind: identifier
  location: "EventData → ProcessId"
  encoding: uint32
  references-data:
  - concept: ProcessId
    role: actingProcess
  note: "PID of the process that triggered the driver load (typically the Service Control Manager or System process). For user-initiated driver loads (e.g., via sc.exe or net start), PID identifies the initiator — joins to Security-4688 / Sysmon-1 process-creation record."
- name: utc-time
  kind: timestamp
  location: "EventData → UtcTime + System/TimeCreated"
  encoding: ISO-ish UTC timestamp
  clock: system
  resolution: 1ms
  note: "Driver load time. Pair with System-7045 (service install) when the driver is loaded via a newly-created service — T1543.003 kernel-driver-service persistence combo."
observations:
- proposition: LOADED_DRIVER
  ceiling: C4
  note: 'Sysmon-6 is the primary DFIR source for kernel driver load
    events on hosts where Sysmon is deployed. Native Windows does not
    log driver loads to Security channel by default — without Sysmon,
    driver loads are nearly-invisible. For rootkit / BYOVD / kernel-
    exploitation investigations, Sysmon-6 is often the only artifact
    that surfaces the attacker driver with hash + signing state +
    loading process. Pair with CodeIntegrity-3077 (native channel
    event for unsigned driver load attempt) and System-7045 (service
    install) for complete driver-persistence coverage.'
  qualifier-map:
    setting.dll: field:image-loaded
    object.hash: field:hashes
    actor.process: field:process-id
    time.start: field:utc-time
anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX-level; Sysmon config signing separately
  known-cleaners:
  - tool: "stop Sysmon service + delete / clear Microsoft-Windows-Sysmon/Operational channel"
    typically-removes: all Sysmon events (high noise — Sysmon service stop = event 255 on same channel)
  survival-signals:
  - Signed=false driver load = unsigned driver on testsigning-mode host OR signing-bypass exploit
  - Driver path outside %SystemRoot%\System32\drivers\ AND outside vendor-specific directories = candidate suspicious load
  - Signature="Microsoft Windows" but hash not matching Microsoft driver catalog = likely stolen Microsoft-signed cert abuse (historical: CCleaner, NotPetya)
  - Driver hash matching LOLDrivers / vulnerable-driver list = BYOVD candidate
provenance: [ms-sysmon-system-monitor, project-2024-living-off-the-land-drivers-vu, mitre-t1014]
---

# Sysmon Event ID 6 — DriverLoad

## Forensic value
Sysmon-6 fires once per kernel-mode driver load. Captures image path, cryptographic hashes, signing state, signer name, and triggering process. Essential for:

- **Rootkit detection** (T1014): unsigned or attacker-signed drivers loaded into the kernel
- **BYOVD detection** (T1068): legitimately-signed but KNOWN-VULNERABLE drivers loaded for kernel-level privilege escalation
- **Stolen-cert attribution**: drivers signed by "legitimate" vendors but not matching vendor catalog

Without Sysmon, driver load events are NOT surfaced on the native Security channel — CodeIntegrity channel catches signing failures but doesn't log successful loads.

## Concept references
- ExecutablePath, ExecutableHash, ProcessId

## Triage
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=6} -MaxEvents 100 |
    ForEach-Object {
        $x = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time = $_.TimeCreated
            Driver = ($x.Event.EventData.Data | ? Name -eq 'ImageLoaded').'#text'
            Signed = ($x.Event.EventData.Data | ? Name -eq 'Signed').'#text'
            Signature = ($x.Event.EventData.Data | ? Name -eq 'Signature').'#text'
            Status = ($x.Event.EventData.Data | ? Name -eq 'SignatureStatus').'#text'
            Hashes = ($x.Event.EventData.Data | ? Name -eq 'Hashes').'#text'
        }
    } | Format-Table -AutoSize
```

## Cross-reference
- **CodeIntegrity-3077** — native channel event for unsigned driver load attempts
- **System-7045** — service install (if driver loaded via new service)
- **Security-4697** — service install at Security channel
- **BCD-Store** registry — testsigning state context
- **Amcache-InventoryDriverBinary** — companion persistent driver inventory

## Practice hint
On a lab VM with Sysmon running: `sc create testdrv binPath= C:\Windows\System32\drivers\null.sys type= kernel` + `sc start testdrv`. Observe Sysmon-6 for null.sys load. Note Signed=true, Signature=Microsoft Windows. That's the baseline for legitimate driver loads. Attacker drivers deviate on Signed / Signature / ImageLoaded path.
