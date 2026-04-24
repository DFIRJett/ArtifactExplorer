---
name: Sysmon-7
title-description: "Image loaded"
aliases:
- Sysmon ImageLoaded
- DLL-load event
- module-load event
link: application
tags:
- timestamp-carrying
- tamper-hard
volatility: runtime
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Sysmon/Operational
platform:
  windows: { min: "7", max: "11", note: Sysmon required }

location:
  channel: Microsoft-Windows-Sysmon/Operational
  event-id: 7
  log-file: "%WINDIR%\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx"

fields:
- name: rule-name
  kind: label
  location: EventData\RuleName
  encoding: utf-16le
  note: Matching config rule name. Because Event 7 is extremely high-volume, well-tuned configs heavily rely on named rules for filter clarity.
- name: utc-time
  kind: timestamp
  location: EventData\UtcTime
  encoding: iso8601-utc
  clock: system
  resolution: 1ms
- name: process-guid
  kind: identifier
  location: EventData\ProcessGuid
  encoding: guid-string
- name: process-id
  kind: identifier
  location: EventData\ProcessId
  encoding: uint32
  references-data:
  - concept: ProcessId
    role: actingProcess
  note: PID of the process into which the module was loaded.
- name: image
  kind: path
  location: EventData\Image
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: actingProcess
  note: the process into which the module was loaded
- name: image-loaded
  kind: path
  location: EventData\ImageLoaded
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: loadedModule
  note: the DLL/EXE module that was loaded — this is the forensic target
- name: file-version
  kind: identifier
  location: EventData\FileVersion
  encoding: utf-16le
- name: description
  kind: identifier
  location: EventData\Description
  encoding: utf-16le
- name: product
  kind: identifier
  location: EventData\Product
  encoding: utf-16le
- name: company
  kind: identifier
  location: EventData\Company
  encoding: utf-16le
- name: original-file-name
  kind: identifier
  location: EventData\OriginalFileName
  encoding: utf-16le
  note: "PE OriginalFilename resource. Mismatch with ImageLoaded's filename = renamed binary — canonical DLL-side-load indicator (legitimate DLL name at a wrong path with a different embedded OriginalFileName)."
- name: hashes
  kind: hash
  location: EventData\Hashes
  encoding: "compound string 'MD5=...,SHA1=...,SHA256=...,IMPHASH=...'"
  references-data:
  - concept: ExecutableHash
    role: ranHash
  note: hash of the LOADED module (not the process)
- name: signed
  kind: flags
  location: EventData\Signed
  encoding: bool
  note: whether the loaded module carries a valid Authenticode signature
- name: signature
  kind: identifier
  location: EventData\Signature
  encoding: utf-16le
  note: signer name when Signed=true
- name: signature-status
  kind: enum
  location: EventData\SignatureStatus
  encoding: "'Valid' / 'NotSigned' / 'Expired' / 'Invalid' / etc."
- name: user
  kind: identifier
  location: EventData\User
  encoding: "'DOMAIN\\username'"

observations:
- proposition: EXECUTED
  ceiling: C4
  note: |
    Module-load event. Not process execution per se, but the DLL's code
    executes when loaded — forensically equivalent for "this module's code
    ran." Primary signal for DLL-side-load detection and malicious DLL
    injection tracking.
  qualifier-map:
    process.host-image: field:image
    process.loaded-module: field:image-loaded
    process.module-hash: field:hashes
    actor.user: field:user
    time.start: field:utc-time

anti-forensic:
  write-privilege: service
  integrity-mechanism: EVTX checksums
  survival-signals:
  - unsigned DLL loaded into signed-process host (lsass.exe, explorer.exe) = classic injection pattern
  - DLL loaded from %TEMP%, %APPDATA%, or network path = high-suspicion
  - known-good DLL name with signer mismatch = side-load replacement
provenance:
  - ms-sysmon-system-monitor
  - hartong-2024-sysmon-modular-7-image-load-ru
  - sans-2022-sysmon-event-7-dll-side-loadin
---

# Sysmon Event 7 — Image Loaded

## Forensic value
Per-process DLL/EXE load event. Each record captures the host process + the loaded module path + hash + signature status. For DLL-side-loading attacks (a primary technique in modern malware), Sysmon-7 is the detection event.

High volume — default Sysmon configs filter aggressively. Enabling comprehensive ImageLoad coverage produces hundreds of events per process startup; typical filters focus on suspicious paths, unsigned modules, or specific sensitive processes.

## Three concept references
- ExecutablePath (image — actingProcess) + (image-loaded — loadedModule)
- ExecutableHash (hashes — ranHash)

## Primary use cases
- **DLL side-loading** — legitimate process loads attacker DLL with matching name from wrong path
- **Reflective DLL injection** — not always visible here; Sysmon-7 sees filesystem-loaded modules
- **Unsigned-module-in-signed-process** — common injection tell
