---
name: COM-HijackKeys
title-description: "COM CLSID InprocServer32 / InprocHandler32 / LocalServer32 hijack registry"
aliases:
- COM hijacking
- CLSID persistence
- InprocServer32 hijack
link: persistence
tags:
- persistence-primary
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: NT3.1
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SOFTWARE (HKLM) + NTUSER.DAT / UsrClass.dat (HKCU)
  path: "Classes\\CLSID\\<CLSID>\\InprocServer32 (and \\InprocHandler32, \\LocalServer32)"
  addressing: hive+key-path
  note: "COM CLSIDs are resolved via HKCR (merged view of HKLM\\SOFTWARE\\Classes + HKCU\\SOFTWARE\\Classes). Per-user hijack in HKCU takes PRECEDENCE over HKLM's machine-wide entry — classic unprivileged persistence technique (COM search-order hijack)."
fields:
- name: clsid
  kind: identifier
  location: "<CLSID> subkey name under Classes\\CLSID"
  encoding: guid-string
  note: "The COM class identifier being registered or hijacked. Well-known abused CLSIDs include {AB8902B4-09CA-4bb6-B78D-A8F59079A8D5} (COMCAT category manager), {42aedc87-2188-41fd-b9a3-0c966feabec1} (Shell.Explorer delegation), and IE's browser helper object CLSIDs."
- name: inproc-server32
  kind: path
  location: "InprocServer32\\(Default) value"
  type: REG_SZ / REG_EXPAND_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Path to the in-process DLL implementing the COM object. Loaded into whatever process instantiates the CLSID. Hijack = replace with attacker DLL; every caller of CoCreateInstance(<CLSID>) loads the attacker code."
- name: inproc-handler32
  kind: path
  location: "InprocHandler32\\(Default) value"
  type: REG_SZ / REG_EXPAND_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "DLL that provides lightweight local handling of a remote COM object. Less common than InprocServer32 but equally weaponizable; same load semantics when the CLSID is instantiated locally."
- name: local-server32
  kind: path
  location: "LocalServer32\\(Default) value"
  type: REG_SZ / REG_EXPAND_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Full executable path launched as its own process to host the COM object (out-of-process server). Attacker gets a new process spawning whenever the CLSID is activated; process name can be anything, persistence trigger is COM activation rather than boot/logon."
- name: threading-model
  kind: label
  location: "InprocServer32\\ThreadingModel value"
  type: REG_SZ
  note: "'Apartment' / 'Free' / 'Both' / 'Neutral'. Usually doesn't change across hijack; presence of a non-default ThreadingModel on a CLSID whose DLL path looks suspicious is a secondary signal."
- name: key-last-write-inproc
  kind: timestamp
  location: InprocServer32 key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "Per-CLSID LastWrite under the InprocServer32 subkey. Post-install creation/modification of a CLSID registration is a higher-suspicion signal than the broad Classes\\CLSID tree (which is touched continuously by legitimate software)."
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'COM hijack is one of the broadest persistence mechanisms on Windows
    because the trigger is "any process activates this CLSID" — thousands
    of CLSIDs, and OS components / Office / browsers / shell constantly
    activate them. Combined with HKCU precedence over HKLM, a non-admin
    attacker can achieve user-scope persistence by populating the per-
    user Classes\\CLSID hive. Detection requires BOTH registry inventory
    AND path-validity checking (DLL path outside System32 for an inbox
    CLSID = suspicious).'
  qualifier-map:
    setting.registry-path: "Classes\\CLSID\\<CLSID>\\InprocServer32"
    setting.dll: field:inproc-server32
    time.start: field:key-last-write-inproc
anti-forensic:
  write-privilege: unknown
  survival-signals:
  - "HKCU Classes\\CLSID\\<CLSID> for a CLSID that's already registered in HKLM = search-order hijack"
  - "Inbox-CLSID InprocServer32 pointing outside %SystemRoot%\\System32 = replacement"
  - "CLSID with LastWrite post-dating OS install + no corresponding installer event in System-7045 / Security-4697 = drive-by registration"
  - "LocalServer32 path pointing to a script interpreter (cmd.exe / powershell.exe / wscript.exe) with arguments = likely COM-scriplet abuse"
provenance: [ms-registering-com-servers, mitre-t1546-015, enigma0x3-2017-userland-persistence-with-sche]
---

# COM CLSID hijack

## Forensic value
COM is the broadest persistence mechanism in Windows because the trigger condition — "any process calls CoCreateInstance on this CLSID" — is constantly met by normal system activity. Shell, Explorer, Office, browsers, and OS components all activate CLSIDs continuously. Hijacking the right CLSID guarantees execution inside trusted processes.

Three registration values under each `Classes\CLSID\<CLSID>` subkey:
- `InprocServer32` — in-process DLL (loaded into the caller's process)
- `InprocHandler32` — lightweight local handler DLL
- `LocalServer32` — out-of-process executable server

## HKCU precedence
The resolution order `HKCR` = `HKCU\SOFTWARE\Classes` merged over `HKLM\SOFTWARE\Classes`. When the same CLSID is registered in both, **HKCU wins for the current user**. This means a non-admin attacker who writes to HKCU can intercept any CLSID activation in their own user session — no admin rights needed.

This "COM search-order hijack" variant (MITRE T1546.015) is attractive because:
- Admin not required
- Survives across logons (persisted in NTUSER.DAT)
- Invisible to admin-focused registry sweeps that only check HKLM

## Concept reference
- ExecutablePath (one per InprocServer32 / InprocHandler32 / LocalServer32)

## Triage
Admin-scope:
```cmd
reg query HKLM\SOFTWARE\Classes\CLSID /s /f "InprocServer32" /t REG_SZ
```

Per-user (must enumerate per user):
```cmd
reg query HKCU\SOFTWARE\Classes\CLSID /s /f "InprocServer32" /t REG_SZ
```

Cross-reference every CLSID found in HKCU against its HKLM counterpart — matching pair = hijack.

## Practice hint
On a test VM, pick a well-known benign CLSID (e.g. Image Catalog Thumbnail Handler) and register an HKCU hijack pointing to a harmless DLL. Trigger it by opening an image in File Explorer. Observe which user-process loads the DLL — typically `explorer.exe` for shell-related CLSIDs.
