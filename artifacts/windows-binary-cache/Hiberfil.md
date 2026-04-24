---
name: Hiberfil
title-description: "Windows hiberfil.sys — full hibernation image (kernel + drivers + compressed user-memory snapshot)"
aliases:
- hibernation file
- hiberfil.sys
- hibernation image
link: memory
link-secondary: file
tags:
- memory-image
- full-system-state
- itm:ME
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: Hiberfil
platform:
  windows:
    min: '2000'
    max: '11'
    note: "Format has evolved across Windows releases. Pre-Win8 hibernation used the legacy HIBR compressed-image format. Win8+ uses an updated format that also stores kernel and driver state (previously dumped separately). Hibernate + Fast Startup behavior means modern Windows writes hiberfil.sys even after 'shutdown' — Fast Startup is a partial hibernate of the kernel. This makes hiberfil.sys common on home/consumer Windows 10/11 even when the user never explicitly hibernates."
  windows-server:
    min: '2003'
    max: '2022'
location:
  path: "%SystemDrive%\\hiberfil.sys (root of system partition; hidden system file)"
  addressing: file-path
  note: "Typical size ≈ 40% to 75% of installed RAM (configurable via powercfg). On Windows 8+, hiberfil.sys also stores kernel and driver state for Fast Startup — which means a 'clean shutdown' from a modern consumer Windows install produces a populated hiberfil even if the user never explicitly hibernated. Always acquire. File is locked during live operation; use VSC-copy or offline image."
fields:
- name: ram-snapshot
  kind: content
  location: "hiberfil.sys — compressed user-memory pages + kernel state"
  encoding: proprietary compressed (Xpress / LZ77 variants depending on Win version)
  note: "Compressed snapshot of physical RAM at hibernate / fast-startup time. Decompressed, it is a full memory dump — every process's address space, kernel memory, drivers, registry hives (live portions), network state, and crypto material. Equivalent to a memory capture taken at shutdown moment. For DFIR, this is a 'free' memory dump you didn't have to take live. Hibernation Recon (Arsenal Recon) and Volatility convert it to raw memory format."
- name: process-list-at-hibernate
  kind: content
  location: "inside decompressed image — EPROCESS list"
  references-data:
  - concept: ProcessId
    role: sessionContext
  note: "Every process that was running at hibernate time — with PID, parent, command-line, and in-memory artifacts. Attacker processes that existed only in memory (fileless malware, injected payloads) appear here. Compare against surviving on-disk evidence — discrepancies ('this process ran but nothing on disk') = fileless."
- name: network-state
  kind: content
  location: "inside decompressed image — TCP/UDP socket tables, routing tables, ARP cache"
  note: "Active connections at hibernate time. Recovers C2 connections that closed before the attacker cleaned up. Uniquely valuable on hosts acquired after reboot — Sysmon-3 may have rolled but hiberfil preserves the connection list at the last hibernate."
- name: crypto-keys
  kind: content
  location: "inside decompressed image — lsass memory, browser process memory, BitLocker handlers"
  note: "NT hashes (from lsass), TLS session keys, browser-stored credentials in process memory, BitLocker FVEK (Full Volume Encryption Key) when BitLocker was unlocked at hibernate time. Hiberfil + Elcomsoft / Passware = BitLocker-encrypted disk recovered."
- name: hibernate-time
  kind: timestamp
  location: "inside decompressed image — header / kernel time structures"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "When the hibernate event occurred. Serves as a 'state-as-of' stamp for everything recovered from the image. Pair with System-42 (resume from sleep) events and System-507 (sleep events) EVTX records."
- name: file-mtime
  kind: timestamp
  location: hiberfil.sys $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime — updates on each hibernate/Fast-Startup write. Joins with hibernate EVTX events. A stale mtime (weeks old) means hiberfil is preserving an older snapshot — acquire anyway, but interpret timestamps accordingly."
- name: file-size
  kind: counter
  location: hiberfil.sys size
  encoding: uint64
  note: "Typical size is 40%-75% of RAM. Very small hiberfil (< few hundred MB) on a multi-GB-RAM host = 'reduced' hiberfile mode (powercfg /hibernate /type reduced) — only Fast Startup kernel state, no full user memory. Full-size hiberfil (≈RAM size) = standard hibernation / full Fast-Startup with user memory."
- name: hibernation-enabled
  kind: flags
  location: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\HibernateEnabled value"
  type: REG_DWORD
  note: "1 = hibernation enabled (file present), 0 = disabled (file deleted). Attackers with admin may disable via 'powercfg /hibernate off' to destroy evidence; this leaves a signal in the registry LastWrite on the Power key even after the file is deleted."
observations:
- proposition: HAD_CONTENT
  ceiling: C4
  note: 'Hiberfil.sys is one of the highest-yield DFIR artifacts on
    Windows because it provides a full system memory snapshot WITHOUT
    requiring live memory capture. Every process, every kernel
    module, every network connection, every in-memory credential and
    key — preserved in a single file acquirable from an offline
    image. Because modern Windows uses hiberfil for Fast Startup
    (partial kernel hibernate on "shutdown"), hiberfil is present on
    most consumer Windows 10/11 installs even when the user never
    deliberately hibernated. For fileless-malware investigations,
    memory-injected persistence, and BitLocker unlock-state
    recovery, hiberfil is often the single most consequential
    artifact after acquisition.'
  qualifier-map:
    object.content: field:ram-snapshot
    object.credential: field:crypto-keys
    time.end: field:hibernate-time
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: hibernation-image header checksum; partial page-level validation on resume
  known-cleaners:
  - tool: "powercfg /hibernate off"
    typically-removes: the hiberfil.sys file itself (admin required; leaves Power-subsystem registry LastWrite as evidence)
  - tool: "secure-delete / overwrite of hiberfil.sys with file unlocked"
    typically-removes: content (rarely attempted — file is locked during normal operation)
  survival-signals:
  - hiberfil.sys missing on a Win10/11 consumer host = hibernation was explicitly disabled (check Power registry LastWrite for tamper time)
  - hiberfil.sys full-size but HibernateEnabled=0 = hibernation was disabled AFTER the file was written — the disk content survives the registry change (acquire immediately)
  - Acquisition-time delta much newer than hiberfil mtime = OS was running for some time after the preserved snapshot
provenance:
  - ms-hibernate-the-system-hiberfil-sys-f
  - recon-2022-hibernation-recon-convert-hibe
  - foundation-2021-volatility-hibernate-address-s
  - for508-2023-hibernation-file-analysis-in-i
exit-node:
  is-terminus: true
  primary-source: ms-hibernate-the-system-hiberfil-sys-f
  attribution-sentence: 'In a hibernate transition, all the contents of memory are written to a file on the primary system drive, the hibernation file (Microsoft, 2025).'
  terminates:
    - COMMUNICATED
    - RAN_PROCESS
  sources:
    - ms-hibernate-the-system-hiberfil-sys-f
    - recon-2022-hibernation-recon-convert-hibe
    - foundation-2021-volatility-hibernate-address-s
    - for508-2023-hibernation-file-analysis-in-i
  reasoning: >-
    hiberfil.sys is a point-in-time memory snapshot — every running process, loaded driver, open network connection, and in-memory payload at hibernate moment is preserved. For questions about system state at that specific timepoint, Hiberfil is the terminus: no correlation or downstream evidence can refine the answer.
  implications: >-
    Courtroom-grade point-in-time evidence. For COMMUNICATED: the TCP/UDP connection tables in memory name the remote endpoints directly. For RAN_PROCESS: EPROCESS list enumeration is authoritative for what ran at hibernate. Survival through reboot + attacker-cleanup is the key anti-forensic property — even if live artifacts are wiped, hibernation from prior to the wipe may remain.
  preconditions: "System hibernated at least once; hiberfil.sys not zeroed by attacker (powercfg /h off followed by /h on)."
  identifier-terminals-referenced:
    - ProcessId
    - ExecutablePath
    - IPAddress
    - URL
---

# hiberfil.sys

## Forensic value
`hiberfil.sys` is the Windows hibernation image — a compressed snapshot of RAM written when the system enters hibernate state. Decompressed, it is a full memory dump. Equivalent to capturing memory live — except it survives reboot and is acquirable from an offline image without any live-response tooling.

Crucially, **modern Windows uses hiberfil for Fast Startup**: when a consumer Windows 10/11 user clicks "Shut Down," the kernel state is hibernated to hiberfil.sys to enable fast boot. This means hiberfil is present on most consumer systems even when the user never deliberately hibernated.

## What you recover
- Every running process's full address space (EPROCESS list + memory)
- Kernel memory (drivers, kernel modules, SSDT, IRP handlers)
- Live registry hive cached copies
- Active TCP / UDP connection tables
- ARP cache, routing table, DNS resolver cache
- lsass.exe memory including NT hashes, Kerberos tickets, cached credentials
- Browser process memory (saved passwords, session cookies, open tabs)
- **BitLocker FVEK** (Full Volume Encryption Key) when BitLocker was unlocked at hibernate
- Fileless malware executing only in memory

## Compared to pagefile / swapfile
- **Pagefile**: arbitrary evicted pages; no process context
- **Swapfile**: UWP app suspension state only
- **Hiberfil**: FULL memory snapshot at hibernate moment — the richest of the three

## Concept reference
- None direct — content-recovery artifact.

## Acquisition
```powershell
# Live system — file is locked; use VSC
vssadmin create shadow /for=C:
# Copy hiberfil.sys out of the shadow-copy path

# Offline image
# Just copy from disk image mount
```

## Parsing
```powershell
# Arsenal Hibernation Recon (commercial, GUI)
# Produces a raw .bin memory image compatible with Volatility

# Volatility 3 — direct hiberfil support
vol.py -f hiberfil.sys windows.pslist
vol.py -f hiberfil.sys windows.netscan
vol.py -f hiberfil.sys windows.hashdump
vol.py -f hiberfil.sys windows.cmdline
```

## Cross-reference
- **System EVTX** events: 42 (sleep initiated), 1 (sleep enter), 107 (resume from hibernate)
- **HKLM\SYSTEM\CurrentControlSet\Control\Power\HibernateEnabled** — explicit on/off state
- **HKLM\SYSTEM\CurrentControlSet\Control\Power\HiberFileType** — "Full" (default) vs "Reduced"
- **Pagefile / Swapfile** for complementary memory-backed artifacts

## Attack-chain example
Fileless malware runs in memory only; attacker cleans up on-disk droppers. User closes laptop (hibernates). Attacker has no opportunity to wipe hiberfil before seizure. DFIR acquires image, parses hiberfil with Volatility, enumerates EPROCESS — attacker's in-memory process is listed with its command-line and loaded modules. No on-disk evidence, but full in-memory evidence.

## Practice hint
On a lab VM: `powercfg /hibernate on` then hibernate the machine. Power back up, acquire hiberfil.sys via VSC copy. Run Volatility pslist against it — every process from the pre-hibernate session is enumerable. This is the analysis capability DFIR relies on for real memory-preservation cases.
