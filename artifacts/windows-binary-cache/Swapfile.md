---
name: Swapfile
title-description: "Windows swapfile.sys — UWP / Modern-app working-set backing file (distinct from pagefile)"
aliases:
- swapfile
- swapfile.sys
- UWP app swap
- Modern app paging
link: memory
link-secondary: application
tags:
- memory-carve
- uwp-state
- itm:ME
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: Swapfile
platform:
  windows:
    min: '8'
    max: '11'
    note: "Introduced in Windows 8 alongside the Modern (UWP / Metro) app suspension model. Persists on all subsequent Windows releases. Windows 7 and earlier do NOT have a swapfile — only pagefile."
  windows-server:
    min: '2012'
    max: '2022'
location:
  path: "C:\\swapfile.sys (root of system drive — co-located with pagefile.sys)"
  addressing: file-path
  note: "Hidden system file at the root of the system volume. Typical size is 256 MiB to 16 GiB depending on UWP app usage. The file is used to back suspended UWP app processes — Windows suspends a Modern app (fast startup resume experience) by writing its compressed working-set image here and freeing its physical RAM. Live pagefile and swapfile serve DIFFERENT purposes; acquire both."
fields:
- name: suspended-app-state
  kind: content
  location: "swapfile.sys — per-suspended-app compressed memory region"
  encoding: compressed (Microsoft proprietary — not documented; effectively raw upon decompression)
  note: "The in-memory state of every UWP / Modern app that was suspended during this system's uptime. Decompressed regions hold Windows-Store app process memory including: app state, opened document content, entered form data, in-flight SSL session state. For evidentiary purposes the swapfile is a memory-dump of every Store app the user used — one of the richest UWP-era artifacts on the system."
- name: app-identifier-fragments
  kind: identifier
  location: "inside decompressed regions — PackageFamilyName strings, AppContainer SIDs"
  encoding: utf-16le
  references-data:
  - concept: AppID
    role: jumplistApp
  note: "Each suspended region contains the UWP app's identity markers. Cross-reference against the StateRepository (AppRepository\\StateRepository-Machine.srd) to attribute a recovered region to a specific Store app. Unique to swapfile — pagefile has process-context-free pages."
- name: ui-content-fragments
  kind: content
  location: "inside decompressed regions — XAML rendering buffers, WinRT-surface content"
  note: "Modern-app UI content (text displayed in the app, rendered images, in-app browser content for UWP WebView). Recovers what the user SAW in a Store app session that has since closed."
- name: clipboard-content
  kind: content
  location: "inside decompressed regions — app-scoped clipboard handlers"
  note: "Per-app clipboard content for Modern apps. Unlike system-wide Clipboard History (Windows 10+, separate artifact), each UWP app may buffer clipboard state within its own process — suspension freezes that buffer to swapfile."
- name: file-mtime
  kind: timestamp
  location: swapfile.sys $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime — updates on every write. Active Modern-app use keeps mtime current. Stale mtime on a long-running system = user hasn't used UWP apps recently."
- name: file-size
  kind: counter
  location: swapfile.sys size
  encoding: uint64
  note: "Grows on-demand up to system-configured cap. Large swapfile = many Modern apps suspended recently = more evictable content. Systems that never use Store apps may have a minimal swapfile (256 MiB floor)."
observations:
- proposition: HAD_CONTENT
  ceiling: C3
  note: 'Swapfile is the specific-to-UWP complement of the classic
    pagefile. While pagefile captures arbitrary pages from any
    process, swapfile captures compressed memory images of
    specifically-suspended Modern / Store apps. For a user whose
    workflow heavily uses Store apps (Mail, Calendar, Photos,
    WhatsApp, Spotify via Store, edge-launched PWAs), the swapfile
    contains the bulk of their evidentiary UWP-app state. Critically,
    UWP apps close by "suspend → swapfile" rather than full process
    termination, so swapfile content survives what a user perceives
    as "closing the app." Routinely overlooked by analysts focused
    only on pagefile.'
  qualifier-map:
    object.content: field:suspended-app-state
    object.app: field:app-identifier-fragments
    time.end: field:file-mtime
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: none
  known-cleaners:
  - tool: "ClearPageFileAtShutdown=1 (applies to swapfile on modern Windows)"
    typically-removes: content at clean shutdown
  - tool: "disable UWP feature / disable swapfile via registry"
    typically-removes: the file (very unusual configuration; breaks UWP app performance)
  survival-signals:
  - swapfile.sys absent on modern Windows = disabled UWP / swapfile feature (unusual outside server builds)
  - swapfile.sys much larger than expected relative to Store-app usage = many suspended apps recently
provenance: [ms-uwp-app-lifecycle-suspend-resume-sw, forensics-2019-the-windows-swapfile-what-it-c]
exit-node:
  is-terminus: false
  terminates:
    - RAN_PROCESS
    - HAD_CONTENT
  sources:
    - ms-uwp-app-lifecycle-suspend-resume-sw
    - forensics-2019-the-windows-swapfile-what-it-c
  reasoning: >-
    swapfile.sys on Windows 8+ stores suspended-app state for UWP apps and, on modern systems where pagefile.sys is reduced or disabled, captures compressed-memory overflow for legacy processes as well. For RAN_PROCESS / HAD_CONTENT queries about UWP apps or modern-system memory-pressure events, swapfile IS the terminus — no downstream evidence covers the suspended-app memory region.
  implications: >-
    Complement to Hiberfil + Pagefile for modern Windows memory forensics. UWP-app state (MSIX-deployed apps, Store apps) is often recoverable only here since pagefile scope shrank in Win10+. Relevant for cases involving browser-UWP variants, Cortana sessions, Paint 3D, WSL sessions (limited).
  preconditions: "System ran Windows 8+ ; ClearPageFileAtShutdown policy did NOT wipe swapfile"
  identifier-terminals-referenced:
    - ProcessId
    - ExecutablePath
---

# swapfile.sys

## Forensic value
`swapfile.sys` is a separate memory-backing file from `pagefile.sys`, introduced in Windows 8 to support the UWP (Modern / Metro / Store) app suspension model. When a Store app goes suspended:

- Its working-set memory is compressed and written to `swapfile.sys`
- Its RAM pages are freed
- On user return to the app, memory is restored from swapfile for near-instant resume

The forensic consequence: every UWP app the user touched during this system's uptime may have part of its working-set memory compressed into this file. That includes app state (opened documents, typed messages, rendered UI), AppContainer identity markers, and clipboard content.

## Swapfile vs pagefile — different artifacts
- **Pagefile**: arbitrary page frames from any process under memory pressure
- **Swapfile**: compressed working-set images of suspended UWP apps specifically

Acquire BOTH.

## What you recover
- UWP Mail app state (email text, attachments, contact lists)
- Calendar app state (meeting details)
- WhatsApp / Signal for Windows (Modern-app variants) — message content
- Store-installed apps' in-process state
- Edge UWP (legacy) state
- Photos app (viewed images, metadata)

## Concept reference
- None direct — content artifact recovered by carving and decompression.

## Acquisition
```cmd
:: Same as pagefile — file is locked; use VSC
vssadmin create shadow /for=C:
:: Copy from shadow
```

## Carving
Swapfile compression is Microsoft-proprietary and not publicly-specified. Tools:
- Magnet RAM Capture / Magnet Axiom process swapfile natively
- Manual hex inspection + attempt to extract PE / document signatures from decompressed candidate regions
- Combine with a companion memory dump for fuller context

## Cross-reference
- `StateRepository-Machine.srd` under `%ProgramData%\Microsoft\Windows\AppRepository\` — UWP app catalog for attribution
- `%LocalAppData%\Packages\<PFN>\` — UWP app's on-disk state (pair with in-memory state recovered from swapfile)
- `ActivitiesCache.db` — timeline of UWP app usage

## Practice hint
On a Windows 10/11 lab VM: open several Store apps (Photos, Calculator, Microsoft To Do), then switch away without closing them. Wait 5 minutes for suspension. Acquire swapfile.sys via VSC. Use a strings carver across the file — you should find UTF-16LE content fragments from each of those apps (to-do list text, photo filenames, calculator history). That carving capability is what DFIR relies on for real Store-app investigations.
