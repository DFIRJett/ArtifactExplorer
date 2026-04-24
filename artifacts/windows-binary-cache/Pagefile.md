---
name: Pagefile
title-description: "Windows pagefile.sys — disk-backed virtual-memory overflow; carve for credentials, URLs, decrypted payloads"
aliases:
- pagefile
- pagefile.sys
- page file
- virtual memory swap
link: memory
link-secondary: file
tags:
- memory-carve
- credential-recovery
- itm:ME
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: Pagefile
platform:
  windows:
    min: NT3.1
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  path: "C:\\pagefile.sys (root of system drive; path configurable via Control Panel → System → Advanced → Performance → Virtual Memory)"
  addressing: file-path
  note: "Hidden system file at the root of the system partition. Default size = RAM-size on modern Windows (dynamically managed). Multiple pagefiles possible (swapping.sys per volume). Always acquire via raw-disk read or VSC-copy — the file is locked by the Memory Manager during live operation."
fields:
- name: page-content
  kind: content
  location: "pagefile.sys — 4 KiB page-aligned data (page-index ordered; no internal structure)"
  encoding: raw-bytes (no file-system overlay)
  note: "Raw page frames that the Memory Manager has evicted from physical RAM. No ordering or metadata — pages are written in whatever slot is free. Carving, not parsing. Volatility's 'pagefile' plugin can MAP a pagefile into a memory analysis if you have the companion memory image, but the pagefile alone is carveable for strings, regex-matched URLs, credential patterns, and known-bad byte sequences."
- name: credential-strings
  kind: content
  location: "inside page frames — ASCII or UTF-16LE passwords / NT hashes / tickets"
  note: "Cleartext credentials frequently land here because the OS pages out lsass.exe's working set (depending on memory pressure) and because browsers, VPN clients, and RDP clients handle passwords as plain strings in their own address space before freeing. Grep with regex patterns for 'Password=', 'PSK=', Kerberos AS-REQ structures, NTLM responses, and JWT tokens."
- name: url-trail
  kind: content
  location: "inside page frames — http:// / https:// strings + HTTP headers in UTF-16LE"
  encoding: utf-16le
  references-data:
  - concept: URL
    role: visitedUrl
  note: "Browser and application URL fetches leave full URL strings in pagefile pages. Useful when browser history is cleared or the browser uses a DNS-over-HTTPS stack that bypasses host DNS telemetry — the URL string still lands in the browser's paged-out working set."
- name: decrypted-payload
  kind: content
  location: "inside page frames — PE headers (MZ...PE\\0\\0) or shellcode in attacker-process working sets"
  encoding: raw-bytes
  note: "Malware that decrypts payloads in memory at runtime leaves the DECRYPTED form in pagefile pages when the OS evicts those pages. Pagefile carving can recover the plaintext payload even when the on-disk dropper remains encrypted. Classic technique: scan for MZ+PE signatures, extract, analyze with static tools."
- name: clipboard-fragments
  kind: content
  location: "inside page frames — text/image clipboard content handled by applications"
  note: "Any process that held the clipboard leaves residue. Copied passwords, document excerpts, URLs — fragments survive until the page is reused."
- name: file-mtime
  kind: timestamp
  location: pagefile.sys $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime — updated by the Memory Manager on every write. Live systems show near-current mtime constantly; acquired images preserve the mtime at acquisition time, useful as a 'system was up to at least this moment' signal."
- name: file-size
  kind: counter
  location: pagefile.sys size
  encoding: uint64
  note: "Dynamically managed; typical range on Win10/11 is half-RAM to 1.5x-RAM. Large pagefiles on low-RAM systems indicate memory pressure events and thus MORE evicted content to carve."
- name: clearing-policy
  kind: flags
  location: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\ClearPageFileAtShutdown value"
  type: REG_DWORD
  note: "0 = do not clear at shutdown (default; pagefile content persists across reboot as evidence); 1 = zero the pagefile at clean shutdown (anti-forensics-relevant: hardened environments enable this, and attackers occasionally enable it to destroy pre-reboot evidence)."
observations:
- proposition: HAD_CONTENT
  ceiling: C3
  note: 'The pagefile is one of the highest-yield DFIR artifacts for
    recovering content that normally dies with process termination —
    cleartext credentials, decrypted malware payloads, visited URLs,
    clipboard residue, BitLocker recovery keys, TLS session keys.
    Unlike memory dumps, the pagefile persists across reboot unless
    ClearPageFileAtShutdown is enabled. It is disk-backed so it is
    acquirable from an offline image without live-response tooling.
    Critically, pagefile content is process-context-free — you get
    ARBITRARY pages from ANY process that was resident during the
    pagefile''s life, which is why a full-system grep against the
    pagefile surfaces evidence no other single artifact provides.'
  qualifier-map:
    object.content: field:page-content
    object.credential: field:credential-strings
    peer.url: field:url-trail
    time.end: field:file-mtime
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: none
  known-cleaners:
  - tool: "ClearPageFileAtShutdown=1 + clean shutdown"
    typically-removes: all content (zero-fill pass at shutdown — requires legitimate shutdown; abrupt power-off skips this)
  - tool: "disable pagefile and reboot"
    typically-removes: the file itself (very visible configuration change; live Windows under any memory pressure will struggle)
  survival-signals:
  - ClearPageFileAtShutdown=1 on a workstation without an enterprise hardening policy = deliberate anti-forensics
  - pagefile.sys missing on a system where Windows is running = disabled pagefile (unusual; check SYSTEM event channel for Memory Manager events)
  - Pagefile age much older than OS uptime = suspicious (normal behavior is constant writes; a stale pagefile suggests the file is not backing actual paging, which is rare on a live OS)
provenance:
  - ms-manage-virtual-memory-paging-file-m
  - foundation-2021-volatility-hibernate-address-s
exit-node:
  is-terminus: true
  primary-source: ms-manage-virtual-memory-paging-file-m
  attribution-sentence: 'Page files enable the system to remove infrequently accessed modified pages from physical memory to let the system use physical memory more efficiently for more frequently accessed pages (Microsoft, 2022).'
  terminates:
    - COMMUNICATED
    - RAN_PROCESS
  sources:
    - ms-manage-virtual-memory-paging-file-m
    - foundation-2021-volatility-hibernate-address-s
  reasoning: >-
    pagefile.sys captures paged-out portions of process virtual address space. For non-resident process memory (evicted from RAM), pagefile is the only source of the bytes. Carved PE signatures, URL fragments, or credential strings found in pagefile pages are direct evidence that the process ran (or communicated) in this system's memory — terminating the chain without needing corroboration.
  implications: >-
    Recovers content from processes that exited before live acquisition or that were paged out under memory pressure. Especially valuable when in-memory-only malware is suspected — if the payload touched pagefile, it's recoverable. Pairs with Hiberfil for complete memory-state reconstruction.
  preconditions: "pagefile.sys is not zeroed (ClearPageFileAtShutdown policy disabled)."
  identifier-terminals-referenced:
    - ProcessId
    - ExecutablePath
    - URL
---

# pagefile.sys

## Forensic value
`pagefile.sys` is the Windows Memory Manager's disk-backed virtual-memory overflow. When RAM pressure evicts pages, the Memory Manager writes them to this file. The file is:

- **Process-agnostic** — pages from any process that was resident may land here
- **Reboot-surviving** (by default) — ClearPageFileAtShutdown is 0 on standard Windows installs
- **Disk-acquirable** — no live-response tooling needed
- **Carveable** — raw page frames, no filesystem overlay; use `strings`, regex hunts, PE-signature carving

## What you can recover from a pagefile alone
- Cleartext passwords / API tokens / session cookies paged out from browsers / VPN clients / RDP clients / lsass
- Decrypted malware payloads (PE signatures, shellcode)
- URLs visited (including DoH / browser-private-DNS fetches that bypass host DNS logging)
- Clipboard fragments
- BitLocker recovery keys (when key handlers paged out)
- TLS session keys (when browsers / stacks paged out during session)
- SQL query result fragments
- Chat / document text from any paged-out app

## Acquisition
```cmd
:: Live system — VSC-copy or raw disk
vssadmin create shadow /for=C:
:: then copy pagefile.sys out of the VSC snapshot

:: Offline image — use FTK Imager / X-Ways / dd
```

`pagefile.sys` is locked on a live system — direct copy fails. Use VSC or acquire the disk image.

## Carving workflow
```bash
# String-carve for URLs
strings -el pagefile.sys | grep -E 'https?://' > urls-utf16.txt
strings pagefile.sys | grep -E 'https?://' > urls-ascii.txt

# Credential-hunt regex
strings -el pagefile.sys | grep -iE 'password[=:]|psk=|apikey=|bearer '

# PE carve
foremost -t exe,dll -i pagefile.sys -o carved/

# Combined with memory image (Volatility)
vol.py -f memory.raw --pagefile pagefile.sys windows.pslist
```

## Concept reference
- URL (carved from page content)

## Cross-reference
- Companion memory image (Volatility's --pagefile flag for unified VA translation)
- `$MFT` entry for `pagefile.sys` gives size and timestamps
- `ClearPageFileAtShutdown` registry value documents tamper policy

## Practice hint
On a lab VM: browse a few HTTPS sites, type a fake password in a login form, force some memory pressure (open many apps). Acquire the pagefile via VSC copy, then run `strings -el pagefile.sys | grep -iE 'password='` — your fake password should surface as a hit. That is the recovery capability you rely on for real investigations.
