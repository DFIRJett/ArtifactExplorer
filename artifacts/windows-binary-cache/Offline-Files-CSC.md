---
name: Offline-Files-CSC
title-description: "Client-Side Caching (CSC) — offline copies of network-share files cached locally by the Offline Files feature"
aliases:
- Client-Side Caching
- CSC database
- Offline Files cache
- Folder Redirection cache
link: file
tags:
- network-share-cache
- exfil-artifact
- enterprise-persistence
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: Offline-Files-CSC
platform:
  windows:
    min: '2000'
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  path-v2: "%WINDIR%\\CSC\\v2.0.6\\namespace\\ (Win7+)"
  path-v1: "%WINDIR%\\CSC\\ (legacy Win2000/XP)"
  addressing: file-path
  note: "Client-Side Caching is the Windows Offline Files feature that mirrors specified network-share content to local disk so the user can work offline. CSC database structure: 'namespace' subdirectory holds per-share-path mirrored directory hierarchy. ACL restricts to SYSTEM — raw read requires elevated acquisition. For DFIR, CSC frequently holds data from network shares the host user actively worked on — even after the share itself is decommissioned or the user leaves the network. Enterprise-deployed Folder Redirection + Offline Files means every user's Documents / Desktop / Favorites may be mirrored here."
fields:
- name: cached-file
  kind: content
  location: "CSC\\v2.0.6\\namespace\\<server>\\<share>\\<path>\\<file>"
  encoding: native file content (same as on the server)
  note: "Mirror of a file from a network share. Full content, not a stub. For investigations involving network-share-hosted sensitive data (HR documents, source code, customer databases on file servers), CSC is the ON-CLIENT COPY of that data. Users can exfil from CSC without touching the server — their own cache IS the data."
- name: server-name
  kind: identifier
  location: "directory name immediately under CSC\\v2.0.6\\namespace\\"
  encoding: utf-16le (hostname)
  references-data:
  - concept: MachineNetBIOS
    role: trackerMachineId
  note: "UNC server name whose shares are cached. Reveals which file servers the user's CSC has mirrored content from. Enterprise environments typically have one or two primary file servers — additional unexpected server names = investigate. Hostnames of decommissioned servers preserve in CSC even after the server is gone."
- name: share-name
  kind: identifier
  location: "directory name under <server>\\"
  encoding: utf-16le
  note: "Share name on the server. Full UNC can be reconstructed as \\\\<server>\\<share>\\<path-from-here>. Sensitive-share names (HR$, Finance$, SourceCode$) indicate mirrored access to sensitive content."
- name: cached-mtime
  kind: timestamp
  location: per-file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime of the cached copy. Typically matches the server-side file's mtime at last sync. Stale mtime relative to recent CSC activity = file was cached once and never re-synced (user went offline with it)."
- name: cscdb
  kind: content
  location: "CSC database metadata files (binary state)"
  encoding: proprietary binary
  note: "Internal CSC state tracking which files are dirty / pending-sync / conflicted. Less commonly analyzed directly; the cached file content itself is the primary evidentiary target."
observations:
- proposition: HAD_FILE
  ceiling: C3
  note: 'Offline Files / CSC is one of the most-overlooked sources of
    network-share data in DFIR. For enterprises using Folder
    Redirection + Offline Files, every user''s Documents / Desktop
    content from the file server is mirrored at %WINDIR%\\CSC\\. For
    users configured with specific Offline-Available shares (manual
    "Always available offline" selection on network folders), CSC
    holds copies of exactly those shares. Insider-threat cases: a
    departing employee''s CSC contains local copies of every
    network-share document they worked on — which they may exfil
    before leaving. Network-breach cases: CSC of a compromised user
    contains file-server content that attackers didn''t need to
    access the server to steal. Always acquire and enumerate CSC
    when investigating an endpoint that had Offline Files enabled.'
  qualifier-map:
    object.path: "CSC\\namespace\\<server>\\<share>\\<file>"
    object.content: field:cached-file
    time.end: field:cached-mtime
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: none
  known-cleaners:
  - tool: "disable Offline Files + delete CSC namespace (requires Safe Mode or SYSTEM context)"
    typically-removes: all cached content
  - tool: "csc.exe (Win10+) / Sync Center 'Delete offline files'"
    typically-removes: selective or full cache
  survival-signals:
  - CSC\\v2.0.6\\namespace populated on an enterprise endpoint = Offline Files is / was enabled; inventory cached server+share namespace for exposure review
  - Cached files from shares the user should not have had access to = privilege escalation / share-permission misconfiguration
  - Large CSC with mtimes clustered before a departure / incident date = user pulled many files offline right before the event
provenance: [ms-offline-files-client-side-caching-o, for500-2022-offline-files-forensics-csc-na]
---

# Offline Files (CSC database)

## Forensic value
`%WINDIR%\CSC\v2.0.6\namespace\` is the Offline Files feature's local cache — a mirror of network-share files marked "Always available offline" plus (in many enterprises) redirected-folder content from Folder Redirection GPO.

The namespace structure mirrors UNC paths:
```
CSC\v2.0.6\namespace\
    fileserver01\
        HR$\
            employees\
                roster.xlsx          ← cached copy of network file
        ProjectX\
            source\
                payroll.sql
```

Each file under the namespace is a full content copy — not a stub.

## Why this matters
- **Insider threat**: a user with Offline Files enabled has LOCAL copies of every network-share file they worked on. Exfil from CSC skips server access.
- **Network-breach reconstruction**: CSC holds file-server content without requiring evidence of direct server access.
- **Post-network-decommission recovery**: CSC survives after the source share is taken down.

For enterprise endpoints with Folder Redirection + Offline Files (common setup), every user's Documents / Desktop / Pictures / Favorites directory is mirrored to CSC.

## Concept reference
- None direct — filesystem-level mirror artifact.

## Triage
```cmd
:: Elevated — ACL requires SYSTEM
dir /s "%WINDIR%\CSC\v2.0.6\namespace"

:: Take ownership first if needed (destructive — document first)
takeown /f "%WINDIR%\CSC" /r /d y
icacls "%WINDIR%\CSC" /grant Administrators:F /t /c

:: Acquire the namespace tree
robocopy "%WINDIR%\CSC\v2.0.6\namespace" .\evidence\csc\ /MIR
```

## Cross-reference
- **Folder Redirection policy** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` + GPO mapping) — identifies which folders were redirected and thus likely cached
- **MountPoints2 / Map Network Drive MRU** — network shares the user mapped
- **Security-5140 / 5145** — network share access events (server-side)
- **UsnJrnl of CSC namespace** — when content was created / modified in the cache

## Practice hint
On a lab domain: map a network share, right-click a folder → Always Available Offline. Work online, then disconnect. The cached content is at `%WINDIR%\CSC\v2.0.6\namespace\<server>\<share>\<folder>`. Take ownership and browse — full content is mirrored. That mirror is the artifact insider-threat and network-breach investigators rely on.
