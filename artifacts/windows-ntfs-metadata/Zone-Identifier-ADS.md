---
name: Zone-Identifier-ADS
aliases:
- Zone.Identifier
- mark-of-the-web
- MOTW
- download provenance ADS
link: file
tags: []
volatility: persistent
interaction-required: none
substrate: windows-ntfs-metadata
substrate-instance: ADS on NTFS file
substrate-hub: Streams
platform:
  windows:
    min: XP SP2
    max: '11'
  windows-server:
    min: '2003'
    max: '2022'
location:
  ads-name: <filename>:Zone.Identifier
  addressing: alternate-data-stream on the primary file
fields:
- name: zone-id
  kind: enum
  location: '[ZoneTransfer] section, ZoneId= line'
  encoding: integer-0-to-4
  note: 0=Local, 1=Intranet, 2=Trusted, 3=Internet, 4=Untrusted — browsers and mail clients tag downloads from Zone 3
- name: referrer-url
  kind: path
  location: ReferrerUrl= line (when present)
  encoding: ascii
  references-data:
  - concept: URL
    role: referrerUrl
- name: host-url
  kind: path
  location: HostUrl= line (when present)
  encoding: ascii
  references-data:
  - concept: URL
    role: downloadedFromUrl
  note: the URL of the downloaded resource itself
- name: host-ip-address
  kind: identifier
  location: HostIpAddress= line (Win10+)
  encoding: ip-address-string
  references-data:
  - concept: IPAddress
    role: sourceIp
- name: last-writer-package
  kind: identifier
  location: LastWriterPackageFamilyName= (Win10+)
  encoding: ascii
  note: the app that wrote the file — e.g., 'Microsoft.MicrosoftEdge_8wekyb3d8bbwe'
observations:
- proposition: CREATED
  ceiling: C3
  note: 'MOTW stream proves the file was downloaded (zone >= 3) and captures

    where from. Its absence on a file that should have been downloaded =

    user manually stripped it with `Unblock-File` or stream removal.

    '
  qualifier-map:
    object.path: the file this ADS is attached to
    object.origin-url: field:host-url
    object.referrer-url: field:referrer-url
    object.source-ip: field:host-ip-address
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: PowerShell Unblock-File
    typically-removes: full
    note: explicit user action to remove MOTW
  - tool: streams.exe -d
    typically-removes: full
  survival-signals:
  - file downloaded (as per browser history) but no Zone.Identifier ADS = MOTW manually stripped
  - Zone.Identifier exists but HostUrl/ReferrerUrl absent = older Windows-style MOTW (pre-Win8)
provenance: [libyal-libfsntfs-libfsntfs-ntfs-extended-attrib, carrier-2005-file-system-forensic-analysis]
---

# Zone.Identifier Alternate Data Stream

## Forensic value
NTFS alternate data stream attached to any file downloaded via browser, email, or similar network-origin path. Records the origin zone (Internet, Intranet, etc.) and — on modern Windows — the originating URL, referrer, and source IP.

For any "where did this file come from" question, Zone.Identifier is the authoritative provenance record. Absence on a file that should have one = tampering signal.

## Three concept references
- URL (host-url, referrer-url)
- IPAddress (host-ip-address)

## Known quirks
- **NTFS-only.** FAT32/exFAT don't support alternate data streams; downloads to those filesystems lose MOTW.
- **Stream access**: `Get-Content file.exe -Stream Zone.Identifier` (PowerShell) or `more < "file.exe:Zone.Identifier"` (legacy cmd).
- **Format is INI-like.** `[ZoneTransfer]` header followed by key=value lines. Simple to parse.
- **Win8+ added HostUrl, ReferrerUrl.** Earlier Windows only carried ZoneId.
- **Win10+ added HostIpAddress and LastWriterPackageFamilyName.**

## Practice hint
Download a file with a browser. Check for its Zone.Identifier: `Get-Content download.exe -Stream Zone.Identifier`. Observe the full origin URL. Run `Unblock-File download.exe` — re-check; the stream is gone. That's the deliberate-cleanup signature.
