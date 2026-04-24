---
name: CryptnetUrlCache
title-description: "Cryptnet URL Cache (content + metadata files — every URL wininet fetched for signature verification)"
aliases:
- cryptnet cache
- Content\MetaData cryptnet files
- CryptoAPI URL cache
link: file
tags:
- download-trail
- execution-evidence
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: Microsoft-Cryptnet-UrlCache
platform:
  windows:
    min: '7'
    max: '11'
  windows-server:
    min: '2008R2'
    max: '2022'
location:
  path-system: '%WINDIR%\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content and \MetaData'
  path-user: '%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content and \MetaData'
  addressing: file-path
  note: "Two parallel directories. Content\\<hash> holds the downloaded bytes; MetaData\\<hash> holds the URL, timestamps, and response headers. Filenames are truncated-hash lookups — match Content and MetaData entries by hash prefix."
fields:
- name: content-file
  kind: content
  location: "Content\\<hash> file"
  encoding: raw-bytes
  note: "The actual downloaded content. For Authenticode revocation checks (the common case) this is a small CRL or certificate file. For .application / ClickOnce / msi signature checks it may be the signed artifact itself."
- name: metadata-file
  kind: content
  location: "MetaData\\<hash> file"
  encoding: binary-header + url
  note: "Binary metadata file. Header contains FILETIMEs (LastModified, Expiry, LastSync), HTTP status code, content length, and — critically — the full URL that was fetched. Parsers (EZ Tools' CryptnetURLCacheParser, KAPE cryptnet module) extract the URL from offset ~0x20 onwards."
- name: url
  kind: identifier
  location: MetaData\<hash> — embedded URL string
  encoding: utf-16le or utf-8 depending on Windows build
  references-data:
  - concept: URL
    role: downloadedFromUrl
  note: "The source URL. THIS is the forensic gold — reveals what the system attempted to download in the background for signature / revocation checks. Includes both signed-binary CRL lookups AND any URL passed to CryptQueryObject / WinVerifyTrust."
- name: last-modified
  kind: timestamp
  location: MetaData\<hash> header — LastModified FILETIME
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "From the HTTP response's Last-Modified header. Indicates when the remote content was last updated."
- name: expiry
  kind: timestamp
  location: MetaData\<hash> header — Expiry FILETIME
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "From HTTP Cache-Control / Expires. Controls when the local cache entry is considered stale."
- name: last-sync
  kind: timestamp
  location: MetaData\<hash> header — LastSync FILETIME
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "When the local cache entry was last refreshed from the remote URL — i.e., when the system actually went to the network to fetch or re-validate. For forensic purposes THIS is 'when Windows reached out to this URL.'"
- name: response-size
  kind: counter
  location: MetaData\<hash> header — ContentLength
  encoding: uint32
  note: "Size in bytes of the cached Content. Cross-reference with Content\\<hash> file size for integrity."
- name: http-status
  kind: enum
  location: MetaData\<hash> header — HTTP status code
  encoding: uint32
  note: "HTTP status of the last fetch (200 / 304 / 404). 404 or non-200 on a URL that is NOT a Microsoft revocation endpoint is a hunt signal."
- name: content-file-mtime
  kind: timestamp
  location: Content\<hash> file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime of the Content file. Pairs with MetaData LastSync as an independent timestamp."
observations:
- proposition: COMMUNICATED
  ceiling: C4
  note: 'The Cryptnet URL Cache is one of the highest-value network-
    reconnaissance artifacts on Windows because it captures URLs that no
    other artifact records. Authenticode revocation checks, ClickOnce
    deployment, MSI signature verification, and any CryptoAPI network
    call land here — including from processes that use their own HTTP
    stack but delegate signature verification to the OS. URLs appear
    here even when Sysmon-22 DNS or Sysmon-3 network events are absent
    (browsers with their own DNS resolvers / network stacks still
    trigger OS-level signature checks against CRL endpoints).'
  qualifier-map:
    direction: sent
    peer.url: field:url
    time.start: field:last-sync
anti-forensic:
  write-privilege: admin
  survival-signals:
  - Content\<hash> file whose corresponding URL is not a Microsoft CRL endpoint (authrootstl.cab, crl.microsoft.com) = application-level download via CryptoAPI; worth investigating the triggering process
  - MetaData\<hash> file with LastSync matching an incident window AND URL pointing to an attacker-controlled domain = explicit fetch for signature / content retrieval by malware using CryptQueryObject
provenance:
  - zimmerman-2021-cryptneturlcacheparser-forensi
  - hull-2020-the-cryptnet-url-cache-an-over
  - ms-working-with-certificate-revocation
---

# Cryptnet URL Cache

## Forensic value
Every time the Windows CryptoAPI reaches out to a URL (Authenticode revocation checks, ClickOnce manifest fetches, MSI signature verification, any `CryptQueryObject` / `WinVerifyTrust` call with network=true) the response is cached here. Two parallel directories:

- `Content\<hash>` — the actual downloaded bytes
- `MetaData\<hash>` — the URL, timestamps, HTTP status, response size

The MetaData file is binary; parsers (Zimmerman's `CryptnetURLCacheParser`, KAPE's Cryptnet module, libyal) extract the URL and FILETIME fields.

**Why it's forensically valuable:**
1. Captures URLs that browsers-with-their-own-DNS (Firefox DoH, Chrome DoH) don't expose to Sysmon-22.
2. Captures OS-initiated background fetches the user never saw — Authenticode revocation check on an executable the user launched tells you the URL of its CRL endpoint, which pinpoints the code-signing certificate.
3. Survives across reboots; per-file artifacts that persist until cache hygiene cleans them up (rare).
4. On system-scope (systemprofile's cache), captures activity from SYSTEM-context CryptoAPI calls — service accounts, scheduled tasks, Windows Update.

## Concept reference
- URL (the fetched URL per MetaData entry)

## Locations
- System: `C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\`
- Per-user: `%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache\`

Both contain `Content\` and `MetaData\` subdirs. Match entries by their truncated-hash filenames.

## Triage
```powershell
# System-scope
Get-ChildItem "C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\"
# User-scope (all users)
Get-ChildItem "C:\Users\*\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\"
```

Parse each MetaData file with Zimmerman's tool:
```cmd
CryptnetURLCacheParser.exe -f "<path-to-metadata-file>"
```

## Attack-chain example
Malicious MSI installer signed with a stolen / revoked certificate is dropped and double-clicked. The following sequence happens:
1. Windows launches msiexec.
2. CryptoAPI verifies the MSI signature — fetches the CRL from the cert's CDP.
3. CRL URL hits the network → Content/MetaData entry written.
4. User sees the install proceed; malware runs.

Forensic reconstruction months later: browser history is gone, Sysmon logs rolled, no Security-4688 for msiexec retained. But the Cryptnet MetaData file survives with the attacker certificate's CRL URL, fingerprinting the code-signing cert the malware was signed with.

## Practice hint
Visit a signed website in Edge or run a signed installer. Immediately check the cache:
```powershell
Get-ChildItem "$env:USERPROFILE\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\" |
  Sort LastWriteTime -Descending | Select -First 5
```
You should see fresh MetaData entries. Parse one of them to see the CRL URL the OS just fetched.
