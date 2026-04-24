---
name: OfficeMRU
aliases:
- Office File MRU
- Word/Excel/PowerPoint recent files
- Trusted Documents
link: file
tags:
- per-user
- tamper-easy
- application-specific
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: XP
    max: '11'
    note: exact paths vary by Office version — 14.0 (2010), 15.0 (2013), 16.0 (2016/2019/365)
location:
  hive: NTUSER.DAT
  paths:
    - Software\Microsoft\Office\<ver>\Word\File MRU
    - Software\Microsoft\Office\<ver>\Excel\File MRU
    - Software\Microsoft\Office\<ver>\PowerPoint\File MRU
    - Software\Microsoft\Office\<ver>\OneNote\File MRU
    - Software\Microsoft\Office\<ver>\Access\File MRU
    - Software\Microsoft\Office\<ver>\Publisher\File MRU
  trusted-docs-path: Software\Microsoft\Office\<ver>\<app>\Security\Trusted Documents\TrustRecords
  addressing: hive+key-path
fields:
- name: File-MRU-entry
  kind: path
  location: values named 'Item 1', 'Item 2', ..., 'Item 50'
  type: REG_SZ
  encoding: '[F00000000][T<hex-FILETIME>]*<filepath>'
  note: |
    Each value encodes both the file path AND a FILETIME for the last access.
    Format prefix '[F00000000]' is flags; '[T01D7...]' is the last-used FILETIME
    in hex; what follows '*' is the path (local or UNC).
- name: per-entry-time
  kind: timestamp
  location: embedded in value data as '[T<hex-filetime>]' token
  encoding: FILETIME-LE hex-encoded
  clock: system
  resolution: 100ns
  update-rule: on each file open or save (user-initiated)
  note: per-entry timestamp — richer than most MRUs which only give key-level last-write
- name: trust-record
  kind: binary
  location: Trusted Documents\TrustRecords → values named by full file path
  type: REG_BINARY
  encoding: proprietary TrustRecord blob — 24 bytes header with FILETIME + trust flags
  note: marks a document as trusted (macros enabled, content unblocked); strong signal for macro-document execution history
observations:
- proposition: OPENED
  ceiling: C3
  note: Per-Office-app recent-file list. Each entry carries its own FILETIME. Trusted Documents subkey separately records documents the user explicitly trusted (macro enable) — crucial for malicious-macro attribution.
  qualifier-map:
    actor.user: NTUSER.DAT owner
    object.file.path: field:File-MRU-entry
    time.last_open: field:per-entry-time
anti-forensic:
  write-privilege: user
  known-cleaners:
  - tool: Office application File → Options → Clear unpinned recent documents
    typically-removes: File MRU only (not Trusted Documents)
  - tool: CCleaner Office module
    typically-removes: full
provenance: []
provenance: [libyal-libregf, regripper-plugins]
---

# OfficeMRU

## Forensic value
Per-application recent-documents history for every Office app. Distinct from system-wide RecentDocs because:

- **Per-app scope** — Word has its own list, Excel has its own, etc.
- **Per-entry timestamps** — each value carries a FILETIME in its data, unlike RecentDocs where only the key last-write gives a date
- **Full paths including UNC** — network-share opens are captured verbatim
- **Trusted Documents twin** — a separate subkey records documents the user has marked trusted (enabled macros for)

## Trusted Documents — the macro-malware trail
`Software\Microsoft\Office\<ver>\<app>\Security\Trusted Documents\TrustRecords` holds one value per document where the user clicked "Enable Content" (or answered the macro-warning dialog affirmatively). Each value's data contains:
- FILETIME of the trust action
- Flag bytes indicating trust scope (edit, macro, external-content)

For a macro-malware investigation, this subkey is often the decisive artifact:
- "Did the user enable macros on this document?" → TrustRecord presence
- "When?" → embedded FILETIME in the TrustRecord data
- "Which Office app?" → which `<app>` subkey

Even if the document has been deleted, its TrustRecord entry persists — evidence of the trust decision survives.

## Value-data format
```
[F00000000][T01D7C9A2B3C4D5E6]*C:\Users\bob\Documents\report.docx
```
- `[F...]` — flags/version prefix
- `[T<hex>]` — FILETIME as 16 hex chars (8 bytes LE)
- `*` — separator
- trailing — the path (UTF-16LE in raw binary; REG_SZ decodes it automatically)

Parsers that miss the `[T...]` token won't extract per-entry timestamps.

## Cross-references
- **RecentDocs** — system-wide per-extension MRU; some overlap with Word (.docx), Excel (.xlsx), etc.
- **LastVisitedPidlMRU** — common-dialog box history; Office file-picker interactions appear there too
- **Outlook-PST** — when opening a PST, the path is recorded in Outlook's own File MRU under `Outlook\Profiles\<profile>\...` (different subkey tree)
- **Windows-Search-edb** — indexed content of the Office files referenced here

## Practice hint
Trusted-Documents triage for macro-malware hunts:
```powershell
Get-ChildItem "HKCU:\Software\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords" -EA 0 |
  ForEach-Object {
    $props = Get-ItemProperty $_.PSPath
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Value -is [byte[]] } |
      ForEach-Object {
        $bytes = $_.Value
        if ($bytes.Length -ge 8) {
          $ft = [BitConverter]::ToInt64($bytes, 0)
          [pscustomobject]@{
            Path = $_.Name
            Trusted = [datetime]::FromFileTimeUtc($ft)
          }
        }
      }
  }
```
