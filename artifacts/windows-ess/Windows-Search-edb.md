---
name: Windows-Search-edb
aliases:
- Windows.edb
- Windows Search Index
- SystemIndex
link: file
tags:
- system-wide
- content-indexing
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-ess
substrate-instance: Windows.edb
platform:
  windows:
    min: Vista
    max: '11'
location:
  path: "%PROGRAMDATA%\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb"
  addressing: ese-table-row
fields:
- name: WorkId
  kind: identifier
  location: SystemIndex_* tables → WorkId column
  note: internal sequence id for every indexed entity
- name: System_ItemPathDisplay
  kind: path
  location: SystemIndex_PropertyStore → WorkId-keyed row
  note: full path of the indexed file/folder
- name: System_FileName
  kind: label
  location: SystemIndex_PropertyStore → FileName
- name: System_DateCreated
  kind: timestamp
  location: SystemIndex_PropertyStore → DateCreated
  encoding: filetime-le
- name: System_DateModified
  kind: timestamp
  location: SystemIndex_PropertyStore → DateModified
- name: System_DateAccessed
  kind: timestamp
  location: SystemIndex_PropertyStore → DateAccessed
- name: System_Search_AutoSummary
  kind: content
  location: SystemIndex_PropertyStore → AutoSummary
  note: extracted textual content — the indexed TEXT of the file, available for keyword search even after the file is deleted
- name: System_Message_ToAddress
  kind: label
  location: SystemIndex_PropertyStore → email-specific properties
  note: "set of email-specific columns — ToAddress, FromAddress, Subject, Body, Attachments; index covers Outlook PST/OST if search scope includes them"
  references-data:
  - concept: EmailAddress
    role: recipient
- name: url-field
  kind: url
  location: SystemIndex_PropertyStore → url-specific properties when Edge/IE history is indexed
  references-data:
  - concept: URL
    role: visitedUrl
observations:
- proposition: CONTENT_OBSERVED
  ceiling: C2
  note: Full-text indexed content for every file, email, and indexed URL the user's Search scope covered. Content survives the source — a deleted file's extracted text remains in Windows.edb until index rebuild.
  qualifier-map:
    object.file.path: field:System_ItemPathDisplay
    object.content.snippet: field:System_Search_AutoSummary
    time.modified: field:System_DateModified
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - tool: Indexing Options → Rebuild
    typically-removes: full (rebuilds from current filesystem state — destroys historical content)
  - tool: net stop WSearch && delete Windows.edb
    typically-removes: full; service will rebuild on restart
provenance: [ms-windows-search-architecture-gather, libyal-libesedb]
---

# Windows-Search-edb

## Forensic value
The Windows Search index holds **full-text content** for every file, email, and sometimes URL within the user's configured indexing scope. This is unique:

- **Extracted text of documents** — the searchable body of Office docs, PDFs (with IFilter), text files. Deleted files' text often survives in Windows.edb because the index is not immediately scrubbed.
- **Email bodies** — if Outlook PSTs/OSTs are indexed, the index contains searchable email content with From/To/Subject/Body/Attachment metadata.
- **File metadata beyond $MFT** — EXIF, ID3, Office metadata (author, last editor, creation app).

In cases where the file on disk has been deleted or overwritten, the extracted content may remain queryable in the index for weeks or months.

## Format quirks
Windows.edb is ESE (Jet Blue). Parse with:
- **ese-analyst** (Mark Baggett) — Python toolset focused on SystemIndex tables
- **libesedb / esedbexport** (Joachim Metz)
- **SearchIndexerExtractor** — specialized Win.edb extractor
- **ElcomSoft Forensic Search** — commercial, full-feature

## Schema highlights
The primary table is `SystemIndex_PropertyStore`. Columns follow the Windows Property System naming (`System.ItemPathDisplay`, `System.DateModified`, etc.). Email content lives under `System.Message.*` properties. Deleted-row recovery via libesedb can yield pre-delete entries.

## Live-file caveat
WSearch service holds `Windows.edb` locked. Options:
- `net stop WSearch` + copy (service will be restarted when re-enabled)
- Shadow-copy + offline parse
- `esentutl /y /vss` to force a consistent copy via VSS

## Cross-references
- **WebCache-V01** — legacy IE/Edge browser content (different ESE DB, similar format)
- **Outlook-PST** / **Outlook-OST** — the PSTs/OSTs that feed email content into Windows-Search-edb
- **RecentDocs** / **LastVisitedPidlMRU** — registry-based file-access history; Windows-Search-edb provides the *content* those records reference

## Practice hint
For email body searches against a cold image:
```python
# Pseudocode — use libesedb or ese-analyst's SystemIndex module
for row in db.SystemIndex_PropertyStore:
    if 'System.Message.Body' in row and query in row['System.Message.Body']:
        print(row['System.ItemPathDisplay'], row['System.Message.From'])
```
