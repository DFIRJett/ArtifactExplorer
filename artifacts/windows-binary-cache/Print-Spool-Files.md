---
name: Print-Spool-Files
title-description: "Print spool directory — .SPL (EMF/XPS print data) + .SHD (shadow job metadata)"
aliases:
- Print spooler files
- SPL files
- SHD files
- PRINTERS directory
link: file
link-secondary: user
tags:
- print-job-recovery
- exfil-channel
- itm:IF
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: Print-Spool-Files
platform:
  windows:
    min: NT3.1
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  path: "%SystemRoot%\\System32\\spool\\PRINTERS\\"
  addressing: file-path
  note: "Print Spooler service writes two paired files per queued print job: <N>.SPL (the actual print data as EMF / XPS / raw printer language) and <N>.SHD (shadow metadata — job owner, document name, target printer, timestamps). Files are deleted after successful print unless 'Keep printed documents' is enabled on the printer. Orphan files remain after spooler crashes, cancelled jobs, or service stops mid-print."
fields:
- name: spl-content
  kind: content
  location: "PRINTERS\\<N>.SPL"
  encoding: EMF / XPS / printer-raw (printer-driver dependent)
  note: "The actual rendered print data. For EMF spool (GDI-based drivers), the SPL contains GDI commands that can be replayed to an image — tools like EMF Explorer or EMFSpoolViewer reconstruct a visual page. For XPS (XPSDrv), the file IS an XPS document that can be opened directly. This recovers the printed document content even if the source file is gone."
- name: shd-job-owner
  kind: identifier
  location: "PRINTERS\\<N>.SHD — pJobInfo.UserName field"
  encoding: utf-16le
  references-data:
  - concept: UserSID
    role: profileOwner
  note: "Username of the account that submitted the print job. Joins with logon session data (Security-4624) to tie the job to a specific session. For domain printers, DOMAIN\\user format."
- name: shd-document-name
  kind: label
  location: "PRINTERS\\<N>.SHD — pJobInfo.pDocument field"
  encoding: utf-16le
  note: "Original document name as shown to the application's Print dialog ('Employee Roster.xlsx - Microsoft Excel'). High-value: reveals WHAT was printed without parsing the SPL. A document name containing PII-indicating terms plus out-of-hours job timestamp = strong exfil signal."
- name: shd-machine-name
  kind: identifier
  location: "PRINTERS\\<N>.SHD — pJobInfo.pMachineName"
  encoding: utf-16le
  note: "Source hostname of the print job. For a print server, this distinguishes local vs. remote submissions — useful when investigating which workstation initiated a sensitive print."
- name: shd-printer-name
  kind: label
  location: "PRINTERS\\<N>.SHD — pJobInfo.pPrinterName"
  encoding: utf-16le
  note: "Target printer (share name or local device). A home-office / public / non-enterprise printer as target = higher exfil concern."
- name: shd-submit-time
  kind: timestamp
  location: "PRINTERS\\<N>.SHD — pJobInfo.Submitted field"
  encoding: systemtime
  clock: system
  resolution: 1s
  note: "Wall-clock time the job was submitted. Pairs with Microsoft-Windows-PrintService/Operational events 307 / 808."
- name: spl-mtime
  kind: timestamp
  location: PRINTERS\<N>.SPL file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime. Equals SPL content-write time — i.e. the moment the rendered print data was written to the spool directory. Independent check against SHD submit-time."
observations:
- proposition: PRINTED
  ceiling: C4
  note: 'Printing is frequently invisible to endpoint DLP — an insider
    wanting to exfiltrate data can print and walk out with paper,
    leaving no network, USB, or cloud trail. The print spool directory
    is the single strongest server-side / client-side evidence of what
    was printed. Each job writes an SPL + SHD pair with content,
    document name, printer, owner, and timestamp. Default behavior
    deletes both files after successful print, but spooler crashes,
    cancelled jobs, "Keep printed documents" setting, and offline
    printers all leave the files behind. Paired with PrintService EVTX
    events, this is the full printing story.'
  qualifier-map:
    object.content: field:spl-content
    object.name: field:shd-document-name
    actor.user: field:shd-job-owner
    time.start: field:shd-submit-time
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  known-cleaners:
  - tool: net stop spooler + del *.SPL *.SHD
    typically-removes: all pending / retained spool content (elevated prompt required)
  - tool: "disable printer 'Keep printed documents' option"
    typically-removes: retention — prospective jobs delete cleanly after print
  survival-signals:
  - .SPL / .SHD pairs present in PRINTERS directory with mtime in incident window = jobs that failed to delete OR 'Keep printed documents' was on
  - .SPL files whose decoded content matches sensitive document names in SHD = direct evidence
  - PrintService events 307 / 808 with no corresponding spool cleanup event = orphan content still in PRINTERS
  - Repeated identical document names printed to a public / non-corporate printer in short window = probable exfil via print
provenance:
  - ms-print-spooler-architecture-spl-and
  - 13cubed-2020-print-job-forensics-recovering
  - matrix-nd-dt061-detect-text-authored-in
---

# Print Spool Files (SPL / SHD)

## Forensic value
Every print job submitted to the Windows Print Spooler service produces two files in `%SystemRoot%\System32\spool\PRINTERS\`:

- **`<N>.SPL`** — the rendered print data
- **`<N>.SHD`** — the shadow job-metadata record

Under default settings both files are deleted after the job prints successfully. In the real world they frequently aren't:

- Spooler service crashes mid-print
- Printer goes offline with a pending job
- User cancels after submit but before completion
- Printer property "Keep printed documents" is on (rare in enterprise, common on home / legacy printers)

Orphan SPL/SHD pairs are a direct window into prior printing activity.

## Two spool-data formats
1. **EMF (GDI)** — the SPL contains GDI drawing commands; reconstruction requires an EMF-replayer. Common on older drivers.
2. **XPS (XPSDrv)** — the SPL IS an XPS document, openable directly in an XPS viewer. Common on modern Windows.

Check the first bytes of the SPL to determine format (XPS files start with `PK` being ZIP-based; EMF starts with the EMF header).

## Concept references
- None directly — the artifact is file-based with join keys (username, machine, document name) against other artifacts.

## Parsing
- `EMFSpoolViewer` — EMF-format reconstruction
- Any XPS viewer (Edge, XPS Viewer) — XPS-format content
- SHD metadata: custom parser or hex-editor per Microsoft's structure spec

## Correlation
Cross-reference spool files against `Microsoft-Windows-PrintService/Operational` channel events:
- **Event 307** — Document printed (job submitted)
- **Event 808** — Document printed successfully
- **Event 842** — Print job deleted by user

A 307 with no matching 808 in the channel but surviving SPL/SHD files = job interrupted; print actually didn't happen. A 808 with lingering files = retention was on.

## Triage
```cmd
dir /a %SystemRoot%\System32\spool\PRINTERS\
```

Acquire all `*.SPL` + `*.SHD` pairs. Preserve filesystem timestamps. For each pair, parse SHD for metadata first (cheap), then decode SPL for content (expensive, per-file).

## Practice hint
On a test VM: enable a printer's "Keep printed documents" advanced property. Print any Word/Excel document. Navigate to `C:\Windows\System32\spool\PRINTERS\` (elevated command prompt; ACLs restrict normal access). Observe the SPL/SHD pair. Open the SPL in the appropriate viewer — the full document content is recoverable. Then disable "Keep" and print again: files delete automatically. The ON-state is the forensic condition you're hunting for.
