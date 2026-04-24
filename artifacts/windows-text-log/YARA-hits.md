---
name: YARA-hits
aliases:
- YARA match log
- yara scanner output
- YARA detection record
link: security
tags:
- timestamp-carrying
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: yara-scan-<timestamp>.log
platform:
  windows:
    any: true
  linux:
    any: true
  macos:
    any: true
location:
  path: deployment-specific — typically SIEM-forwarded or a scanner-specific output dir
  addressing: scan-id + match-id
fields:
- name: scan-timestamp
  kind: timestamp
  location: scan-run metadata
  encoding: iso8601
  clock: scanner-system
  resolution: 1s
- name: file-path
  kind: path
  location: match record — file-path field
  encoding: utf-8
  references-data:
  - concept: ExecutablePath
    role: scannedTarget
- name: file-hash
  kind: hash
  location: match record — hash field
  encoding: hex-string
  references-data:
  - concept: ExecutableHash
    role: detectedHash
  note: typically SHA256 in modern YARA outputs
- name: rule-name
  kind: identifier
  location: match record — rule name
  encoding: ascii
- name: tags
  kind: identifier
  location: match record — rule tags array
  encoding: ASCII comma-separated or JSON array
  note: e.g., 'malware,trojan,APT29' — rule author's categorization
- name: strings-matched
  kind: identifier
  location: match record — per-string hits
  encoding: offset + matched-bytes
observations:
- proposition: EXISTS
  ceiling: C2
  note: 'YARA matches are HEURISTIC — a rule match indicates a file contains

    patterns the rule author believes are indicative, not a definitive

    identification. Ceiling capped at C2; corroborate with hash-match

    against known-bad feeds or sandbox detonation for stronger claims.

    '
  qualifier-map:
    entity.path: field:file-path
    entity.hash: field:file-hash
    entity.classification: field:rule-name
    time.start: field:scan-timestamp
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: none unless forwarded to immutable SIEM
  known-cleaners:
  - tool: delete log file
    typically-removes: full
  survival-signals:
  - SIEM has YARA-hit entries not present in local log = local tampering
  - YARA-hit exists for a file no longer on disk = file was deleted after scan; quarantined or manually cleaned
provenance: []
---

# YARA Scanner Match Log

## Forensic value
Output of YARA (or commercial equivalents) rule-matching against files. Each match records: scanned file path, file hash, rule name, tag categories, and which rule strings hit.

Typically a derived/analysis artifact rather than a primary source — an investigator RUNS YARA over collected evidence and writes these logs. But recorded logs from automated scanning infrastructure become primary evidence of "what the scanner saw."

## Two concept references
- ExecutablePath (file-path scanned)
- ExecutableHash (file-hash)

## Known quirks
- **Format varies by runner.** `yara -m` outputs plain lines; `yara --print-meta` adds metadata. Enterprise scanners (VMware Carbon Black, Falcon) wrap YARA output in their own format.
- **False positives common.** YARA rules can be over-broad; a match alone doesn't prove maliciousness. Report as "pattern match" not "malware confirmed."
- **Rule provenance matters.** Open-source rule packs (YARA-rules, Neo23x0/signature-base) have known qualities; custom rules need review before trusting matches.

## Practice hint
Run `yara /path/to/rulefile.yar /path/to/suspect-dir -r -s --print-meta` on a test directory with a known EICAR test file. Observe the match output format. Pipe to CSV for bulk analysis.
