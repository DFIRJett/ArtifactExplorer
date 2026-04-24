---
name: CMD-History-Doskey
aliases: [cmd.exe F7 history, doskey buffer]
link: user
tags: [per-user, volatile, user-intent]
volatility: persistent
interaction-required: user-action
substrate: windows-text-log
substrate-instance: in-memory (doskey buffer per cmd.exe session)
platform:
  windows: {min: XP, max: '11'}
location:
  path: "NOT PERSISTED — lives in memory of the cmd.exe process until its session ends"
  addressing: process-memory
fields:
- name: command-history-buffer
  kind: record
  location: cmd.exe process memory, F7 recall / doskey /h
  note: "visible on a live system via `doskey /history` inside an active cmd.exe. Lost when the process exits. Memory-forensics tools can recover from a captured RAM image via Volatility's cmdscan / consoles plugins."
  references-data:
  - {concept: ExecutablePath, role: ranProcess}
observations:
- proposition: RECENT_COMMAND_INTENT
  ceiling: C2
  note: "Volatile. Present ONLY on live captures or memory dumps. When present, captures exact command invocations including arguments — stronger evidence than Prefetch (which gives binary but not args)."
  qualifier-map:
    actor.user: owning cmd.exe user
    object.command: field:command-history-buffer
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - {tool: cls or doskey /reinstall, typically-removes: buffer contents}
  - {tool: process exit, typically-removes: full}
provenance: [mitre-t1059]
---

# cmd.exe history (Doskey buffer)

## Forensic value
Volatile counterpart to PSReadline-history. cmd.exe maintains an in-memory history per session (the one F7 / up-arrow recalls). NOT persisted to disk — only recoverable from live-response or memory captures.

## Practice hint
On a live suspect cmd.exe window: `doskey /history` dumps the buffer. Offline: Volatility `windows.cmdscan` / `windows.cmdline` / `windows.consoles` plugins against a captured RAM image.

## Cross-references
- **PSReadline-history** — persistent, per-user PowerShell analog
- **Security-4688** — process-creation events give structured command-line with args (if auditing on)
