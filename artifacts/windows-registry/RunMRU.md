---
name: RunMRU
aliases:
- Win+R history
- Run dialog MRU
link: user
tags:
- per-user
- tamper-easy
- user-intent
- recency-ordered
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: XP
    max: '11'
location:
  hive: NTUSER.DAT
  path: Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
  addressing: hive+key-path
fields:
- name: command-letter
  kind: identifier
  location: values named 'a', 'b', 'c', ... up to ~26
  type: REG_SZ
  note: each lettered value holds one command entered at Win+R followed by '\1' (literal) as list terminator
- name: command-text
  kind: command
  location: value data
  encoding: UTF-16LE ending with '\\1'
  note: raw command string as typed (cmd.exe /c powershell ..., \\\\server\\share, http://..., etc.)
  references-data:
  - concept: ExecutablePath
    role: ranProcess
- name: MRUList
  kind: order
  location: MRUList value
  type: REG_SZ
  note: string ordering of letters indicating most-recent-first order (e.g. 'badc' means b was most-recent)
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: updated on every Run-dialog submission (new or reused)
observations:
- proposition: EXECUTED_USER_INTENT
  ceiling: C3
  note: Deliberate Win+R submission — strongest user-intent signal for ad-hoc execution (distinct from shortcut double-click or Run-Keys autorun).
  qualifier-map:
    actor.user: NTUSER.DAT owner
    object.command: field:command-text
    time.last: field:key-last-write (approximate — for the most-recent only)
anti-forensic:
  write-privilege: user
  known-cleaners:
  - tool: CCleaner
    typically-removes: full
  - tool: BleachBit
    typically-removes: full
  - tool: manual reg delete
    typically-removes: surgical
provenance: []
exit-node:
  is-terminus: false
  terminates:
    - EXECUTED_USER_INTENT
  sources:
    - cybertriage-2026-how-to-investigate-runmru
    - itm-dt127-runmru-userassist-absence
    - splunk-2026-runmru-registry-deletion-detection
  reasoning: >-
    RunMRU is the unique terminus for user-typed command-box execution. No downstream artifact captures the literal user-typed command-line string — UserAssist sees the resolved binary, Prefetch sees the EXE that ran, Security-4688 sees the process creation, but only RunMRU preserves what the user actually typed into Win+R. Distinctness: RunMRU differs from RecentDocs (file-open, not command) and from cmd-history / PSReadline (shell-prompt, different substrate). Absence-as-evidence: a populated RunMRU on a system with otherwise-cleaned history reveals selective cleanup; an empty RunMRU on a system with UserAssist launches from non-Explorer sources suggests deliberate RunMRU-only clearing.
  implications: >-
    Strongest single-artifact user-intent signal for ad-hoc command execution. Defensible citation when attribution requires distinguishing 'user deliberately typed this command' from 'program was launched somehow.' Pair with UserAssist for Win+R→GUI-launch corroboration; pair with Security-4688 for typed-command→actual-process-creation proof chain.
  preconditions: "NTUSER hive accessible; transaction logs replayed; user did not clear via Explorer's Run-dialog 'Clear history' toggle or reg delete"
  identifier-terminals-referenced:
    - UserSID
    - ExecutablePath
provenance: [libyal-libregf, regripper-plugins]
---

# RunMRU

## Forensic value
Every Win+R ("Run") submission is captured here. This is among the cleanest user-intent artifacts — the user *typed* a command. Distinct from:

- **Run-Keys** persistence (autorun programs, not user actions)
- **RecentDocs** (file-open history, not command execution)
- **cmd-history / PSReadline-history** (shell prompt, separate substrate)

Captures commands, UNC paths (`\\srv\share`), URLs (pasted into Run → opens in default browser), binaries (`cmd`, `powershell`, `mstsc`), and anything else Run accepts. The `\\1` trailing terminator is how the value distinguishes "raw command" from other REG_SZ usage.

## Per-letter rotation
Values are named `a` through `z` (single lowercase letter), with `MRUList` defining the order. Max ~26 entries; oldest falls off. Timestamp is per-key — only useful for dating the *most-recent* addition.

## Forensic cross-references
- **UserAssist** often has a corresponding entry if the typed command launched a tracked binary
- **Prefetch** catches execution of the invoked binary if it was an EXE
- **Security-4688** (if process auditing enabled) records the actual process creation triggered

## Anti-forensic
"Clear history" in Explorer's dialog options wipes RunMRU. A populated RunMRU on a system with otherwise-cleaned history is suspicious by absence-of-cleanup.

## Practice hint
Type something obvious into Run (`calc` then `cmd`), then:
```
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
```
Observe that `MRUList` moves most-recent to the front of the letter string.
