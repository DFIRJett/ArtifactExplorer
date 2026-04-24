---
name: UserAssist
aliases:
- UserAssist
- GUI-launch history
- Explorer UserAssist
link: application
tags:
- timestamp-carrying
- tamper-easy
- per-user
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: XP
    max: '11'
  windows-server:
    min: '2003'
    max: '2022'
location:
  hive: NTUSER.DAT
  path: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<category-GUID>\Count
  addressing: hive+key-path
  categories:
    '{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}': Active Desktop / Executables launched from Explorer
    '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}': Shortcut (.lnk) files launched
    '{5E6AB780-7743-11CF-A12B-00AA004AE837}': legacy — IE toolbars/shell-new objects
fields:
- name: category-guid
  kind: identifier
  location: subkey name under UserAssist
  encoding: guid-string
  note: identifies what class of launch this Count subkey tracks
- name: rot13-value-name
  kind: path
  location: value name under Count subkey
  encoding: ROT13-encoded ASCII path or known constant (UEME_CTLSESSION, UEME_CTLCUACount:ctor, UEME_RUNPATH, UEME_RUNPIDL,
    etc.)
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: ROT13 is trivially reversible — parsers do it automatically; path references an exe or .lnk target depending on category
- name: run-count
  kind: counter
  location: value data offset 0x04
  encoding: uint32-le (Win7+ format)
  note: number of times the launch was observed — on Win7+ starts from 0 and increments; some value-name families never increment
- name: focus-count
  kind: counter
  location: value data offset 0x08 (Win7+)
  encoding: uint32-le
  note: number of distinct focus sessions with the launched window
- name: focus-time-ms
  kind: counter
  location: value data offset 0x0C (Win7+)
  encoding: uint32-le
  note: cumulative milliseconds the window had focus — an approximate 'dwell time' signal
- name: last-run-time
  kind: timestamp
  location: value data offset 0x3C (Win7+)
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: updated on each launch observed in this user's session
- name: user-scope-sid
  kind: identifier
  location: derived from NTUSER.DAT owner via ProfileList
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: profileOwner
- name: value-data-version
  kind: enum
  location: value data size distinguishes format versions
  encoding: 'size-based: XP=16 bytes (simple); Win7+=72 bytes (rich)'
  note: parsers must branch on the Windows version to decode correctly
observations:
- proposition: EXECUTED
  ceiling: C3
  note: 'Per-user GUI-launched execution. Captures programs the user ran via

    Explorer double-click, Start menu, or taskbar — does NOT capture

    programs run from cmd.exe, services, scheduled tasks, or malware that

    bypasses Explorer.

    '
  qualifier-map:
    process.image-or-lnk: field:rot13-value-name
    actor.user: field:user-scope-sid
    frequency.count: field:run-count
    frequency.focus-time: field:focus-time-ms
    time.start: field:last-run-time
    time.end: field:last-run-time
  preconditions:
  - NTUSER hive is the target user's (ProfileList SID matches)
  - Transaction logs replayed before parsing
anti-forensic:
  write-privilege: user
  integrity-mechanism: none, beyond ROT13 'obfuscation' that does not impede tampering
  known-cleaners:
  - tool: CCleaner
    typically-removes: partial
    note: depending on settings, may target UserAssist or miss it
  - tool: Autoruns "Run keys" UI
    typically-removes: false
  - tool: manual reg-delete
    typically-removes: surgical
  survival-signals:
  - UserAssist present with rich execution history + Prefetch directory empty = selective Prefetch cleanup (attacker knew
    Prefetch is the obvious target, missed UserAssist)
  - run-count anomalies (e.g., count = 0 for a recently-listed entry) = value was reset but not deleted; common sign of naive
    cleanup that just zeroed the counter
provenance: []
exit-node:
  is-terminus: false
  terminates:
    - EXECUTED
  sources:
    - securelist-2024-userassist-ir-value
    - magnet-userassist-artifact-profile
    - matrix-dt127-userassist
    - libyal-winreg-kb-userassist
  reasoning: >-
    UserAssist is the per-user NTUSER-scoped terminus for GUI-initiated execution. No downstream artifact provides a richer user-scoped binding of Explorer-launched programs — run-count, focus-count, cumulative focus-time, and last-run FILETIME together give a session-level record no other artifact offers for the GUI launch path. Co-terminus with BAM (BAM covers non-GUI user-scope execution like CreateProcessAsUser; UserAssist covers the GUI launch surface). Scope deliberately narrow: EXECUTED claim is bounded to Explorer double-click / Start menu / taskbar / .lnk invocation and does NOT cover cmd-launched, service-launched, or scheduled-task-launched execution.
  implications: >-
    Defensible citation for user-attributed GUI execution. When Prefetch is cleared or machine-wide ambiguity makes Prefetch hard to attribute, UserAssist still anchors user→program→time. Especially valuable for insider-threat and user-intent analysis — the run-count and focus-time fields directly surface 'deliberate and repeated use' signals that no other per-user artifact provides with comparable resolution.
  preconditions: "NTUSER hive accessible; transaction logs replayed; parser handles both XP 16-byte and Win7+ 72-byte formats"
  identifier-terminals-referenced:
    - UserSID
    - ExecutablePath
provenance: [libyal-libregf, regripper-plugins]
---

# UserAssist

## Forensic value
Per-user GUI-launch history. Explorer tracks every program the user starts via double-click, Start menu, or taskbar click, along with run count, focus time, and last-run timestamp. One of the two strongest *user-attributed* execution artifacts on Windows (the other is BAM).

Critically: UserAssist is **per-user**, living in NTUSER.DAT. Each user's GUI launches are segregated in their own hive. This makes it the canonical "which user ran this" artifact for GUI-launched programs, whereas Prefetch is machine-wide and requires session-chain inference to attribute to a user.

## Two concept references
- ExecutablePath — from the ROT13-decoded value name
- UserSID — from the NTUSER owner via ProfileList

## Known quirks
- **ROT13 is not obfuscation.** It's a historical artifact from early Windows shell development. Trivially reversible; every parser does it automatically. Don't let ROT13 fool casual viewers into thinking values are "encrypted."
- **GUI-only scope.** Programs launched from `cmd.exe`, `powershell.exe`, services, scheduled tasks, or anywhere outside Explorer's launching path do NOT appear. Malware that spawns via COM or service manipulation is invisible here.
- **Three categories (GUIDs), two matter in practice.** `{CEBFF5CD-...}` tracks executables; `{F4E57C4B-...}` tracks .lnk shortcuts. The legacy IE one is rarely forensically interesting.
- **Several `UEME_*` reserved value names** (UEME_CTLSESSION, UEME_CTLCUACount:ctor, etc.) exist per Count subkey. These are counters for session/initialization events, not user-launched programs. Parsers strip them; don't mistake for launches.
- **Focus-time is cumulative across all runs**, not per-run. Divide by run-count for a rough per-run dwell.
- **Win7+ value format is 72 bytes.** Pre-Win7 was 16 bytes and much less informative. Parsers must branch on size.

## Anti-forensic caveats
User-editable (HKCU scope, no elevation, no native audit). Trivially clearable via registry cleaners or direct `reg delete`. Because Prefetch and BAM also capture execution evidence, UserAssist is rarely the *only* record of a launch — cross-check across the three for corroborating or disagreeing accounts.

Common naive-cleanup pattern: attacker deletes `UserAssist\{CEBFF5CD-...}\Count\<target-entry>` but leaves the Count subkey itself intact. This is surgically appropriate but leaves residual structure that LastWrite times on the Count subkey can reveal.

## Practice hint
- Launch a known program (Notepad, Calculator) from the Start menu on a clean Win10 VM. Parse UserAssist with RegRipper's `userassist` plugin. Decode the ROT13 value names.
- Run the same program several times over a minute. Observe run-count increment and focus-time-ms accumulate proportional to how long windows had focus.
- Launch a program from `cmd.exe` instead of Explorer. Confirm UserAssist does NOT record it. Cross-check Prefetch to see that the launch is captured there instead.
- Compare UserAssist entries across two user profiles on the same machine — the per-user scope is visible directly.
