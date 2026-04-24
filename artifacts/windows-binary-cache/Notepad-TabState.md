---
name: Notepad-TabState
title-description: "Windows Notepad TabState .bin — UWP Notepad's unsaved-tab persistent buffer"
aliases:
- Notepad TabState
- UWP Notepad drafts
- untitled Notepad buffer
link: file
link-secondary: application
tags:
- per-user
- unsaved-content
- insider-draft
- itm:ME
volatility: persistent
interaction-required: user-action
substrate: windows-binary-cache
substrate-instance: Notepad-TabState
platform:
  windows:
    min: '11'
    max: '11'
    note: "Modern UWP Notepad (shipped with Windows 11 and back-ported to some Win10 21H2 builds). Classic notepad.exe on Windows 10 does NOT have this feature — it used to discard unsaved text on close."
location:
  path: "%LOCALAPPDATA%\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\*.bin and *.0.bin"
  addressing: file-path
  note: "One .bin per open tab. Each tab's file stores the full text buffer plus metadata (tab GUID, was-saved flag, source file path if any). Survives Notepad close, system restart, even crash — UWP Notepad is designed to recover every tab on next launch, and that design is the forensic gift."
fields:
- name: buffer-content
  kind: content
  location: "TabState\\<guid>.bin — text buffer at variable offset"
  encoding: utf-16le (with length prefix and size markers)
  note: "The actual typed text. For an unsaved tab, THIS file is the only place on the system where the content exists — the user never pressed Ctrl+S, so the 'document' has no file on disk other than this hidden cache."
- name: source-path
  kind: path
  location: "TabState\\<guid>.bin — optional saved-document path field"
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: "If the tab was opened from a saved file, this field records that path. Absence of a path = pure untitled buffer (most common forensic case: the user was drafting something they never intended to persist)."
- name: was-modified
  kind: flags
  location: "TabState\\<guid>.bin — dirty-bit byte"
  type: uint8
  note: "1 = tab has unsaved modifications (the content has been edited since last save or never saved). 0 = in-sync with source file. Dirty=1 on a tab with no source-path = untitled draft = highest-value insider-draft evidence."
- name: tab-guid
  kind: identifier
  location: "filename <guid>.bin and embedded GUID field"
  encoding: guid-string
  note: "Unique identifier per tab. Joins the .bin file to the companion .<n>.bin undo-history file if present."
- name: file-mtime
  kind: timestamp
  location: TabState\<guid>.bin $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "Updates whenever Notepad writes the buffer to disk (auto-save on lose-focus / every few keystrokes). Gives a 'last-edit' pivot that the user didn't know was being recorded."
- name: undo-history
  kind: content
  location: "TabState\\<guid>.<n>.bin (companion files)"
  encoding: binary delta records
  note: "Undo-stack per tab. Recovers intermediate states — earlier versions of the typed text before the user deleted parts. For insider cases where a user typed then deleted sensitive content, these files may still hold the deleted characters."
observations:
- proposition: DRAFTED
  ceiling: C3
  note: 'A surprisingly strong content-recovery artifact on Windows 11.
    The modern UWP Notepad auto-persists every tab — saved or not — so
    a user who types sensitive content (a password, a resignation note,
    exfiltration instructions, customer PII) and closes the window
    without saving leaves the full text in TabState. Undo-history
    companion files further enable recovery of deleted intermediate
    text. Standard disk forensics misses this because analysts look at
    Documents / Desktop / OneDrive, not the UWP package cache.'
  qualifier-map:
    object.content: field:buffer-content
    object.path: field:source-path
    time.end: field:file-mtime
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: Settings → Apps → Notepad → Advanced options → Reset
    typically-removes: everything in LocalState and TempState (full wipe of all tabs including undo history)
  - tool: delete LocalState\TabState\ directory while Notepad is closed
    typically-removes: all tab buffers (Notepad recreates empty folder on next launch)
  survival-signals:
  - TabState\*.bin files present on a host where Notepad appears in UserAssist but no recent Documents/Desktop .txt files = user drafts that never became saved files
  - Companion <guid>.<n>.bin undo files with large delta records = user typed and then deleted substantial content — inspect for sensitive phrases
  - TabState mtime within incident window and buffer-content contains keywords (passwords, hostnames, command-line snippets) = drafting of attack commands or exfil notes
provenance:
  - ms-windows-notepad-restore-session-tab
  - hammond-2022-notepad-tabstate-bin-files-uns
  - matrix-nd-dt061-detect-text-authored-in
---

# Notepad TabState (UWP Notepad unsaved tabs)

## Forensic value
The modern Windows 11 Notepad (a UWP app, not the classic notepad.exe) auto-persists every open tab to `%LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_*\LocalState\TabState\` as a `.bin` file. Tabs that were never saved to disk still leave their full text buffer here. This turns a historically disposable workspace into a first-class forensic artifact:

- Drafts the user never intended to persist (passwords, notes, exfil commands)
- Content the user typed and then deleted (recoverable from undo-history companion files)
- Tabs still open at shutdown/crash time

Because the file lives under the Packages AppData tree (not `%USERPROFILE%\Documents`), users attempting to cover tracks rarely clean it.

## Concept reference
- None direct — path + content artifact. If the tab has a `source-path`, it joins back to the saved file via path match.

## Parsing
Community reversing (notably John Hammond's work) identified the binary layout:
- Header with tab-GUID
- Variable-length UTF-16LE text buffer with length prefix
- Dirty/saved flag byte
- Optional source-file path (absent for untitled tabs)

Tools:
- `NotepadTabStateReader` (open-source Python) — dumps buffer + metadata
- Hex-editor fallback: grep for `FF FE` BOM then decode UTF-16LE

## Triage
```powershell
# List every user's TabState .bin files
Get-ChildItem "C:\Users\*\AppData\Local\Packages\Microsoft.WindowsNotepad_*\LocalState\TabState\*.bin" -Force

# Copy offline while Notepad is NOT running (file may be locked)
Copy-Item "C:\Users\<user>\AppData\Local\Packages\Microsoft.WindowsNotepad_*\LocalState\TabState\*" -Destination .\evidence\notepad-tabstate\ -Recurse
```

## Insider-threat usage pattern
1. User types sensitive content (password, customer list, resignation draft) in a new Notepad tab.
2. User closes Notepad without saving — assumes content is discarded.
3. Notepad persisted the tab to `TabState\<guid>.bin` automatically.
4. Months later, DFIR recovers the tab during user-profile triage.

This exact workflow has surfaced in recent insider exfil cases where the user staged credential lists in Notepad between reading from a password manager and pasting into an email.

## Practice hint
On Windows 11: open Notepad, type "sensitive draft text", close the Notepad window without saving. Navigate in Explorer (with hidden items shown) to `%LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_*\LocalState\TabState\`. Open the newest .bin in a hex viewer — the UTF-16LE text of what you typed is visible after the header. Reopen Notepad and observe the tab auto-restored. That's the forensic property.
