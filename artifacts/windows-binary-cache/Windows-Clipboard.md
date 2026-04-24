---
name: Windows-Clipboard
title-description: "Windows Clipboard on-disk storage — cloud clipboard sync + pinned clipboard history"
aliases:
- Cloud Clipboard
- Pinned Clipboard
- Clipboard History
link: user
link-secondary: application
tags:
- per-user
- clipboard-content
- exfil-staging
- itm:IF
volatility: persistent
interaction-required: user-action
substrate: windows-binary-cache
substrate-instance: Windows-Clipboard
platform:
  windows:
    min: '10'
    max: '11'
    note: "Windows 10 1809+ introduced cloud-clipboard and persistent clipboard history (Win+V). Prior Windows versions kept clipboard purely in memory. Registry feature flag at HKCU\\Software\\Microsoft\\Clipboard\\EnableClipboardHistory controls persistence."
  windows-server: N/A (client-focused feature)
location:
  path-pinned: "%LOCALAPPDATA%\\Microsoft\\Windows\\Clipboard\\Pinned\\{GUID}\\{GUID}\\ (metadata.json + base64-named files)"
  registry-enable: "HKCU\\Software\\Microsoft\\Clipboard"
  companion-cloud: "ActivitiesCache.db ClipboardPayload column (already covered as separate artifact)"
  addressing: file-path
  note: "Windows 10/11 Clipboard History persists USER-PINNED clipboard entries to disk under LOCALAPPDATA\\Microsoft\\Windows\\Clipboard\\Pinned\\. Unpinned history lives only in memory. Directory structure: one {GUID} subdirectory per pinned item, containing a metadata.json file describing the content type (Text, Image, HTML, RTF, FileDrop) plus base64-named files holding the actual clipboard content. Cloud-Clipboard (cross-device sync) data lives separately in ActivitiesCache.db's ClipboardPayload column. For insider-threat investigations, Pinned\\ is a direct record of what the user deliberately saved to their clipboard — often reveals staged credentials, customer lists, URLs, file paths relevant to exfil."
fields:
- name: pinned-text
  kind: content
  location: "Pinned\\{GUID}\\{GUID}\\<base64>"
  encoding: UTF-16LE / UTF-8 (text filename decoded from base64)
  note: "Pinned text clipboard entry. File name is base64-encoded of the content-descriptor (e.g., 'VGV4dA==' = 'Text'). File content = the actual pinned text in UTF-16LE. Attacker / insider staging credentials, customer records, snippets of sensitive docs — all visible in plain text here."
- name: pinned-image
  kind: content
  location: "Pinned\\{GUID}\\{GUID}\\<base64-image-files>"
  encoding: PNG / BMP bytes
  note: "Pinned image clipboard entry (screenshot copied via PrtScr, image dragged from browser, etc.). Raw image bytes in native format. Recoverable as direct image evidence."
- name: pinned-html
  kind: content
  location: "Pinned\\{GUID}\\{GUID}\\<base64-html>"
  encoding: HTML
  note: "HTML clipboard entry — content copied from web pages / emails. Useful for reconstructing content source URLs + formatting."
- name: pinned-filedrop
  kind: content
  location: "Pinned\\{GUID}\\{GUID}\\<base64-filedrop>"
  encoding: path list (UTF-16LE CRLF-separated)
  references-data:
  - concept: MFTEntryReference
    role: targetFile
  note: "FileDrop format — when the user copied FILES (not file contents) to clipboard (e.g., Ctrl+C on selected files in Explorer). List of full paths. Reveals which files the user staged in clipboard for subsequent paste."
- name: pinned-metadata
  kind: content
  location: "Pinned\\{GUID}\\{GUID}\\metadata.json"
  encoding: JSON
  note: "JSON document listing the content types stored in the containing directory, timestamp of the pin, and optional source-app context. Root for discovery of what's in the directory."
- name: pinned-timestamp
  kind: timestamp
  location: "metadata.json — timestamp field OR directory creation mtime"
  encoding: ISO-8601 or filetime
  clock: system
  resolution: 1s
  note: "When the user pinned the entry. Brackets the staging timeline — combined with incident window, identifies clipboard staging for exfil."
- name: enable-clipboard-history
  kind: flags
  location: "HKCU\\Software\\Microsoft\\Clipboard\\EnableClipboardHistory value"
  type: REG_DWORD
  note: "1 = clipboard history enabled (Win+V works; Pinned survives); 0 = disabled (no persistent clipboard). Users deliberately enabling this feature on enterprise-baseline-disabled machines = worth correlating with staging activity."
- name: enable-cloud-clipboard
  kind: flags
  location: "HKCU\\Software\\Microsoft\\Clipboard\\EnableCloudClipboard value"
  type: REG_DWORD
  note: "1 = cross-device clipboard sync enabled (content syncs to Microsoft account). Companion ActivitiesCache.db ClipboardPayload column captures synced content. Attackers / insiders who enable this can exfil via phone / other device without needing to touch the host's network stack."
observations:
- proposition: HAD_CONTENT
  ceiling: C4
  note: 'Windows Clipboard on-disk storage captures content the user
    EXPLICITLY saved for reuse — a direct window into staging
    behavior. Text, images, file-path lists. For insider-threat
    investigations: pinned clipboard entries with sensitive content
    in the incident window = direct staging evidence. For exfil
    cases where Cloud Clipboard was enabled, cross-device sync
    means the content reached the user''s phone / other device and
    is exfiltrated without host-network involvement — ActivitiesCache.
    db ClipboardPayload corroborates. Routinely overlooked because
    clipboard is often assumed memory-only.'
  qualifier-map:
    object.content: field:pinned-text
    time.start: field:pinned-timestamp
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: "Win+V → Clear all"
    typically-removes: clipboard history (pinned + unpinned)
  - tool: "Settings → System → Clipboard → Clear clipboard data"
    typically-removes: same
  - tool: delete Pinned\ directory
    typically-removes: pinned entries file-level
  survival-signals:
  - Pinned\ directory populated on incident-window-corresponding mtimes = user-staged clipboard entries
  - EnableCloudClipboard=1 combined with recent ActivitiesCache.db ClipboardPayload activity = cloud-exfil vector
  - metadata.json timestamps matching sensitive-file access times in UsnJrnl = copied-for-exfil pattern
provenance:
  - ms-windows-clipboard-history-feature-r
---

# Windows Clipboard (Pinned + Cloud)

## Forensic value
Windows 10 1809+ Clipboard History persists user-pinned clipboard entries to disk at:

`%LOCALAPPDATA%\Microsoft\Windows\Clipboard\Pinned\{GUID}\{GUID}\`

Directory structure per pinned item:
- `metadata.json` — content-type descriptor + timestamp
- Base64-named files — actual content (text / image / HTML / filedrop)

Filename base64-decodes to the content-type label (e.g., `VGV4dA==` → `Text`, `SFRNTA==` → `HTML`).

Companion Cloud Clipboard content lives in `ActivitiesCache.db` (separate artifact) under the `ClipboardPayload` column.

## Why clipboard persistence matters
- **Insider threat**: user copies sensitive text (passwords, customer lists, internal URLs), pins the entry, pastes later to email / chat / another device → pin persists
- **Cloud clipboard exfil**: text copied on host syncs to user's phone / tablet via MS account → exfil happens without host network involvement
- **File staging**: FileDrop entries reveal file paths staged for subsequent paste
- **Screenshot evidence**: pinned image entries preserve screenshots without using Snipping Tool

## Concept reference
- None direct — content artifact.

## Triage
```powershell
Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Windows\Clipboard\Pinned" -Recurse -ErrorAction SilentlyContinue

# Inspect metadata
Get-Content "C:\Users\<user>\AppData\Local\Microsoft\Windows\Clipboard\Pinned\{GUID}\{GUID}\metadata.json"

# Decode file content (UTF-16LE text example)
Get-Content "<path>\VGV4dA==" -Encoding Unicode
```

## Cross-reference
- **ActivitiesCache** — ClipboardPayload column for cloud-sync content
- **Registry**: `HKCU\Software\Microsoft\Clipboard` (EnableClipboardHistory, EnableCloudClipboard)
- **UsnJrnl** — Pinned directory file-creation events
- **Sysmon-11** — file-creation events for Pinned content

## Practice hint
On Windows 11: copy text, press Win+V, pin the entry. Check `%LOCALAPPDATA%\Microsoft\Windows\Clipboard\Pinned\` — directory with base64-named content files appears. Open metadata.json to see the structure. This is exactly what DFIR parses for clipboard-staging evidence.
