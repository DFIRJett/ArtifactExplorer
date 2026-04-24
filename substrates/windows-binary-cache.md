---
name: windows-binary-cache
kind: binary-structured-file
substrate-class: Application Cache
aliases: [Windows application binary cache, per-app AppData cache, binary state blob]

format:
  storage: "application-defined binary blob(s); each app writes its own schema"
  rotation: "per-app — some apps rotate individual files, others overwrite in place, some never evict"
  authoritative-spec: "no single spec — each cache is defined by the writing application's private implementation"

persistence:
  root:
    modern-uwp: "%LOCALAPPDATA%\\Packages\\<PFN>\\LocalState\\"
    modern-uwp-tempstate: "%LOCALAPPDATA%\\Packages\\<PFN>\\TempState\\"
    win32-localappdata: "%LOCALAPPDATA%\\<Vendor>\\<App>\\"
    system-appcompat: "%WINDIR%\\AppCompat\\Programs\\ (RecentFileCache.bcf, pre-Amcache)"
    system-print-spool: "%WINDIR%\\System32\\spool\\PRINTERS\\ (SPL/SHD pairs)"
    per-user: yes (or system-scope for compat/spool cases)
  locked-on-live-system: "partial — locked while the originating application has files open; freed on app exit"
  acquisition:
    methods:
      - direct file copy when the owning app is closed
      - VSC-based copy for locked files
      - offline image
  retention:
    policy: "application-specific — commonly LRU with size-cap (RDP bitmap cache), or keep-until-save (Notepad TabState), or keep-until-user-delete (screenshot directories)"

parsers:
  - name: application-specific parsers (BMC Viewer for RDP bitmap cache; NotepadTabStateReader; etc.)
    strengths: [schema-aware extraction of embedded content]
  - name: binwalk + custom reversing
    strengths: [first-look at undocumented blobs]
  - name: hex-editor plus magic-byte search
    strengths: [locating embedded JPEG/PNG/BMP inside the blob]

forensic-relevance:
  - content-recovery: |
      These caches frequently embed user-content (screenshot pixels, typed text,
      remote-session bitmap tiles). For insider-threat and exfil cases the cache
      file itself is the evidence — you don't need the source document, you
      need the cache slice.
  - post-cleanup-survival: |
      Cache files sit outside the source-document's folder and outside the
      Recycle Bin. Users wiping "their documents" rarely clean AppData caches.
      A cache that persists after source deletion is the strongest tier of
      evidence-of-prior-existence.
  - uwp-sandboxing: |
      UWP apps store state under %LOCALAPPDATA%\\Packages\\<PFN>\\ — this is
      per-user, per-app, and outlives the app's process. The TempState
      subfolder is frequently non-empty with in-progress / unsaved user work.

integrity:
  signing: none
  tamper-vectors:
    - direct file edit while app is closed (no checksum)
    - deletion of the whole folder (application may recreate empty on next run)
    - UWP "Reset" option in Settings (wipes LocalState + TempState)
  audit-trail: "none — caches have no integrity guard"

known-artifacts:
  authored: []
  unwritten:
    - name: Notepad-TabState
      location: "%LOCALAPPDATA%\\Packages\\Microsoft.WindowsNotepad_*\\LocalState\\TabState\\*.bin"
      value: unsaved Notepad tab contents — drafts, credentials, notes
    - name: RDP-Bitmap-Cache
      location: "%LOCALAPPDATA%\\Microsoft\\Terminal Server Client\\Cache\\*.bmc + Cache0000.bin"
      value: reconstructable screenshots of RDP sessions (tile-based)
    - name: Snipping-Tool-Captures
      location: "%LOCALAPPDATA%\\Packages\\Microsoft.ScreenSketch_*\\TempState\\Snips + \\Recordings + Pictures\\Screenshots + Videos\\Screen Recordings"
      value: screenshot/screen-recording exfil of sensitive data
provenance:
  - libyal-libfwnt-job-file-format-libwrc-reverse
  - ms-background-intelligent-transfer-ser
---

# Windows Binary Cache (per-application)

## Forensic value
Catch-all container for application-private binary state blobs living in AppData. The shared forensic properties are:

- **Per-user, persistent across reboots** (sit in AppData / Packages)
- **Unsaved / ephemeral content that never hit the "official" document location** — Notepad drafts, RDP bitmap tiles, in-progress Snipping Tool captures
- **Commonly missed by users cleaning up** — caches live outside My Documents, Recycle Bin, browser history panes

Together these properties make binary caches a tier-3 insider-threat goldmine: users copy, screenshot, or remote-view sensitive data; the raw pixels or typed text land in a cache they don't know exists, and the cache outlasts deletion of the source file.

## Acquisition checklist
- Identify the target application's PFN (Package Family Name) for UWP apps
- Acquire both `LocalState\` and `TempState\` directories
- For Win32 apps, acquire `%LOCALAPPDATA%\<Vendor>\<App>\` recursively
- Note the directory mtimes — they bracket the active-use window

## Schema-reverse-engineering stance
Most caches in this class are undocumented by Microsoft. Community parsers exist for high-value ones (RDP bitmap cache, Notepad TabState). When no parser exists, binwalk + hex editor plus magic-byte hunting (JPEG `FFD8FF`, PNG `89504E47`, PE `4D5A`) recovers embedded content even without full schema knowledge.
