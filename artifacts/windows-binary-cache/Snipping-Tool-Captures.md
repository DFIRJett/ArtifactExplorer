---
name: Snipping-Tool-Captures
title-description: "Windows 11 Snipping Tool screenshots and screen recordings — Snips / Recordings / saved output"
aliases:
- Snipping Tool
- Snip & Sketch
- ScreenSketch captures
- Screen recordings
link: file
link-secondary: user
tags:
- per-user
- screen-capture
- exfil-channel
- itm:IF
volatility: persistent
interaction-required: user-action
substrate: windows-binary-cache
substrate-instance: Snipping-Tool-Captures
platform:
  windows:
    min: '10'
    max: '11'
    note: "Win10 Snip & Sketch and Win11 Snipping Tool share the ScreenSketch UWP package. Win11 added the screen-recording feature (2022 feature update) — .mp4 recordings land in a different subdirectory than screenshots."
location:
  path-tempstate-snips: "%LOCALAPPDATA%\\Packages\\Microsoft.ScreenSketch_8wekyb3d8bbwe\\TempState\\Snips\\"
  path-tempstate-recordings: "%LOCALAPPDATA%\\Packages\\Microsoft.ScreenSketch_8wekyb3d8bbwe\\TempState\\Recordings\\"
  path-saved-screenshots: "%USERPROFILE%\\Pictures\\Screenshots\\"
  path-saved-recordings: "%USERPROFILE%\\Videos\\Screen Recordings\\"
  path-settings: "%LOCALAPPDATA%\\Packages\\Microsoft.ScreenSketch_8wekyb3d8bbwe\\Settings\\settings.dat"
  addressing: file-path
  note: "Two-layer persistence: (1) TempState holds the most recent capture pending user save/discard; (2) user-saved captures land in Pictures/Videos. The AutoSaveCaptures flag in settings.dat controls whether TempState auto-persists — when enabled, EVERY snip gets saved automatically, which is a forensic gold mine."
fields:
- name: screenshot-png
  kind: content
  location: "TempState\\Snips\\*.png and Pictures\\Screenshots\\*.png"
  encoding: png
  note: "Full-resolution PNG of each screenshot. For exfil cases the pixels ARE the evidence — what the user captured from the sensitive application / document. EXIF-like metadata is minimal (no device info) but mtime = capture time."
- name: recording-mp4
  kind: content
  location: "TempState\\Recordings\\*.mp4 and Videos\\Screen Recordings\\*.mp4"
  encoding: mp4 (h.264)
  note: "Full-resolution screen recordings (Win11 Snipping Tool 2022+). Include the entire screen or a cropped region of the screen over time — an insider screen-recording a CRM browsing session to exfil customer records captures everything to one file."
- name: capture-mtime
  kind: timestamp
  location: .png / .mp4 file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "Capture creation time. Pair with logon session and foreground-application focus (via ActivitiesCache or UserAssist) to identify WHICH application the user captured from."
- name: autosave-captures
  kind: flags
  location: "Settings\\settings.dat — AutoSaveCaptures value"
  type: registry-hive (settings.dat is an internal reg hive)
  note: "Boolean — when True, every snip auto-saves to Pictures\\Screenshots without user action. When False, only user-confirmed saves persist. AutoSaveCaptures=False plus populated Pictures\\Screenshots means EVERY screenshot was deliberately saved = higher intentionality."
- name: saved-path
  kind: path
  location: "Pictures\\Screenshots\\<descriptive-name>.png"
  references-data:
  - concept: UserSID
    role: profileOwner
  note: "User-chosen filename when 'Save As' was used. Filename semantics (e.g., 'customer_list.png', 'password_prompt.png') frequently reveal intent directly."
- name: tempstate-cleanup
  kind: timestamp
  location: "TempState\\Snips\\ directory mtime"
  encoding: filetime-le
  note: "TempState auto-prunes as new snips are taken. Directory mtime reflects the most recent prune. Historical captures are NOT retained unless AutoSaveCaptures is on or the user manually saved."
observations:
- proposition: CAPTURED_SCREEN
  ceiling: C4
  note: 'Screen-capture tooling is one of the most under-monitored exfil
    vectors on enterprise endpoints. DLP solutions that watch clipboard
    and USB transfers are blind to a screenshot tool that reads pixels
    from a foreground window and writes a PNG to disk. The PNG is then
    trivially uploaded, emailed, or photographed from the screen. The
    Snipping Tool / ScreenSketch package persists capture history in
    two layers (TempState auto + Pictures saved), giving DFIR a direct
    evidentiary trail of what the user captured and when. For any
    insider-threat exfil case, Snipping Tool captures should be
    acquired alongside browser history and email attachments.'
  qualifier-map:
    object.content: field:screenshot-png
    time.start: field:capture-mtime
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: Settings → Apps → Snipping Tool → Advanced options → Reset
    typically-removes: TempState contents + settings.dat (Pictures\Screenshots unaffected)
  - tool: manual delete of Pictures\Screenshots\*.png
    typically-removes: saved captures (but mtime-based Volume Shadow Copy recovery may work)
  survival-signals:
  - Pictures\Screenshots\ contains PNGs with mtimes in incident window and no legitimate business justification = candidate exfil captures
  - TempState\Snips\ non-empty on a host where user claims "I never use the Snipping Tool" = direct contradiction
  - Videos\Screen Recordings\*.mp4 on a workstation with no documented training/recording use case = strong signal (insider recording sensitive browsing sessions)
  - AutoSaveCaptures=True in settings.dat combined with recent TempState activity = every captured screen auto-persisted; acquire Pictures\Screenshots in full
provenance:
  - matrix-nd-dt061-detect-text-authored-in
  - aboutdfir-com-2023-windows-11-snipping-tool-foren
---

# Snipping Tool captures (Win11)

## Forensic value
The Windows 11 Snipping Tool / Snip & Sketch (UWP package `Microsoft.ScreenSketch_8wekyb3d8bbwe`) persists screen captures in up to four locations:

1. **`%LOCALAPPDATA%\Packages\Microsoft.ScreenSketch_*\TempState\Snips\`** — most recent captures held pending save/discard
2. **`%LOCALAPPDATA%\Packages\Microsoft.ScreenSketch_*\TempState\Recordings\`** — most recent screen recordings
3. **`%USERPROFILE%\Pictures\Screenshots\`** — user-saved screenshots
4. **`%USERPROFILE%\Videos\Screen Recordings\`** — user-saved screen recordings

The `AutoSaveCaptures` boolean in `settings.dat` controls whether every snip is auto-persisted to Pictures\Screenshots without user confirmation. When enabled, every capture survives permanently.

## Why this matters for insider-threat work
Screen capture is a DLP blind spot. Endpoint DLP watches USB, network uploads, clipboard, and email attachments. It does not typically inspect pixel buffers sent from GDI to a UWP app that then writes a PNG to user-writable AppData. An insider who cannot copy files off the box via those monitored channels can:

1. Open the sensitive application (ERP, PII viewer, source-code editor)
2. Take snips / record screen
3. Save PNGs / MP4s to local disk
4. Upload via personal cloud, email, phone photograph, or transfer later

The PNGs and MP4s persist locally and become the forensic smoking gun.

## Concept references
- None direct — pure file-content artifact with timestamp and path evidence.

## Triage
```powershell
# TempState (most recent unsaved captures)
Get-ChildItem "C:\Users\*\AppData\Local\Packages\Microsoft.ScreenSketch_*\TempState\Snips\" -Force -ErrorAction SilentlyContinue
Get-ChildItem "C:\Users\*\AppData\Local\Packages\Microsoft.ScreenSketch_*\TempState\Recordings\" -Force -ErrorAction SilentlyContinue

# Saved captures
Get-ChildItem "C:\Users\*\Pictures\Screenshots\" -Filter *.png
Get-ChildItem "C:\Users\*\Videos\Screen Recordings\" -Filter *.mp4

# AutoSaveCaptures flag — the settings.dat is a registry hive; load offline
reg load HKLM\SSK "C:\Users\<user>\AppData\Local\Packages\Microsoft.ScreenSketch_*\Settings\settings.dat"
reg query "HKLM\SSK\LocalState" /v AutoSaveCaptures
reg unload HKLM\SSK
```

## Acquisition notes
- Both .png and .mp4 files tend to be large — plan acquisition storage
- EXIF is absent; mtime is the only reliable capture timestamp
- settings.dat is a registry-hive binary file; must be loaded (`reg load`) to inspect values

## Practice hint
On Windows 11: press `Win+Shift+S`, capture any region of the screen, click the Snipping Tool notification to confirm. Check `Pictures\Screenshots\` for the saved PNG. Record a short screen-recording via `Win+G` or Snipping Tool's Record feature — observe `Videos\Screen Recordings\*.mp4`. Inspect the ScreenSketch `TempState\Snips\` folder in parallel — you'll see the transient PNG that the user *could have* discarded but in fact persisted until the next capture replaces it.
