---
name: Start-TrackProgs
title-description: "Explorer Advanced Start_TrackProgs flag — switches off UserAssist / RunMRU / frequent-apps tracking"
aliases:
- Start_TrackProgs
- Turn off MFU list
- Disable program tracking
link: evasion
tags:
- anti-forensics
- tamper-signal
- itm:AF
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: '10'
    max: '11'
  windows-server:
    min: '2016'
    max: '2022'
location:
  hive: NTUSER.DAT
  path: "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"
  value: Start_TrackProgs
  addressing: hive+key-path+value
  note: "Per-user flag exposed in the Settings UI as 'Show most used apps in Start' (Win10) / 'Show most used apps' (Win11). Setting it to 0 silently suppresses UserAssist writes, RunMRU additions, and Start Menu frequent-app tracking — a low-effort, GUI-discoverable anti-forensics toggle that blinds an analyst's primary user-activity pivot points."
fields:
- name: tracking-enabled
  kind: flags
  location: "Advanced\\Start_TrackProgs value"
  type: REG_DWORD
  encoding: uint32
  note: "0 = tracking off (anti-forensics state). 1 = tracking on (default on a fresh install). Default value is 1 — absence of the value also means 'on'. Presence AND value=0 is the forensic signal."
- name: key-last-write
  kind: timestamp
  location: Explorer\Advanced key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on the Advanced key reflects the moment Start_TrackProgs was toggled (or any sibling value changed). Compare with the expected timeline — toggling off immediately before the incident window is a textbook evasion sequence."
- name: companion-usertile-off
  kind: flags
  location: "Policies\\Explorer\\NoStartMenuMFUprogramsList / NoInstrumentation"
  type: REG_DWORD
  note: "Group-policy counterparts that disable MFU program list / Windows-Tracking instrumentation at the policy layer. When both Start_TrackProgs=0 AND NoInstrumentation=1 are set by the same user, it's deliberate blanket tracking suppression, not a UI slip."
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'A rare forensic artifact whose value lies in its absence — when
    Start_TrackProgs is 0, subsequent UserAssist / RunMRU / RecentDocs /
    RecentApps entries won''t appear for that user. Investigators who
    miss this flag will look at an empty UserAssist and conclude "no
    activity" when the truth is "tracking was turned off." Check this
    early in every user-activity investigation.'
  qualifier-map:
    setting.registry-path: "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Start_TrackProgs"
    time.start: field:key-last-write
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  survival-signals:
  - Start_TrackProgs=0 on a user profile whose UserAssist shows zero recent activity = deliberate suppression
  - LastWrite on Explorer\Advanced immediately before (minutes-to-hours) the suspected activity window = pre-attack evasion prep
  - Combination of Start_TrackProgs=0 + cleared event logs + Prefetch disabled = coordinated anti-forensics campaign, tier-up the incident
provenance:
  - mitre-t1562-006
  - matrix-nd-dt061-detect-text-authored-in
---

# Start_TrackProgs (MFU tracking disable flag)

## Forensic value
A single REG_DWORD per user profile controls whether Windows records MFU / program-launch telemetry. When `Start_TrackProgs = 0`:
- UserAssist stops writing new GUID-keyed session counters
- RunMRU dialog no longer accrues entries
- The Start Menu frequent-apps list freezes
- Some Shell folder MRUs stop updating

The value lives in `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`. Default value on a fresh install is 1 (or the value is absent and treated as 1). An explicitly-set 0 is the forensic finding.

**Why it's a tier-3 hunt signal**: a user who wanted to hide activity but didn't touch event logs or install anti-forensics tooling — just flipped a Settings-UI toggle — leaves this breadcrumb. It's frequently overlooked because investigators go straight to UserAssist parsing and find nothing.

## Detection logic
- Enumerate all NTUSER.DAT hives on the image
- For each, read `Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`
- Value present AND equal to 0 → flag
- Capture the `Advanced` key's LastWrite timestamp — when the suppression was toggled on

Correlate toggling time with:
- User logon sessions (Security-4624) before and after
- ShellBag / Open-SavePidl activity that continues in parallel (those aren't disabled by this flag → surviving activity window)

## Triage
```powershell
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs
# Offline from a mounted NTUSER.DAT:
RegistryExplorer.exe -f NTUSER.DAT  # navigate to Explorer\Advanced → Start_TrackProgs
```

## Practice hint
On a lab VM, open Settings → Personalization → Start → "Show most used apps" and toggle it off. In Registry Editor, observe `Start_TrackProgs` flip from absent/1 to 0. Launch a few applications, then inspect UserAssist with RegRipper — no new counter increments. Toggle back on: UserAssist resumes. This is the anti-forensics signal you're hunting for.
