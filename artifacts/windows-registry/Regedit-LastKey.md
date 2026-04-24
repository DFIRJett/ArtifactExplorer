---
name: Regedit-LastKey
title-description: "Regedit LastKey — the last registry path the user navigated to in Registry Editor (per-user intent evidence)"
aliases:
- Regedit LastKey
- Applets\\Regedit\\LastKey
- Registry Editor history
link: user
tags:
- user-intent
- anti-forensics-pivot
- itm:AF
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: NT5.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: NTUSER.DAT
  path: "Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit"
  addressing: hive+key-path
  note: "Regedit.exe (the built-in Registry Editor) persists the last-navigated key path to this per-user location every time it closes. Value LastKey holds the full registry path. Favorites subkey holds user-added favorites. A populated LastKey with a forensically-interesting destination (persistence key, Defender exclusion, LSA secret area) is direct evidence that THIS user opened Registry Editor and navigated TO that location — intent evidence rather than just configuration evidence."
fields:
- name: last-key
  kind: path
  location: "Applets\\Regedit\\LastKey value"
  type: REG_SZ
  encoding: utf-16le
  note: "Full registry path of the last key the user had selected in Registry Editor when regedit.exe closed. Format: 'Computer\\HKEY_LOCAL_MACHINE\\...full\\path'. Investigator red flags: LastKey pointing at a persistence key (Run / RunOnce / Services), a Defender-Exclusions path, an Image File Execution Options subkey, a COM CLSID subkey of interest. 'This user opened regedit and navigated here' is user-intent evidence."
- name: favorites-list
  kind: content
  location: "Applets\\Regedit\\Favorites subkey (each value = registry path)"
  type: REG_SZ
  note: "User-added Favorites (Regedit's Favorites menu). Rare to see a malicious user / attacker add Favorites — but when present, each favorite is a pinned location the user returned to repeatedly. Highly specific to individual user habit."
- name: key-last-write
  kind: timestamp
  location: Applets\\Regedit key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on the Regedit key updates when LastKey value changes — i.e., on every regedit.exe close. Gives a moment-of-registry-editor-close timestamp. Pair with Security-4688 / Sysmon-1 for the regedit.exe launch event bracketing the session."
- name: view-mode
  kind: flags
  location: "Applets\\Regedit\\View value"
  type: REG_DWORD
  note: "Regedit's view preference (expanded/collapsed pane widths, etc.). Not directly forensic but a moving value that indicates the user genuinely used regedit (a fresh View mtime aligns with fresh LastKey). Stale View with fresh LastKey = possible tamper."
observations:
- proposition: USER_INTENT
  ceiling: C3
  note: 'Regedit LastKey is a small but high-signal artifact for insider-
    threat, tamper-investigation, and attribution cases. The value
    exists SOLELY because this user interactively used Registry
    Editor — and it records the SPECIFIC registry location they
    navigated to. For a user claiming "I never touched registry
    settings," a LastKey pointing at a Defender Exclusions path or
    a Run key is direct contradiction. For investigations where
    persistence was planted manually (not programmatically), this
    artifact puts the specific user account at the specific
    registry location at the editing time.'
  qualifier-map:
    setting.registry-path: "Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit\\LastKey"
    object.path: field:last-key
    time.end: field:key-last-write
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: manual deletion of Applets\\Regedit\\LastKey value
    typically-removes: the LastKey value (leaves Regedit subkey LastWrite as residual evidence)
  - tool: regedit close from HKEY_CURRENT_USER root
    typically-removes: overwrites LastKey with a benign high-level path (rudimentary masking)
  survival-signals:
  - LastKey pointing at a persistence key / Defender Exclusions / security-setting location on a non-admin user's profile = unexpected privileged-registry browsing
  - LastKey matching a key a different artifact shows was modified within incident window = user-attributed tamper evidence
  - Fresh key-last-write on Regedit subkey + LastKey = "" (empty) = deliberate wipe attempt (rare but diagnostic)
provenance:
  - ms-registry-editor-navigation-state-pe
---

# Regedit LastKey

## Forensic value
`HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\LastKey` records the full registry path Registry Editor was displaying when it last closed. One REG_SZ value per user.

Forensically, it answers the question **"what registry location did this user navigate to?"** — and by extension, what they may have viewed or edited during that session.

## Insider-threat / tamper-attribution use
- User claims "I never edited the registry" — LastKey contains `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` → direct contradiction
- Defender exclusion appeared in the registry during incident window — LastKey on a specific user matches the exclusion path → attribution
- Multiple users on a shared machine — LastKey per NTUSER.DAT distinguishes who touched what

## Concept reference
- None direct — user-action pointer.

## Triage
```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /v LastKey
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites"
```

Per-user offline (all NTUSER.DAT hives):
```powershell
Get-ChildItem "C:\Users\*\NTUSER.DAT" -Force | ForEach-Object {
    # Load each hive, read Applets\Regedit\LastKey
}
```

## Cross-reference
- **Security-4688** / **Sysmon-1** — regedit.exe process creation = user session bracket
- **Prefetch** — REGEDIT.EXE-*.pf = execution evidence of regedit.exe
- **UserAssist** — HKCU UserAssist may record regedit.exe launches with per-user run counts
- **Registry LastWrite** on keys nearby the LastKey path = corroboration of editing activity

## Attack-chain example
Insider preparing for exfiltration disables Defender via Registry Editor:
1. Opens regedit.exe
2. Navigates to `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`
3. Adds `C:\Users\<self>\Documents\exfil_staging`
4. Closes regedit.exe

Investigation findings:
- Defender-Exclusions\Paths LastWrite = moment of exclusion addition
- `HKCU\...\Applets\Regedit\LastKey` on this user's profile = Defender exclusions path
- Security-4688 regedit.exe launch timestamp brackets the session
- Three artifacts independently attribute the tamper to this specific user

## Practice hint
On a lab VM (any user account): open regedit, navigate to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, close regedit. Now check `HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\LastKey` — it contains `Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. That user-intent record is exactly the evidence you rely on in attribution cases.
