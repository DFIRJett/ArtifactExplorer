---
name: Cortana-Speech-WAVs
title-description: Cortana voice-command WAV recordings — direct audio captures of user speech queries
aliases:
- Cortana Speech recordings
- voice command WAVs
- LocalState\\Speech
link: user
link-secondary: application
tags:
- per-user
- voice-biometric
- user-attribution
volatility: persistent
interaction-required: user-action
substrate: windows-binary-cache
substrate-instance: Cortana-Speech-WAVs
platform:
  windows:
    min: '10'
    max: '11'
  windows-server: N/A (client-only)
location:
  path: '%LOCALAPPDATA%\Packages\Microsoft.Windows.Cortana_*\LocalState\Speech\*.wav'
  addressing: file-path
  note: Per-user audio recordings of voice commands Cortana processed. Stored as WAV when local speech-processing / training was enabled, OR as transcribed text only when cloud-processing was used without
    local retention. Presence of WAV files indicates the assistant had local speech-retention enabled for this user.
fields:
- name: audio-wav
  kind: content
  location: Speech\<command-id>.wav
  encoding: WAV PCM audio
  references-data:
  - concept: UserSID
    role: profileOwner
  note: Direct audio recording of user voice command. Can be played back to hear exact user speech at query time. Voice-biometric material for user-attribution cases (speaker recognition) in addition to
    the semantic content of the query.
- name: wav-mtime
  kind: timestamp
  location: wav file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: Recording creation time. Brackets voice-query activity.
- name: companion-transcripts
  kind: content
  location: IndexedDB.edb / CortanaCoreDb.dat text-of-query tables
  note: Text transcript of the voice command should appear in one of the sibling databases. Pair WAV audio with text transcript for full context.
observations:
- proposition: USER_UTTERANCE
  ceiling: C3
  note: Cortana Speech WAVs are one of the rare Windows artifacts capturing direct user-voice biometric data. For user-attribution cases they are uniquely compelling — a voice recording is harder to dispute
    than a log entry. For cases involving contested user-activity claims (insider alleging an action was not theirs), speaker-recognition analysis against Speech WAVs can confirm or refute.
  qualifier-map:
    actor.voice: field:audio-wav
    time.start: field:wav-mtime
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: Cortana privacy settings → delete speech data
    typically-removes: local WAVs (cloud-side retention unaffected)
  survival-signals:
  - Speech\\*.wav files present on a user profile = local speech retention was on; playback reveals exact user utterances
provenance:
- ms-cortana-privacy-speech-data-retenti
- singh-2017-cortana-forensics-windows-10
---

# Cortana Speech WAVs

## Forensic value
`%LOCALAPPDATA%\Packages\Microsoft.Windows.Cortana_*\LocalState\Speech\*.wav` holds direct WAV audio recordings of user voice commands when local speech retention was enabled. One of the rare Windows artifacts capturing voice-biometric user data.

## Use case
- **User attribution** — speaker-recognition against a reference voice sample confirms / refutes which user issued a command
- **Content recovery** — exact user utterance recoverable as audio even if text transcript is corrupted / cleared
- **Contested-activity cases** — user claims "I never asked Cortana that" — WAV is the evidence

## Triage
```powershell
Get-ChildItem "C:\Users\*\AppData\Local\Packages\Microsoft.Windows.Cortana_*\LocalState\Speech\*.wav" -ErrorAction SilentlyContinue | Select FullName, LastWriteTime, Length
```

Any returned WAV = direct voice evidence. Play / analyze as needed.

## Cross-reference
- `Cortana-CoreDb` / `Cortana-IndexedDB` — text transcript of the same voice queries
- `ActivitiesCache` — Cortana-initiated activities with timestamps

## Practice hint
On a Win10 VM with Cortana: enable speech retention in Cortana privacy settings. Issue a voice query. Check the Speech folder — WAV file is present. Play it back — exact user utterance preserved.
