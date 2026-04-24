---
name: Cortana-CoreDb
title-description: "Cortana Core ESE database — user geolocation, reminders, reminder trigger points"
aliases:
- Cortana CoreDb
- CortanaCoreDb.dat
- CoreInstance ESE
link: user
link-secondary: application
tags:
- per-user
- geolocation
- user-behavior
volatility: persistent
interaction-required: user-action
substrate: windows-ess
substrate-instance: Cortana-CoreDb
platform:
  windows:
    min: '10'
    max: '11'
    note: "Cortana as an assistant was progressively deprecated across Win10/11 — on newer Win11 builds the Cortana app has been removed from default shipping. However, where Cortana is / was present, the CoreDb.dat file persists until the user profile is removed. Legacy data survives Cortana deprecation."
  windows-server: N/A (client-only)
location:
  path: "%LOCALAPPDATA%\\Packages\\Microsoft.Windows.Cortana_*\\LocalState\\ESEDatabase_CortanaCoreInstance\\CortanaCoreDb.dat"
  companion: "IndexedDB.edb at %LOCALAPPDATA%\\Packages\\Microsoft.Windows.Cortana_*\\AppData\\Indexed DB\\IndexedDB.edb"
  addressing: file-path
  note: "ESE (JET) database. Parse with esedbexport or Windows ESE tools (Nirsoft ESEDatabaseView, libesedb). Schema is Microsoft-proprietary / reverse-engineered — tables include reminder-related structures, geolocation / place tables, contact data, and task/reminder triggers."
fields:
- name: reminder-trigger-location
  kind: content
  location: "reminder-related tables → location-coordinate columns"
  encoding: latitude / longitude floats (per Microsoft schema)
  note: "Where the user set reminders to fire — geolocation points the user designated as 'remind me here'. A user who set a reminder at 'home' reveals their residential geolocation; reminders at 'work' reveal employer location. Direct user-location leakage."
- name: reminder-text
  kind: content
  location: "reminder-related tables → description / text columns"
  encoding: utf-16le
  references-data:
  - concept: UserSID
    role: profileOwner
  note: "Text of each reminder. User-authored content — often reveals personal / professional context (appointments, people, errands, project names). Similar value to journal / notes recovery."
- name: reminder-time
  kind: timestamp
  location: "reminder-related tables → trigger-time columns"
  encoding: filetime-le or ISO-8601 (schema-dependent)
  clock: system
  resolution: 1s
  note: "When the reminder was scheduled to fire. Combined with location, gives a 'user planned to be at place X at time Y' inference."
- name: geolocation-history
  kind: content
  location: "place / history tables"
  encoding: lat/lon + timestamp
  note: "Past locations the user visited (sometimes stored by Cortana for 'recent places' features). If populated, this is direct geolocation tracking of the user over time — equivalent to the Google-Maps timeline feature but on-device and often-overlooked."
- name: voice-command-transcripts
  kind: content
  location: "indexed content tables"
  encoding: utf-16le
  note: "Text transcripts of voice commands Cortana processed. When speech-indexing was enabled, user-voice queries are persisted here in text form (separate from audio WAVs in the Speech folder)."
- name: contact-references
  kind: content
  location: "people / contact tables"
  encoding: varies
  note: "Cross-references to contact entries from the People app. Reveals relationships the user named in Cortana context ('remind me to call <person>' → person reference). Privacy-sensitive."
- name: file-mtime
  kind: timestamp
  location: CortanaCoreDb.dat $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime — updates on any Cortana-database write. A recent mtime indicates active Cortana use; stale mtime on a Cortana-installed system indicates the user disabled or stopped using the assistant."
observations:
- proposition: HAD_CONTENT
  ceiling: C3
  note: 'Cortana CoreDb is a geolocation-rich and behavior-revealing
    user artifact that survives long after Cortana feature-deprecation.
    Because most DFIR playbooks do not include Cortana paths by
    default (the assistant is perceived as obsolete), the data
    typically escapes cleanup. For investigations involving user
    location / movement, reminder content that reveals personal or
    professional context, or voice-command history, CortanaCoreDb
    provides content no other per-user artifact offers.'
  qualifier-map:
    object.location: field:reminder-trigger-location
    object.content: field:reminder-text
    time.start: field:reminder-time
anti-forensic:
  write-privilege: user
  integrity-mechanism: ESE page-level checksums; no signing
  known-cleaners:
  - tool: "Windows Settings → Apps → Cortana → Reset / Uninstall"
    typically-removes: the CortanaCoreDb.dat file (not always — UWP reset sometimes retains user data)
  - tool: delete the whole Packages\\Microsoft.Windows.Cortana_*\\ directory
    typically-removes: everything including CoreDb
  survival-signals:
  - CortanaCoreDb.dat present on a system with recent Cortana mtime = active Cortana user; parse for location / reminder content
  - Geolocation data matching suspect / traveled locations with corresponding reminder context = user-location corroboration
  - Voice-command transcripts containing command-line / scripted content = anomalous use pattern worth triage
provenance:
  - libyal-libesedb
  - singh-2017-cortana-forensics-windows-10
exit-node:
  is-terminus: false
  terminates:
    - VIEWED_LOCATION
  sources:
    - singh-2017-cortana-forensics-windows-10
    - libyal-libesedb
  reasoning: >-
    CortanaCoreDb.dat is the ESE database holding Cortana's local
    storage — reminders, geolocations, voice-command transcripts,
    geofence definitions, per-user Cortana interactions. The DB IS
    the canonical record of user-location-as-known-to-Cortana on
    this host; there's no upstream local store. For "where was the
    user according to system-recorded location context?" reasoning,
    this is the terminus.
  implications: >-
    Geolocation entries matching suspect or traveled locations
    combined with corresponding reminder / voice-command text
    provide user-location corroboration even without GPS-provider
    logs. Entries survive Cortana's own UI cleanup — they persist
    in the ESE database until table compaction. Cross-reference
    with Cortana-IndexedDB and Notifications-wpndatabase for full
    per-app activity reconstruction.
  preconditions: >-
    Read access to the per-user LocalState folder:
    %LOCALAPPDATA%\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\
    LocalState\ESEDatabase_CortanaCoreDb\CortanaCoreDb.dat. ESE
    recovery may need replay of the .log companion files.
  identifier-terminals-referenced:
    - UserSID
---

# Cortana CoreDb

## Forensic value
`%LOCALAPPDATA%\Packages\Microsoft.Windows.Cortana_*\LocalState\ESEDatabase_CortanaCoreInstance\CortanaCoreDb.dat` is the ESE-format persistent database behind the Cortana assistant. It holds:

- **User-set reminders** — with text, scheduled time, and location coordinates
- **Geolocation / places** — designated locations (home, work, favorite places)
- **Voice-command transcripts** — text records of Cortana voice queries
- **Contact references** — people named in Cortana commands

Despite Cortana's progressive deprecation across Win10/11, the database persists on systems that ever had the assistant enabled. Because DFIR playbooks frequently omit Cortana paths (perceived-obsolete feature), the data typically escapes standard sanitization.

## Why it surfaces where other artifacts don't
Browser history, location services, and modern-app telemetry are commonly monitored / DLP'd. Cortana's on-device storage of geo-tagged reminders is typically not instrumented. A user setting a reminder at a specific geolocation reveals that geolocation in the database without ever touching a monitored geolocation API.

## Concept reference
- None direct — content + geolocation artifact.

## Parsing
```cmd
:: ESE export with libesedb / esedbexport
esedbexport.exe -t .\cortana_export CortanaCoreDb.dat

:: NirSoft ESEDatabaseView for GUI
ESEDatabaseView.exe /Load CortanaCoreDb.dat
```

Look for tables with location / place / reminder / person prefixes (schema changed across Cortana builds — inspect what's present).

## Cross-reference
- **Cortana IndexedDB.edb** — sibling indexed-search database with additional content
- **Cortana Speech WAVs** — audio files of voice commands under `\LocalState\Speech\`
- **ActivitiesCache** — Windows Timeline may reference Cortana-tagged activities
- **StateRepository** — UWP app package info for Cortana

## Practice hint
On a Win10 VM with Cortana enabled: set a reminder at a specific location (e.g., "remind me to do X when I get home" — drop a custom pin). Allow Cortana to index. Locate CortanaCoreDb.dat and inspect with ESEDatabaseView — the pinned coordinates and reminder text are readable in the relevant tables. This is the exact data-extraction path DFIR uses in real cases involving Cortana-stored content.
