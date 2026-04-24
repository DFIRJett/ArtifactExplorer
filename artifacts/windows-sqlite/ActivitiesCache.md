---
name: ActivitiesCache
aliases:
- Windows Timeline
- Connected Devices Platform activity cache
link: user
link-secondary: application
tags:
- per-user
- tamper-easy
- cross-device
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: ActivitiesCache
platform:
  windows:
    min: '10'
    max: '11'
    note: Timeline UI removed in Win11 but database still populated for Connected-Devices sync; verify per-build
location:
  path: "%LOCALAPPDATA%\\ConnectedDevicesPlatform\\L.<user>\\ActivitiesCache.db"
  addressing: sqlite-table-row
fields:
- name: AppId
  kind: json
  location: Activity table → AppId column
  encoding: JSON array of {platform, application}
  note: contains one entry per platform (Windows, Web, etc.) with the executable path or PWA ID
  references-data:
  - concept: ExecutablePath
    role: ranProcess
- name: PackageIdHash
  kind: hash
  location: Activity table → PackageIdHash
  note: hashed Windows Store package ID when applicable
- name: Payload
  kind: json
  location: Activity table → Payload
  encoding: JSON blob
  note: application-specific content — for Edge, includes page title, URL, tab-group; for Office, the document path
- name: ContentInfo
  kind: json
  location: Activity table → ContentInfo
  encoding: JSON
- name: ActivityType
  kind: flag
  location: Activity table → ActivityType
  note: 5 = user-engagement / 6 = Cortana-task / 10 = foreground-notification; 5 is the primary forensic type
- name: ActivityStatus
  kind: flag
  location: Activity table → ActivityStatus
  note: 1 = active / 2 = ended / 3 = ignored
- name: StartTime
  kind: timestamp
  location: Activity table → StartTime
  encoding: unix-epoch-seconds (uint32)
  clock: system
  resolution: 1s
- name: EndTime
  kind: timestamp
  location: Activity table → EndTime
  encoding: unix-epoch-seconds
- name: LastModifiedTime
  kind: timestamp
  location: Activity table → LastModifiedTime
  encoding: unix-epoch-seconds
- name: OriginalLastModifiedOnClient
  kind: timestamp
  location: Activity table → OriginalLastModifiedOnClient
  encoding: unix-epoch-seconds
  note: timestamp on the originating device when the activity is synced from another device via MSA
- name: ClipboardPayload
  kind: ciphertext
  location: ActivityOperation table → ClipboardPayload
  encoding: base64 + sometimes encrypted content body
  note: cross-device clipboard content when Clipboard History + cloud clipboard are enabled; the CSIDL data-type code precedes
observations:
- proposition: ACCESSED_WITH_FOCUS
  ceiling: C3
  note: Per-application focus-time and content record. Timeline shows *what document/page* was open in *which app* for *how long*. Cross-device sync via MSA extends this to other devices on the same account.
  qualifier-map:
    actor.user: profile-directory owner
    object.application: field:AppId
    object.content: field:Payload
    time.start: field:StartTime
    time.end: field:EndTime
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - tool: Settings → Privacy → Activity history → Clear
    typically-removes: full
  - tool: Group Policy 'Allow publishing user activities' disable
    typically-removes: prevents future writes
  - tool: manual DROP of Activity table
    typically-removes: full
provenance: []
provenance: [sqlite-org-fileformat]
---

# ActivitiesCache

## Forensic value
Win10/11's **Timeline** database. For every user-engagement activity (file opened, website visited, document edited), Windows records an entry: the app, the content identifier/payload (URL, file path, document title), start/end focus times, and the originating device.

Cross-device coverage is the standout feature: with Microsoft-account sync enabled, activities from OTHER devices on the same MSA (Windows laptop, Android phone with MS Launcher, etc.) appear in the local DB. Evidence of a user's activity on a device you don't have access to.

## Rich payloads
The `Payload` column is JSON, application-keyed:
- **Edge/IE** — `{displayText, description, contentUri, shoulderTapPayload}` — the page title, URL, and summary
- **Office apps** — document path and title
- **Explorer** — folder path
- **Media apps** — track identifier

Parse with any JSON tool. `WxTCmd` (Eric Zimmerman) automates the decode and correlates Activity with ActivityOperation rows.

## Clipboard sync caveat
If "Cloud Clipboard" was ever enabled, the `ActivityOperation.ClipboardPayload` column holds base64-encoded clipboard contents — sometimes multi-MB (images, files). Check for this separately; it's not tied to a specific application activity but to the shared-clipboard sync event.

## Cross-references
- **UserAssist** — per-program launch counts in the registry; complementary counter to Timeline's focus-time
- **FeatureUsage** — taskbar interaction; captures a similar focus signal via registry
- **RecentDocs** — per-extension file history; overlap with Payload file paths
- **Chrome-History / Firefox-places** — browser-specific URL histories; ActivitiesCache captures Edge/IE but not Chromium unless Edge

## Practice hint
`wxtcmd.exe -f ActivitiesCache.db --csv .` (Eric Zimmerman) gives tabular output. For a quick triage, the Activity table alone:
```sql
SELECT datetime(StartTime,'unixepoch') AS start, AppId, Payload
FROM Activity
WHERE ActivityType=5
ORDER BY StartTime DESC LIMIT 30;
```
