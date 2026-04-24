---
name: RecentApps
aliases:
- Search RecentApps
- Win10 per-user app launch MRU
link: user
tags:
- per-user
- tamper-easy
- user-activity
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: '10'
    max: '10'
    note: "Win10 only — removed on Win11 in favor of ActivitiesCache + FeatureUsage. Persisting on upgraded-from-Win10 machines is possible but new writes stop."
location:
  hive: NTUSER.DAT
  path: Software\Microsoft\Windows\CurrentVersion\Search\RecentApps
  sub-paths: RecentApps\<AppID-GUID>\RecentItems\<item-GUID>
  addressing: hive+key-path
fields:
- name: AppPath
  kind: path
  location: per-AppID subkey → AppPath value
  type: REG_SZ
  note: full path or URI of the launched application
  references-data:
  - concept: ExecutablePath
    role: ranProcess
- name: LaunchCount
  kind: counter
  location: per-AppID subkey → LaunchCount value
  type: REG_DWORD
  note: per-app launch count for the lifetime of this entry
- name: LastAccessedTime
  kind: timestamp
  location: per-AppID subkey → LastAccessedTime value
  type: REG_QWORD
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: RecentItem-path
  kind: path
  location: per-AppID → RecentItems\<item-GUID> → Path value
  type: REG_SZ
  note: per-(app, file) record — each file opened by that app gets its own GUID-named subkey with the Path
- name: RecentItem-time
  kind: timestamp
  location: per-AppID → RecentItems\<item-GUID> → LastAccessedTime value
  type: REG_QWORD
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: on file open via that app
observations:
- proposition: EXECUTED
  ceiling: C3
  note: Win10 Search RecentApps — per-app launch counts + per-(app,file) access timestamps. Richer than UserAssist because it correlates the application to the specific files opened through it.
  qualifier-map:
    actor.user: NTUSER.DAT owner
    object.application: field:AppPath
    object.file: field:RecentItem-path
    object.launch.count: field:LaunchCount
    time.last_open: field:LastAccessedTime
anti-forensic:
  write-privilege: user
  known-cleaners:
  - tool: Settings → Privacy → Activity history → Clear
    typically-removes: partial (Timeline UI cleanup does not always touch RecentApps)
  - tool: manual reg delete of RecentApps tree
    typically-removes: full
provenance: []
provenance: [libyal-libregf, regripper-plugins]
---

# RecentApps

## Forensic value
Win10's registry-based per-user app launch and file-open tracker. Sister to UserAssist but structured differently — by AppID GUID rather than encoded path. Each application entry carries:

- The application's path (resolving the AppID GUID to a real executable)
- A lifetime launch count
- A last-accessed FILETIME
- A child list of `RecentItems\<GUID>` entries — each holding a file path + its own timestamp

The child list is the critical part: it ties **which app opened which file when**. UserAssist tells you the app launched but not what it was used for. RecentApps tells you "Word was launched, and these are the five files Word opened in order."

## Deprecation on Win11
Win11 removed the Search\RecentApps writer. Users who upgraded from Win10 may have historical RecentApps data frozen at the upgrade moment. New activity doesn't write here on Win11 — it lands in ActivitiesCache (SQLite) instead.

Implication: for a Win11 host, RecentApps is a **snapshot of Win10-era activity** preserved across upgrade. Last-access timestamps won't postdate the upgrade.

## AppID as the key
Subkey names are GUIDs (e.g., `{00EBD09E-AA94-4B1F-9299-78FEB5EA11E3}`). These GUIDs are Windows-assigned AppIDs — distinct from the CRC64 hex AppIDs used for jump lists / TaskbarLayout. Resolving GUID → human-readable app requires:
- Looking inside the subkey's AppPath value (most reliable)
- Cross-referencing known Microsoft GUIDs for system apps
- MuiCache for some

## Practice hint
Bulk enumeration:
```powershell
$r = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps'
Get-ChildItem $r -EA 0 | ForEach-Object {
  $app = Get-ItemProperty $_.PSPath
  $items = Get-ChildItem "$($_.PSPath)\RecentItems" -EA 0 | ForEach-Object {
    (Get-ItemProperty $_.PSPath).Path
  }
  [pscustomobject]@{
    AppID = $_.PSChildName
    AppPath = $app.AppPath
    LaunchCount = $app.LaunchCount
    LastAccessed = if ($app.LastAccessedTime) { [datetime]::FromFileTimeUtc($app.LastAccessedTime) }
    RecentFiles = $items -join '; '
  }
}
```

## Cross-references
- **UserAssist** — older launch-counter artifact covering the Start Menu shortcut path
- **ActivitiesCache** — Win10+ Timeline DB; the modern replacement on Win11
- **FeatureUsage** — per-AppID taskbar interaction counters (different AppID scheme — 16-char hex)
- **Prefetch** — independent execution evidence (process start, not user-click)
