---
name: FeatureUsage
aliases:
- Taskbar feature usage
- AppSwitched / AppLaunch counters
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
    max: '11'
location:
  hive: NTUSER.DAT
  path: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage
  sub-paths: |
    FeatureUsage\AppSwitched
    FeatureUsage\AppLaunch
    FeatureUsage\ShowJumpView
    FeatureUsage\TrayButtonClicked
  addressing: hive+key-path
fields:
- name: AppSwitched-entry
  kind: counter
  location: AppSwitched → values named by AppID
  type: REG_DWORD
  note: increments when user clicks the taskbar icon of an app already in background (focus-change count)
  references-data:
  - concept: AppID
    role: muiCachedApp
- name: AppLaunch-entry
  kind: counter
  location: AppLaunch → values named by AppID
  type: REG_DWORD
  note: increments when the user clicks the taskbar icon to launch the app (cold-start count)
  references-data:
  - concept: AppID
    role: muiCachedApp
- name: ShowJumpView-entry
  kind: counter
  location: ShowJumpView → values named by AppID
  type: REG_DWORD
  note: increments when the user opens the jump list of the app (right-click)
- name: TrayButtonClicked-entry
  kind: counter
  location: TrayButtonClicked → values named by system-tray applet identifier
  type: REG_DWORD
- name: AppBadgeUpdated-entry
  kind: counter
  location: AppBadgeUpdated → values named by AppID
  type: REG_DWORD
  note: notification-badge update events per app
- name: key-last-write
  kind: timestamp
  location: sub-key metadata (AppSwitched, AppLaunch, etc.)
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: touched on each counter increment (any AppID under the subkey)
observations:
- proposition: INTERACTED_WITH_APP
  ceiling: C3
  note: Per-user taskbar interaction telemetry. Counts distinguish foreground launches, focus switches, and jump-list opens. Last-write timestamp gives freshness.
  qualifier-map:
    actor.user: NTUSER.DAT owner
    object.application: value-name (AppID)
    object.interaction.count: value-data
    time.last: field:key-last-write (subkey-level, not per-value)
anti-forensic:
  write-privilege: user
  known-cleaners:
  - tool: no common cleaner targets FeatureUsage specifically
    typically-removes: n/a
  - tool: manual reg delete of FeatureUsage tree
    typically-removes: full (wipes all user taskbar history)
provenance: []
provenance: [libyal-libregf, regripper-plugins]
---

# FeatureUsage

## Forensic value
Win10/11 registry-based counter set that tracks per-user taskbar behavior. Richer than UserAssist for modern apps because it distinguishes:

- **AppLaunch** — cold-start from taskbar (new process)
- **AppSwitched** — focus switch to already-running instance
- **ShowJumpView** — user opened the jump list
- **AppBadgeUpdated** — notification-badge refresh events
- **TrayButtonClicked** — system-tray applet clicks

Counters are per AppID. AppID is the CRC64 hash of the AppUserModelID — the same identifier that keys jump list filenames and TaskbarLayout entries. Resolving AppID → human-readable app name requires the TaskbarLayout registry mapping or MUICache.

## Why it matters vs UserAssist
UserAssist counts clicks of Start Menu shortcuts; FeatureUsage counts taskbar clicks. Modern users launch apps from the taskbar more than the Start Menu, so FeatureUsage often has richer coverage:

- User never opened Start → UserAssist sparse → FeatureUsage rich
- User exclusively opens documents via recent-files → both sparse; Recent-LNK wins

## Freshness
The subkey last-write timestamp (e.g. `AppSwitched`'s last-write) is the most-recent activity across ALL apps under that subkey. Per-AppID last-used times are not preserved individually — only counts. This is different from UserAssist, where each application value contains a FILETIME.

## Cross-references
- **UserAssist** — complementary Start-menu-click counters
- **TaskbarLayout** — AppID → pinned-status + pin position
- **MUICache** — AppID → human-readable friendly name
- **ActivitiesCache** — Timeline gives per-app focus time (richer for dating)

## Practice hint
```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch' -EA 0
```
Then resolve AppIDs via:
```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MUICache' | ...
```
AppID-to-name mapping isn't perfect — some Windows-resolved AppIDs require hardcoded Microsoft tables.
