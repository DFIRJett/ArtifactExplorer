---
name: AppID
kind: value-type
lifetime: permanent
link-affinity: application
description: |
  16-character uppercase hex representation of a 64-bit CRC64 hash of a
  Windows Application User Model ID (AppUserModelID). Used as the filename
  prefix for jump-list artifacts and as a key name in several taskbar- and
  shell-related registry locations. Lets an examiner correlate evidence
  belonging to the same application across multiple artifacts.
canonical-format: "16 uppercase hex chars (e.g., 'F01B4D95CF55D32A')"
aliases: [app-user-model-id-hash, jumplist-app-id, taskbar-app-id]
roles:
  - id: jumplistApp
    description: "AppID used as filename prefix of an .automaticDestinations-ms / .customDestinations-ms file"
  - id: pinnedApp
    description: "AppID referenced in TaskbarLayout as a user-pinned application"
  - id: muiCachedApp
    description: "AppID referenced in MUICache per-app display-name entries"

known-containers:
  - AutomaticDestinations
  - CustomDestinations
  - TaskbarLayout
  - MUICache
---

# AppID (AppUserModelID hash)

## What it is
A 16-char uppercase hex string derived by Windows from an application's Application User Model ID via CRC64. Used as:
- **Filename prefix** for jump list files (`F01B4D95CF55D32A.automaticDestinations-ms`)
- **Registry key name** in TaskbarLayout, MUICache, and similar taskbar/shell keys

AppID lets Windows tie together artifacts belonging to the same app without needing the full AppUserModelID string. For the examiner it's the same pivot: all files/keys starting with the same 16-hex prefix belong to the same application.

## Known AppIDs (partial list for quick identification)
| Hex | Application |
|---|---|
| `1B4DD67F29CB1962` | Windows Explorer |
| `9E1C2E5B6F2B67C5` | Command Prompt |
| `F01B4D95CF55D32A` | Google Chrome |
| `7E4DCA80246863E3` | Microsoft Edge |
| `AE26B2E1A1DFE24E` | Firefox |
| `5F7B5F1E01B83767` | Notepad |

A reverse lookup table against canonical AppIDs is maintained in tools like JLECmd. Unknown AppIDs require resolving via the live system (`Get-StartApps` on a matching Windows version) or by extracting the AUMID from an app's installed metadata.

## Encoding
`AppID` is the lowercase-insensitive 16-hex-char string. Some parsers force uppercase; some preserve the on-disk case. Match case-insensitively when pivoting across artifacts.
