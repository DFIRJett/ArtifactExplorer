---
name: OneDrive-SyncEngine
aliases: [OneDrive sync-engine state, Personal.dat, Business1.dat]
link: file
link-secondary: application
tags: [per-user, cloud-sync]
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: OneDrive-SyncEngine
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%LOCALAPPDATA%\\Microsoft\\OneDrive\\settings\\Personal\\<uuid>.dat and Business1\\<uuid>.dat"
  note: "OneDrive stores a mix of proprietary binary state files and SQLite databases; parsable with dedicated tools (OneDriveExplorer, KAPE's OneDrive module)"
  addressing: mixed-container-state
fields:
- name: local-path
  kind: path
  location: sync-engine state → local file path
- name: cloud-path
  kind: path
  location: sync-engine state → OneDrive item path
  references-data:
  - concept: URL
    role: embeddedReferenceUrl
- name: file-id
  kind: identifier
  location: sync-engine state → GraphDriveItemId
  note: "GUID identifying the cloud item — joins with OneDrive server logs"
- name: last-sync-time
  kind: timestamp
  location: sync-engine state
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: CLOUD_SYNC_STATE
  ceiling: C3
  note: "OneDrive sync engine state. Surfaces local-to-cloud file mapping plus sync times. Critical for data-exfiltration investigations involving personal or business OneDrive accounts."
  qualifier-map:
    actor.user: profile owner
    object.local.path: field:local-path
    object.cloud.path: field:cloud-path
    time.last_sync: field:last-sync-time
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - {tool: OneDrive → Unlink this PC, typically-removes: partial}
provenance: [khatri-2022-onedriveexplorer-parser-for-on]
---

# OneDrive-SyncEngine

## Forensic value
OneDrive's local sync state. Records the local→cloud mapping for every synced file. Separate stores for Personal (consumer MS account) and Business1+ (Office365 / AAD accounts). Critical for investigations involving:
- Corporate data synced to personal OneDrive (exfil)
- Files present on the host that ALSO live in the cloud (e.g. malicious payloads staged via OneDrive sync)
- Account linkages (profile directory reveals MSA / AAD IDs)

Tools: OneDriveExplorer (Brian Maloney), OneDrive-KAPE module, Magnet Axiom.

## Cross-references
- **Dropbox-filecache** — cross-cloud sibling
- **Chrome-Downloads** — ingress into the sync folder
- **MFT** — local filesystem corroboration
