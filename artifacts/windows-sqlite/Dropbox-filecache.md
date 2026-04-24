---
name: Dropbox-filecache
aliases: [Dropbox sync database]
link: file
link-secondary: application
tags: [per-user, cloud-sync, encrypted]
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: Dropbox-filecache
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%APPDATA%\\Dropbox\\instance1\\filecache.dbx"
  note: "encrypted SQLite variant (.dbx format — Dropbox-specific)"
  addressing: sqlite-table-row
fields:
- name: profile-sid
  kind: identifier
  location: derived from path segment `%APPDATA%\Dropbox\` — the owning user's SID resolves via ProfileList ProfileImagePath
  encoding: sid-string
  note: "Not a column in filecache.dbx — derived from the filesystem path's owning-user-profile. Required to attribute sync-cache evidence to a specific user account."
  references-data:
  - concept: UserSID
    role: profileOwner
- name: file_journal-entries
  kind: record
  location: file_journal table (once decrypted)
  note: "server-synced file metadata: local_path, server_path, size, rev, modified-time, namespace"
- name: local_path
  kind: path
  location: file_journal → local_path
- name: server_path
  kind: path
  location: file_journal → server_path
  note: "Dropbox cloud path where the file lives"
- name: modified
  kind: timestamp
  location: file_journal → modified
  encoding: unix-epoch-seconds
observations:
- proposition: CLOUD_SYNCED_FILE
  ceiling: C3
  note: "Record of files in the user's Dropbox sync set — local AND server paths. Decryption requires extracting the Dropbox-specific key from config.dbx (via dbxkey or similar). Critical for data-exfiltration cases: files on the local disk that ALSO sync to cloud = potential exfil vector."
  qualifier-map:
    actor.user: profile owner
    object.local.path: field:local_path
    object.cloud.path: field:server_path
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - {tool: Dropbox → unlink, typically-removes: partial (config entries retained)}
provenance: []
provenance: [sqlite-org-fileformat]
---

# Dropbox-filecache

## Forensic value
Dropbox's local sync-state database. Records every file in the user's Dropbox, both the local path and the server-side path. Critical for data-exfiltration cases where corporate data is synced to personal Dropbox. The file is encrypted with a device-specific Dropbox key — tools like Magnet Axiom, Dropbox Decryptor, and dbxdecrypt can extract and decrypt.

## Cross-references
- **OneDrive-SyncEngine** — sibling cloud-sync artifact
- **Chrome-Downloads** — may show recent file acquisitions prior to sync
- **MFT** — local filesystem corroboration
