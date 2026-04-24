---
name: IconCache
aliases: [iconcache.db, legacy IconCache.db]
link: file
tags: [per-user, content-survival]
volatility: persistent
interaction-required: user-action
substrate: windows-thumbcache
substrate-instance: iconcache
platform:
  windows: {min: Vista, max: '11'}
location:
  path-legacy: "%LOCALAPPDATA%\\IconCache.db"
  path-modern: "%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\iconcache_*.db"
  addressing: cache-entry-hash
fields:
- name: profile-sid
  kind: identifier
  location: derived from path segment `%LOCALAPPDATA%\` — the owning user's SID resolves via ProfileList ProfileImagePath
  encoding: sid-string
  note: "Not stored in the cache file itself — derived from the per-user %LOCALAPPDATA% path. Required to attribute icon-cache evidence to a specific user's Explorer interactions."
  references-data:
  - concept: UserSID
    role: profileOwner
- name: entry-hash
  kind: identifier
  location: cache-entry header → Hash
  note: "same Windows path-hash as thumbcache; matches thumbcache entries for the same source file"
- name: identifier-string
  kind: label
  location: cache-entry header → IdentifierString
  note: "Win10+ stores source file path; earlier OSes abbreviate"
  references-data:
  - concept: ExecutablePath
    role: shellReference
- name: icon-data
  kind: content
  location: cache-entry data
  encoding: ICO / PNG (size-variant)
observations:
- proposition: FILE_ICON_OBSERVED
  ceiling: C2
  note: "Icon cache parallel to thumbcache but for non-image files. Entry existence proves the host rendered an icon for the source file — weaker than thumbcache (image content) but covers every file type."
  qualifier-map:
    object.file.path: field:identifier-string
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - {tool: Disk Cleanup → 'Thumbnails', typically-removes: partial}
provenance: [libyal-libesedb]
---

# IconCache

## Forensic value
Parallel to thumbcache but for file icons (non-image files). Same CMMM-ish format. When Explorer renders a shortcut or a .exe icon, iconcache persists the rendered bitmap. Evidence that a host's Explorer OBSERVED the file even if the file itself is gone — weaker than thumbcache (image preview) because icons are typically class-level, but valuable when thumbcache lacks an entry.

## Cross-references
- **Thumbcache-Entry** — sibling cache for image content
- **MFT** — correlate identifier-string with current filesystem state
