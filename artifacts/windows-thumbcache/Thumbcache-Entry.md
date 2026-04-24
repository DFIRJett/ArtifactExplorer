---
name: Thumbcache-Entry
aliases:
- thumbnail cache entry
- CMMM cache record
link: file
tags:
- per-user
- content-survival
- tamper-hard
volatility: persistent
interaction-required: user-action
substrate: windows-thumbcache
substrate-instance: thumbcache_<size>.db
platform:
  windows:
    min: Vista
    max: '11'
location:
  path: "%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\thumbcache_<size>.db"
  sizes:
    - thumbcache_16.db
    - thumbcache_32.db
    - thumbcache_48.db
    - thumbcache_96.db
    - thumbcache_256.db
    - thumbcache_768.db
    - thumbcache_1024.db
    - thumbcache_1280.db
    - thumbcache_1600.db
    - thumbcache_1920.db
    - thumbcache_2560.db
  addressing: cache-entry-hash
fields:
- name: profile-sid
  kind: identifier
  location: derived from path segment `%LOCALAPPDATA%\` — the owning user's SID resolves via ProfileList ProfileImagePath
  encoding: sid-string
  note: "Not stored in the cache file itself — derived from the per-user %LOCALAPPDATA% path. Required to attribute thumbnail-cache evidence to a specific user's Explorer activity. Matches the pattern used on sibling IconCache."
  references-data:
  - concept: UserSID
    role: profileOwner
- name: entry-hash
  kind: identifier
  location: cache-entry header → Hash
  type: uint64-le
  note: computed from the source file path via a Windows-specific path-hash; used as primary key. NOT a cryptographic content hash — do not confuse with SHA-1/SHA-256 file hashes. Matching entries across thumbcache_<size>.db files share this hash.
- name: identifier-string
  kind: label
  location: cache-entry header → IdentifierString
  encoding: UTF-16LE
  note: most commonly the source file path (Win10+); may be abbreviated or hash-encoded on older builds
  references-data:
  - concept: ExecutablePath
    role: shellReference
- name: data-size
  kind: size
  location: cache-entry header → DataSize
- name: data-checksum
  kind: checksum
  location: cache-entry header → DataChecksum
- name: header-checksum
  kind: checksum
  location: cache-entry header → HeaderChecksum
- name: data-blob
  kind: content
  location: cache-entry data
  encoding: JPEG / PNG / BMP (extension-free, detect by magic)
  note: the actual thumbnail image — extractable to disk as normal image
- name: cache-file-mac
  kind: timestamps
  location: $MFT of the thumbcache_<size>.db file itself
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: DB-level last-write captures most-recent thumbnail addition
observations:
- proposition: VIEWED_OR_INDEXED
  ceiling: C2
  note: A thumbnail exists for the referenced source file because the user viewed the containing folder in a thumbnail-capable Explorer view. Survives source-file deletion.
  qualifier-map:
    actor.user: profile-directory owner
    object.file.path: field:identifier-string
    object.thumbnail.size: thumbcache filename suffix
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - tool: "Disk Cleanup → Thumbnails"
    typically-removes: full (targeted)
  - tool: manual delete of thumbcache_*.db
    typically-removes: full (after Explorer kill)
provenance: [libyal-libesedb]
---

# Thumbcache-Entry

## Forensic value
Each thumbnail in the cache corresponds to a source file the user viewed — typically because they opened a folder in Explorer using any thumbnail-enabled view mode (Medium/Large/Extra-Large icons, or Thumbnails view). The key property:

**The thumbnail persists after the source file is deleted.**

That makes thumbcache one of the strongest **proof-of-viewing** artifacts in Windows forensics:
- Images no longer present on disk can still be recovered as thumbnails
- Files viewed from a disconnected USB or mapped network drive remain cached
- Attacker cleanup that targets source files without touching thumbcache leaves the thumbnail as evidence

## Size-variant significance
Windows creates separate DB files per thumbnail size. Which size is populated indicates the view the user used:
- 16/32/48/96 — small/medium icons (default file-browser view)
- 256 — large icons
- 768/1024/1280/1600/1920/2560 — extra-large / preview-pane on high-DPI displays

A thumbnail present in `thumbcache_1920.db` means the user viewed the source in a very large preview mode — deliberate examination signal.

## Entry-hash lookup
Given a known file path, the entry-hash can be computed independently of the idx DB. Compute the path-hash and search every `thumbcache_*.db` for that value. If found, extract the data-blob to an image file. Tools: **Thumbcache Viewer** does the computation + search; manual implementation is documented in libwrc.

## Removable-media correlation
A thumbnail with identifier-string `F:\vacation\*.jpg` when `F:` is no longer mounted tells you:
- A drive with label/GUID that once mounted as `F:` contained those files
- The user viewed them in Explorer
- Pair with USBSTOR + MountedDevices to identify the physical device

## Cross-references
- **IconCache** — sibling DB for non-image file icons; separate content but same format
- **Thumbcache-Index** (thumbcache_idx.db) — hash→path lookup table
- **Recent-LNK** — corroborates access to the same files via file-open dialogs

## Practice hint
Use `ThumbcacheViewer.exe` (Erik Hjelmvik) to bulk-export an acquired `thumbcache_*.db` set to a folder of image files. Compare the extracted filename list against known-good user directories to surface images from deleted files or external media.
