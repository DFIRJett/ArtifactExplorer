---
name: windows-thumbcache
kind: binary-structured-file
substrate-class: Database
aliases: [Thumbnail Cache, thumbcache_*.db, Explorer thumbnail database]

format:
  magic: "CMMM"
  endianness: little
  version: "Vista / 7 / 8 / 10 / 11 (schema evolves per OS)"
  structure:
    header:
      name: CMMM (cache main map)
      key-fields:
        - name: format-version
        - name: first-cache-entry-offset
        - name: available-cache-entry-offset
        - name: number-of-cache-entries
    body:
      unit: cache-entry
      holds: [entry-hash, identifier-string-size, padding-size, data-size, data-checksum, header-checksum, identifier-string, data-blob]
      data-blob-format: JPEG / PNG / BMP (depending on entry kind)
  size-variants:
    - thumbcache_16.db    # 16x16 icons
    - thumbcache_32.db    # 32x32
    - thumbcache_48.db    # 48x48
    - thumbcache_96.db    # 96x96
    - thumbcache_256.db   # 256x256
    - thumbcache_768.db   # 768x768 (Win10+)
    - thumbcache_1024.db  # 1024x1024 (Win10+)
    - thumbcache_1280.db  # 1280x1280 (Win10+)
    - thumbcache_1600.db  # 1600x1600 (Win11)
    - thumbcache_1920.db  # 1920x1920 (Win11)
    - thumbcache_2560.db  # 2560x2560 (Win11)
    - thumbcache_idx.db   # index mapping (file-name + MRU ordering)
    - thumbcache_sr.db    # search results cache
  authoritative-spec:
    - title: "Windows thumbnail cache database format"
      author: Joachim Metz (libwrc research notes)
      note: not a Microsoft public format; reverse-engineered from Vista onwards

persistence:
  live-system-location:
    root: "%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\"
    per-user: yes
  retention:
    policy: "LRU eviction when file size cap hit; no TTL"
    cap-default: "limited by registry (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MaxThumbnailCacheSize)"
  locked-on-live-system: true (Explorer keeps handle)
  acquisition:
    methods:
      - VSC-based copy
      - raw-disk read
      - offline image

parsers:
  - name: Thumbcache Viewer (Erik Hjelmvik / EricZimmerman variants)
    strengths: [GUI, bulk export to image files, entry-hash/filename mapping via idx]
  - name: libwrc + python-wrc
    strengths: [programmatic access]
  - name: MFTECmd companion flows
    strengths: [correlation with $MFT timestamps]

forensic-relevance:
  - proof-of-viewing: |
      A thumbnail persists even after the source file is deleted or the user
      navigates away. Evidence that a user browsed a folder containing a
      specific image — even one that no longer exists — is strong corroboration
      in possession cases (IP theft, CSAM, contraband research).
  - post-deletion-survival: |
      Because thumbcache is user-scoped and independent from the source file,
      deleting the file leaves the thumbnail intact. Attempted cleanup that
      ignores %LOCALAPPDATA%\\Microsoft\\Windows\\Explorer is a common gap.
  - hash-based-identification: |
      Each entry carries an entry-hash derived from Windows' path-hash
      scheme. Given a target file's path, the expected entry-hash can be
      computed to check if THAT file was thumbnailed without needing
      thumbcache_idx.db.
  - removable-media-inference: |
      Thumbnails for files on a now-disconnected USB or mapped drive remain
      in the user's thumbcache. Combined with USBSTOR/MountedDevices, this
      places specific files on specific removable devices.

integrity:
  signing: none
  tamper-vectors:
    - direct entry deletion (requires closing Explorer)
    - file overwrite (destroys LRU index coherence)
    - Disk Cleanup "thumbnails" option (targeted wipe)
    - anti-forensic cleaners that target %LOCALAPPDATA%\\Microsoft\\Windows\\Explorer

anti-forensic-concerns:
  - "Disk Cleanup's 'Thumbnails' checkbox is the cleanest no-tool removal path; its use produces artifact in CBS.log."
  - Cleaning source files while leaving the thumbcache intact is the most common attacker mistake — the thumbnail proves the file existed.
  - "`del /f` of thumbcache_*.db files requires Explorer to be killed; the kill itself leaves process-termination evidence in Security.evtx or Sysmon event 5."

known-artifacts:
  authored: []
  unwritten:
    - name: Thumbcache-Entry
      location: "thumbcache_<size>.db cache entries"
      value: per-file thumbnail as JPEG/PNG/BMP with entry-hash and identifier-string linking to source path
    - name: Thumbcache-Index
      location: "%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\thumbcache_idx.db"
      value: entry-hash → filename + MRU ordering; enables filename-based lookups
    - name: Thumbcache-SearchResults
      location: "%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\thumbcache_sr.db"
      value: search-operation thumbnail cache — evidence of Explorer search queries
    - name: IconCache
      location: "%LOCALAPPDATA%\\IconCache.db (legacy) + %LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\iconcache_*.db"
      value: per-size icon cache; supplements thumbcache for non-image files
provenance: [libyal-libesedb]
---

# Windows Thumbnail Cache

## Forensic value
The thumbnail cache is Explorer's per-user store of image previews for every file a user browses in thumbnail view. Critically, **entries persist after the source file is deleted** — the cache is independent of the original file. This makes thumbcache one of the strongest evidence-of-viewing artifacts in Windows forensics:

- Images that no longer exist on disk can still be recovered from thumbcache.
- Files on disconnected removable media remain in the cache.
- Deletion by the user does not clean the thumbnail unless Disk Cleanup or an explicit cleaner targets it.

## Addressing within thumbcache
Each entry is keyed by an **entry-hash** (a Windows-specific path hash). To find "did this user view this specific file?", compute the expected entry-hash from the target path and look it up across all size variants. If no match, the file was likely not thumbnailed; if match, the thumbnail JPEG/PNG/BMP can be extracted and correlated to file content.

The companion `thumbcache_idx.db` maps entry-hashes back to identifier-strings (file paths), making the cache browsable by filename as well.

## Size variants and their meaning
Windows creates separate cache DBs per icon/thumbnail size (16, 32, 48, 96, 256, 768, 1024, 1280 on Win10; adds 1600/1920/2560 on Win11). A file may appear in multiple sizes depending on which views the user used (details vs. large icons vs. extra-large). The presence of a thumbnail at the higher-resolution sizes (768+) indicates the user viewed in a large-thumbnail mode — deliberate examination, not just passing browse.

## Collection notes
On live systems Explorer holds the files locked. Use VSC-copy or offline image. Acquire every `thumbcache_*.db` plus `iconcache_*.db` in the folder — sizes are small relative to their evidentiary value.

## Practice hints
- Create a test image, view it in Explorer's Extra-Large thumbnails, delete the image, and re-open Explorer. Confirm the thumbnail still renders for the now-missing file.
- Use Thumbcache Viewer to bulk-export every thumbnail from a suspect's profile. Grep the idx DB for specific paths of interest.
- For removable-media correlation, cross-reference entry hashes against paths like `F:\*` to identify files viewed from drive letters that are no longer mounted.
