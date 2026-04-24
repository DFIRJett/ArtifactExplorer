---
name: windows-recyclebin
kind: binary-structured-file
substrate-class: Filesystem/Artifact
aliases: [Recycle Bin, $Recycle.Bin, $I/$R pair]

format:
  pair-structure:
    metadata-file:
      name: $I<random>
      holds: original-path + deletion-timestamp + original-size
      versions:
        - version: 1
          platform: Vista, 7, 8, 8.1
          header: 0x01 + size (8B) + deletion-FILETIME (8B) + path (UTF-16LE, 520B fixed)
        - version: 2
          platform: "10, 11"
          header: 0x02 + size (8B) + deletion-FILETIME (8B) + path-length (4B) + path (UTF-16LE, variable)
    content-file:
      name: $R<random>
      holds: verbatim renamed copy of the deleted file
      random-token: same 6-char base32 id pairs with the $I file
  authoritative-spec:
    - title: "Windows Recycle Bin format"
      author: Joachim Metz (libfwsi / libwrc research)
      note: format reverse-engineered; no Microsoft public spec

persistence:
  live-system-location:
    root: "%SystemDrive%\\$Recycle.Bin\\<SID>\\"
    per-user: yes (each SID gets its own subfolder)
    pre-Vista-alt: "C:\\RECYCLER\\<SID>\\INFO2 (single index file, different schema)"
  retention:
    policy: "until user 'Empty Recycle Bin' OR storage-pressure auto-cleanup OR per-file right-click delete"
    size-cap: "default 5-10% of volume, per-drive; configurable in UI"
  locked-on-live-system: partial (Explorer may hold references to in-view items)

parsers:
  - name: RBCmd (Eric Zimmerman)
    strengths: [bulk CSV export, v1/v2 parsing, batch folder mode]
  - name: Recbin / Kroll
    strengths: [GUI]
  - name: libfwsi / python-fwsi
    strengths: [programmatic access, library-quality]
  - name: fls / Sleuth Kit
    strengths: [can recover $I/$R from unallocated]

forensic-relevance:
  - user-attribution:
      scope: SID-scoped subfolder ties deletions to a specific local account
      caveat: requires SID→username resolution from SAM
  - deletion-timeline:
      scope: $I metadata carries deletion FILETIME (not the file's MAC timestamps)
      update-trigger: moved-to-recycle-bin action (Delete key or drag)
      NOT-captured: Shift+Delete (bypasses Recycle Bin entirely)
  - content-recovery:
      scope: $R holds the full file verbatim; recovery = copy-out
      caveat: $R is a FILE COPY at deletion time, not a link — filesystem MAC times reset
  - selective-survival:
      scope: '"Empty Recycle Bin" deletes $I and $R entries; carving from $Recycle.Bin folder unallocated often recovers both'
      caveat: SSD TRIM vs HDD zero-on-delete differs materially

integrity:
  signing: none
  tamper-vectors:
    - direct file deletion of $I (orphans $R — visible as $R without matching $I, itself a signal)
    - path spoofing via hex-edit of $I (detectable — $R filename is always random)
    - volume-level Shift+Delete to bypass entirely (no artifact created)

anti-forensic-concerns:
  - Attacker Shift+Delete OR script-delete bypasses Recycle Bin entirely; absence of expected entries is itself a signal when user behavior suggests normal deletes.
  - '"Empty Recycle Bin" from UI deletes $I/$R pairs but unallocated-space carving typically recovers them; commercial anti-forensic tools (BleachBit, CCleaner) may overwrite free space to defeat.'
  - Per-user SID folder naming ties deletions cryptographically — adversary cannot easily spoof another user's deletions without stealing that SID context.

known-artifacts:
  authored: []
  unwritten:
    - name: RecycleBin-I-Metadata
      location: "%SystemDrive%\\$Recycle.Bin\\<SID>\\$I<random>"
      value: deletion-timestamp + original-path + original-size per deleted file
    - name: RecycleBin-R-Content
      location: "%SystemDrive%\\$Recycle.Bin\\<SID>\\$R<random>"
      value: verbatim renamed copy of deleted file contents — full forensic recovery
    - name: RecycleBin-Orphan-R
      location: "$R file present with no matching $I"
      value: diagnostic signal — manual $I deletion or collection error; content still recoverable but context lost
    - name: RecycleBin-INFO2-Legacy
      location: "C:\\RECYCLER\\<SID>\\INFO2 (pre-Vista)"
      value: single-file index of all deleted items; occasionally present on upgraded systems
provenance:
  - ms-how-the-recycle-bin-stores-files-in
---

# Windows Recycle Bin

## Forensic value
When a user deletes via the standard Delete key or drag-to-trash, Windows moves the file into the volume-scoped Recycle Bin as a pair of files:
- `$I<token>` — a small metadata record holding the original path, original size, and deletion timestamp.
- `$R<token>` — a byte-for-byte copy of the deleted file, renamed to the same token.

The pairing is by filename token (6 random base32 characters). Each user SID gets a subfolder at `%SystemDrive%\$Recycle.Bin\<SID>\` — so deletions are cryptographically tied to the deleting account.

## Addressing within a Recycle Bin
An artifact here is identified by the pair (`$I<token>`, `$R<token>`). The SID folder is the container's per-user scope. For pre-Vista hosts, a single `INFO2` index file replaced $I/$R pairs — rare to encounter on modern systems but occasionally surfaces on long-upgraded boxes.

## What it does NOT capture
- **Shift+Delete** bypasses the Recycle Bin entirely — no artifact is created.
- **cmd `del` or PowerShell `Remove-Item`** by default bypass the Recycle Bin.
- **`rm -rf`-equivalent bulk scripts** skip it.

Absence of expected entries when user behavior suggests normal deletes is itself a forensic signal.

## Collection notes
Acquire the full `$Recycle.Bin\` directory per volume. Both `$I` and `$R` files are small-to-variable (content-proportional for $R). On live systems the folder is readable with normal admin rights. For best $I/$R pair recovery from unallocated, carve with Sleuth Kit `fls -r` or equivalent.

## Practice hints
- Use RBCmd (Eric Zimmerman) to bulk-parse a collected `$Recycle.Bin\` into CSV. Compare deletion-timestamps against `$UsnJrnl:$J` delete entries — they should align but often reveal staggered activity.
- Deliberately Shift+Delete a file on a test VM, then Delete a sibling file. Compare — one leaves no $I/$R trace, the other does.
- Orphan-$R detection: grep the folder for $R files without matching $I. These indicate tampering or partial cleanup.
