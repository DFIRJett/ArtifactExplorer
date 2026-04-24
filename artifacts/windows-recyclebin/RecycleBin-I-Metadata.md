---
name: RecycleBin-I-Metadata
aliases:
- $I metadata file
- recycle-bin index file
link: file
tags:
- per-user
- tamper-easy
- deletion-timeline
volatility: persistent
interaction-required: user-action
substrate: windows-recyclebin
substrate-instance: "$I<token> per deleted item"
substrate-hub: User scope
platform:
  windows:
    min: Vista
    max: '11'
location:
  path: "%SystemDrive%\\$Recycle.Bin\\<SID>\\$I<random>"
  pair-partner: "$R<random> with matching token (content file)"
  addressing: filesystem-path-per-SID
fields:
- name: format-version
  kind: flag
  location: first byte of $I
  note: 0x01 for Vista/7/8/8.1, 0x02 for Win10+
- name: original-size
  kind: size
  location: $I header offset 0x08
  type: uint64-le
- name: deletion-time
  kind: timestamp
  location: $I header offset 0x10
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: set at the moment the file was moved to Recycle Bin
- name: original-path
  kind: path
  location: $I header offset 0x18 (v1 = fixed 520 bytes, v2 = path-length prefix + variable)
  encoding: UTF-16LE
  note: full filesystem path the file occupied before deletion
- name: deleting-user-sid
  kind: identifier
  location: parent folder name ($Recycle.Bin\<SID>)
  note: the SID of the account that deleted the file — cryptographically bound via folder ownership
  references-data:
  - concept: UserSID
    role: actingUser
observations:
- proposition: DELETED
  ceiling: C4
  note: High-confidence deletion record. The $I file is written at deletion time with original-path, size, timestamp, and the deleting user's SID via the folder hierarchy. Cannot be trivially forged without SID-context access.
  qualifier-map:
    actor.user.sid: field:deleting-user-sid
    object.file.path: field:original-path
    object.file.size: field:original-size
    time.deleted: field:deletion-time
anti-forensic:
  write-privilege: user
  known-cleaners:
  - tool: Explorer 'Empty Recycle Bin'
    typically-removes: full (but often recoverable from unallocated)
  - tool: Shift+Delete during deletion
    typically-removes: bypasses — no $I/$R created
  - tool: manual $I edit
    typically-removes: version-byte or path corruption detectable
provenance:
  - ms-how-the-recycle-bin-stores-files-in
---

# RecycleBin-I-Metadata

## Forensic value
Windows writes one `$I<token>` file in `$Recycle.Bin\<SID>\` every time a user moves a file to the Recycle Bin. The metadata is small, structured, and forensically authoritative:

- **Original path** — where the file was before deletion
- **Original size** — byte length at deletion time
- **Deletion FILETIME** — the moment of the move-to-trash operation
- **Deleting SID** — encoded by the containing folder name, NOT inside the $I file itself. Per-user Recycle Bin folders are created by Windows with SID-specific ACLs; a $I file in `S-1-5-21-...-1001`'s folder was written by that user.

Paired with `$R<token>` (content copy), this gives complete recovery of the file with full attribution.

## v1 vs v2 format
- **Version 1** (Vista through Win8.1): fixed 544-byte record; path field is a fixed 520-byte UTF-16LE region, null-padded.
- **Version 2** (Win10+): variable-length path; 4-byte length prefix followed by the actual path bytes. Supports paths longer than 260 chars.

Parsers handle both; watch the version byte (`0x01` vs `0x02`) when doing manual hex walks.

## Shift+Delete does NOT produce $I/$R
If a file was removed via Shift+Delete, `del` command, or PowerShell `Remove-Item`, **no Recycle Bin artifact is created**. The deletion goes straight to the filesystem (USN journal entry, but no $I). When a user would normally Delete-key files but the Recycle Bin is empty for the relevant window, consider:
- Scripted deletion bypass
- Bin was manually emptied
- User actually performed Shift+Delete (behavior discrepancy worth interviewing)

## Orphaned $R without matching $I
If a `$R<token>` exists without its `$I` partner, the metadata was deleted (by tampering, failed write, or partial manual cleanup). The content is still recoverable but the deletion context is lost. Orphan ratio > 5% of the bin is itself a tampering signal.

## Cross-references
- **RecycleBin-R-Content** — the pair partner with actual file bytes
- **UsnJrnl** — records the rename operation that moved the file to `$Recycle.Bin\<SID>\` at deletion time; corroborates deletion-time FILETIME
- **Security-4663** — object-access audit on the Recycle Bin folder (if SACL set)

## Practice hint
```
RBCmd.exe -d <mount>\$Recycle.Bin --csv .
```
Parses all $I files across all SIDs into a timeline CSV. Pair with `RBCmd.exe -f <path-to-single-$I>` for targeted decode of a specific record.
