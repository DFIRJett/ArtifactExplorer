---
name: windows-ntfs-metadata
kind: filesystem-metadata
substrate-class: Filesystem/Metadata
aliases: [NTFS metafile, $MFT family, NTFS system files]

format:
  filesystem: NTFS
  metafiles:
    $MFT:     "master file table — one record per file/folder on the volume"
    $LogFile: "journal — recent transactions (~64MB rolling)"
    $UsnJrnl: "USN (update sequence number) journal — rolling per-file change log"
    $Secure:  "security descriptor storage (deduplicated ACLs)"
    $Bitmap:  "cluster allocation map"
    $BadClus: "list of bad clusters"
    $Boot:    "boot sector + BPB (includes FilesystemVolumeSerial)"
    $Extend:  "container for $UsnJrnl, $Reparse, $ObjId, etc."
  authoritative-spec:
    - title: "NTFS specification"
      author: Richard Russon / Anton Altaparmakov (linux-ntfs project)
      note: "no official Microsoft public spec; community-derived from observation"

structure:
  mft-record:
    size-bytes: 1024 (typical; can be 4096 on some volumes)
    attributes:
      "$STANDARD_INFORMATION (0x10)":  "MACB timestamps, DOS attributes, owner SID"
      "$ATTRIBUTE_LIST (0x20)":        "list of attributes when they don't fit resident"
      "$FILE_NAME (0x30)":             "filename + parent MFT ref + second set of MACB timestamps"
      "$OBJECT_ID (0x40)":             "GUID file identifier"
      "$SECURITY_DESCRIPTOR (0x50)":   "inline ACL (pre-NTFS3 or legacy)"
      "$VOLUME_NAME (0x60)":           "volume label (on $MFT record 3 = $Volume)"
      "$VOLUME_INFORMATION (0x70)":    "NTFS version, dirty flag"
      "$DATA (0x80)":                  "file contents (resident or non-resident)"
      "$INDEX_ROOT (0x90)":            "for directories — index of children"
      "$INDEX_ALLOCATION (0xA0)":      "non-resident directory index"
      "$BITMAP (0xB0)":                "allocation bitmap (for directory indexes or $MFT itself)"
      "$REPARSE_POINT (0xC0)":         "symlinks, junctions, deduplication pointers"
  addressing:
    scheme: MFT-entry-number + sequence-number
    uniqueness: "entry number stable across the life of the volume; sequence increments on record reuse"

persistence:
  acquisition:
    - "raw disk image (FTK Imager, dd, X-Ways) — the canonical source"
    - "live `fsutil usn` for USN journal extraction"
    - "VSS for historical snapshots"
    - "EnCase / X-Ways for interpreted MFT views"
  locked-on-live-system: yes (metafiles) — requires raw-disk access
  parsers:
    - { name: analyzeMFT, strengths: [per-record breakdown, Python] }
    - { name: MFTECmd, strengths: [bulk CSV/JSON export, Eric Zimmerman] }
    - { name: The Sleuth Kit (fls, istat), strengths: [carving + timeline] }
    - { name: X-Ways Forensics, strengths: [commercial, interpreted view] }

forensic-relevance:
  - lifecycle-ground-truth: "$MFT is the authoritative source of file creation, modification, access, and MFT-change timestamps. All other artifacts referencing MFT records are pointers into this structure."
  - deleted-record-recovery: "deleted files remain in $MFT (marked unallocated) until the slot is reused; recovery is often possible well after logical deletion"
  - timeline-anchor: "combined with USN Journal and $LogFile, provides minute-by-minute filesystem activity reconstruction (super-timeline via plaso)"

integrity:
  signing: none
  tamper-vectors:
    - "direct offline MFT edit with raw-disk tools"
    - "timestamp manipulation via tools like timestomp (modifies $SI; $FN is harder to alter without kernel access)"
    - "secure-delete tools (sdelete) that overwrite data and wipe MFT timestamps"
  detection-cues:
    - "$SI timestamps more recent than $FN timestamps is usually benign (normal file write); $FN timestamps more recent than $SI is suspicious (possible timestomp)"
    - "timestamps with non-zero but suspiciously round values (e.g., 2000-01-01 00:00:00) indicate default-zeroing"

known-artifacts:
  # NTFS metadata substrate: hidden `$`-prefixed system files at the root of
  # each NTFS volume, plus per-file ADS structures. The Triforce methodology
  # (MFT + LogFile + UsnJrnl) is foundational; other metadata files add
  # targeted evidence (directory-index slack, reparse points, ACL history).
  # Seed source: authored + David Cowen Triforce research, SANS FOR500,
  # Brian Carrier "File System Forensic Analysis".
  authored:
    - MFT                      # $MFT — master file table
    - UsnJrnl                  # $UsnJrnl:$J + :$Max — change journal
    - Zone-Identifier-ADS      # ADS recording download origin (Mark-of-the-Web)
  unwritten:
    - name: LogFile
      location: $LogFile (root of NTFS volume)
      value: transaction journal — redo/undo records per-transaction; recovers recent-past file operations and reveals incomplete transactions
    - name: I30-Index
      location: $INDEX_ALLOCATION stream on directory MFT records
      value: directory-index slack retains deleted filenames even after MFT-record reuse; pre-eminent slack-space recovery target
    - name: ObjId
      location: $Extend\$ObjId
      value: NTFS object identifiers referenced by LNK DistributedLinkTracker; cross-volume file tracking
    - name: Reparse
      location: $Extend\$Reparse
      value: reparse-point catalog (junctions, symlinks, volume mount points, dedup stubs, OneDrive placeholder files)
    - name: Secure-SDS
      location: $Secure:$SDS
      value: security-descriptor stream history; historical ACL state rarely examined but material in insider cases
    - name: Volume-VolumeLabel
      location: $Volume record ($VOLUME_NAME + $VOLUME_INFORMATION attributes)
      value: volume label, version, dirty-flag, objectid — drive-wide metadata pivot
    - name: Boot
      location: $Boot
      value: NTFS boot record — cluster size, MFT location, volume serial; required to interpret other metadata correctly
    - name: Bitmap
      location: $Bitmap
      value: cluster allocation bitmap — essential for carving and unallocated-space recovery
    - name: Extend-Quota
      location: $Extend\$Quota
      value: per-user disk quota records — evidence of user activity volume
    - name: AlternateDataStream-Generic
      location: any file with NamedStream ADS
      value: ADS-based data hiding beyond Zone-Identifier (e.g., encrypted payloads, dual-use binaries)
provenance:
  - carrier-2005-file-system-forensic-analysis
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - libyal-libusnjrnl-usn-journal-format-max-header
  - ms-change-journal-record-header-fsctl
  - ms-ntfs-extended-attributes-file-syste
  - ms-ntfs-on-disk-format-secure-system-f
---

# NTFS Metadata

## Forensic value
The substrate under every other file/folder artifact on Windows NTFS volumes. $MFT records are the authoritative lifecycle history — anything else that claims a file existed at a time is, ultimately, a reference into or pointer at an $MFT record.

The dual-timestamp system ($STANDARD_INFORMATION + $FILE_NAME, each with four timestamps = 8 per file record) is the foundation of forensic timeline analysis. The $SI set is user-writable (via timestomp-style attacks); the $FN set requires kernel access to modify and so is more authoritative.

## Addressing scheme
Records are identified by entry number (48-bit) + sequence number (16-bit) — the `MFTEntryReference` concept. The combination forms a durable pointer across the volume's lifetime.

## Relationship to other containers
- **ShellBags, ShellLNK, jump lists, Prefetch** all embed MFT entry references to the files they track.
- **$UsnJrnl and $LogFile** reference MFT entries for change-tracking.
- **USN Journal** (inside $Extend\$UsnJrnl) is a rolling per-file change log with MFT entry references.

## Practice hint
Image a test USB with FTK Imager. Parse $MFT with MFTECmd. Pick an entry — note its $SI and $FN timestamps. Open the file in Explorer (which updates $SI.accessed). Re-parse; observe $SI.accessed changed, $FN unchanged. That asymmetry is why $FN is "more authoritative" for timeline claims.
