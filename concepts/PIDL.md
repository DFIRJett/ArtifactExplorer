---
name: PIDL
kind: identifier
lifetime: persistent
link-affinity: file
description: |
  Shell Item ID List — a serialized pointer-to-item-ID-list structure
  (ITEMIDLIST) that encodes a location in the Windows shell namespace
  as a chain of variable-length shell items. The canonical "what folder
  or file was referenced" payload shared across Explorer browsing state,
  file-dialog state, shortcut targets, and jump list destinations. Also
  known as a Shell Item in the LNK specification context.
canonical-format: "binary blob of concatenated ITEMIDLIST entries; null-terminated; interior items carry FAT/DOSDate MAC timestamps and MFT entry+sequence references on NTFS"
aliases: [ITEMIDLIST, Shell Item, Shell Item ID List, Shell-PIDL]
roles:
  - id: browsedItem
    description: "PIDL captured as a folder the user browsed via the Explorer shell (ShellBags BagMRU numbered values)"
  - id: dialogItem
    description: "PIDL captured as a file/folder referenced through a standard Open/Save file dialog (OpenSavePidlMRU, LastVisitedPidlMRU)"
  - id: linkedItem
    description: "PIDL captured as the target Shell Item chain embedded in a .lnk file (LNK Shell Item IDList) or in a jump list DestList entry"

known-containers:
  # User-interaction browsing artifacts
  - ShellBags
  # File-dialog artifacts
  - OpenSavePidlMRU
  - LastVisitedPidlMRU
  # Shortcut / jump list embedded-PIDL artifacts
  - Recent-LNK
  - OfficeRecent-LNK
  - Desktop-LNK
  - Startup-LNK
  - BrowserDownload-LNK
  - NetworkShare-LNK
  - ShellLNK
  - AutomaticDestinations
  - CustomDestinations
  - JumpList-Embedded-LNK
  - JumpList-DestList-Entry
provenance:
  - ms-shllink
  - libyal-libfwsi
  - libyal-liblnk
---

# PIDL (Shell Item ID List)

## What it is

A **PIDL** (pointer to an ITEMIDLIST) is the shell namespace's canonical way to reference a location. Structurally: a concatenation of SHITEMID items, each with its own length prefix and type-specific payload, terminated by a null item. In-memory it's a pointer chain; on-disk (the only form relevant for forensics) it's a serialized binary blob.

A PIDL interior item for a filesystem object typically carries:

- file or folder name (short-name or long-name depending on shell version)
- FAT/DOSDate MAC timestamps (2-second precision)
- file size (for file items)
- on NTFS, the **MFT entry number + sequence number** of the referenced object (added starting Vista)
- extension-dependent sub-blocks (e.g., for `.lnk` items the embedded LNK data)

The structure is how the shell passes "a thing" around — you can focus a folder, add it to a jump list, or persist it to a .lnk file and the PIDL is the glue that encodes what "that thing" actually is.

## Why it's a join key

The same PIDL — byte-for-byte, or close to it — gets persisted across multiple artifact classes when the user touches an item. PIDL-equality across artifacts is an `Established` corroboration join that simultaneously proves:

1. **Which user** referenced the item (parent NTUSER.DAT or UsrClass.dat hive owner)
2. **Which path** was referenced (decoded from the PIDL's filesystem-item interior)
3. **Which MFT entry + sequence** on the source volume (directly readable from the PIDL on NTFS)
4. **What FAT/DOSDate MAC times** the item had at the moment of capture

## How different artifacts carry PIDL

| Artifact | Where | What the PIDL represents |
|---|---|---|
| **ShellBags** | BagMRU numbered `REG_BINARY` values | a folder the user browsed in Explorer |
| **OpenSavePidlMRU** | per-extension subkey numbered values | a file opened/saved via a standard file dialog |
| **LastVisitedPidlMRU** | numbered values | the last folder each executable visited via a file dialog |
| **LNK files** (Recent, Office, Desktop, etc.) | LinkTargetIDList block | the target Shell Item chain of the shortcut |
| **AutomaticDestinations / JumpList entries** | DestList entry's embedded LNK data | a recently-used file per application |
| **CustomDestinations** | embedded LNK records | pinned or custom jump list items |

## Parsing

PIDL binary is not human-readable — parsers that understand the SHITEMID variants (filesystem item, network share, control panel, etc.) are required. The canonical tools:

- **ShellBagsExplorer / SBECmd** (Zimmerman) — decodes ShellBags PIDLs
- **LECmd** (Zimmerman) — decodes LNK LinkTargetIDList
- **JLECmd** (Zimmerman) — decodes jump list embedded PIDLs
- Custom PIDL parsers for OpenSavePidlMRU / LastVisitedPidlMRU values

Raw-byte comparison across artifacts is imprecise because embedded DOSDate fields can differ by a few seconds even for "the same" item captured at two slightly-different moments. Compare on: **decoded path + MFT entry + sequence**, not raw bytes.

## Forensic value

- **Strongest cross-mechanism user-interaction corroboration.** A path appearing in ShellBags (Explorer browsing) AND OpenSavePidlMRU (file dialog) AND an LNK target establishes three independent interaction pathways recorded the same item.
- **Persists after source-file deletion.** The PIDL encodes the MFT entry + sequence. If the source file is deleted and the MFT entry is reused for a different file, the sequence number mismatches — a clean deletion signal.
- **Bridges system-scope device evidence to user-scope file evidence.** A PIDL referencing a removable volume's drive letter (`E:\...\foo.xlsx`) found in per-user artifacts, joined with MountedDevices's volume-to-device mapping, completes the device→user→file chain.

## Limitations

- **Raw bytes are not canonically stable.** Compare on decoded fields, not binary equality.
- **Not all shell interactions produce a PIDL.** Command-line file access, drag-and-drop in some contexts, and programmatic API calls may not populate shell-side state.
- **MFT-entry encoding only on NTFS.** FAT volumes produce PIDLs without MFT entries; FAT DOSDate times become the primary comparison axis.

## Not exit-node
PIDL is a plumbing identifier — a way to encode a location reference. It terminates to a shell namespace item (usually a path on a volume). Pair with the volume identity (FilesystemVolumeSerial, VolumeGUID) and the MFT reference (MFTEntryReference) to resolve the referenced item fully.
