---
name: VolumeGUID
kind: identifier
lifetime: permanent
link-affinity: device
description: |
  Globally unique volume identifier assigned by Windows Mount Manager on
  volume mount. Uniquely identifies a specific volume (partition-plus-
  filesystem) across sessions. Does not necessarily survive reformatting.
canonical-format: "{8-4-4-4-12 hex GUID}"
aliases: [VolumeId, volume-guid, Mount-Manager-GUID]
roles:
  - id: mountedVolume
    description: "Volume GUID as captured at the system mount level (MountedDevices, Partition/Diagnostic)"
  - id: accessedVolume
    description: "Volume GUID as captured in per-user access artifacts (MountPoints2, shellbags, LNK target chain)"

known-containers:
  - MountedDevices
  - MountPoints2
  - PartitionDiagnostic-1006
  - ShellBags
  - ShellLNK
provenance:
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
  - carrier-2005-file-system-forensic-analysis
---

# Volume GUID

## What it is
A GUID the Windows Mount Manager assigns when a volume first mounts. Functions as a volume-scoped identifier independent of drive letter — drive letters change between mounts; the volume GUID does not (within a volume's lifetime).

## Forensic value
Central pivot for bridging device-identity artifacts (USBSTOR, Partition/Diagnostic) with user-scope artifacts (MountPoints2 subkey names, shellbags, jump lists, LNK files). When a volume-GUID string appears in a per-user artifact AND in MountedDevices' binding-data chain, the user's interaction with that physical device is established.

## Encoding variations

| Artifact | Where |
|---|---|
| MountedDevices | value name of form `\??\Volume{<GUID>}` |
| MountPoints2 | subkey name of form `{<GUID>}` (curly-braced, no prefix) |
| Partition/Diagnostic 1006 | event field `VolumeId` as GUID structure |
| ShellBags | embedded in BagMRU binary data (shell-item list) |
| ShellLNK | embedded in target path shell-item list |
| Prefetch | volume-GUID appears in path strings when executable was launched from a non-C: volume |
