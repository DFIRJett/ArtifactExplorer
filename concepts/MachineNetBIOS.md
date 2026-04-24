---
name: MachineNetBIOS
kind: identifier
lifetime: persistent
link-affinity: system
link-affinity-secondary: device
description: |
  NetBIOS name of the machine whose Distributed Link Tracking service stamped
  an object (LNK file, jump list entry, etc.). Preserved even when the object
  is copied to another machine — making it one of the rare cross-host
  attribution artifacts on Windows.
canonical-format: "ASCII string, up to 15 characters, uppercase conventional"
aliases: [DLT-machine-id, TrackerDataBlock-MachineID, source-machine-name, link-tracker-name]
roles:
  - id: trackerMachineId
    description: "NetBIOS machine name from a LNK-format TrackerDataBlock — cross-host provenance"

known-containers:
  - ShellLNK
  - AutomaticDestinations
  - CustomDestinations
---

# Machine NetBIOS ID

## What it is
The NetBIOS computer name of the Windows host whose Distributed Link Tracking (DLT) service created or last "touched" a Shell Link or jump list entry. The DLT service writes this into a structure called `TrackerDataBlock` inside LNK-format objects, so the machine identity travels with the file.

Distinct from:
- **DNS hostname** — NetBIOS is truncated at 15 characters and historically distinct
- **Machine SID** — which is in SAM; not carried in shell artifacts

## Forensic value
One of the rare Windows artifacts that preserves *where a file came from* across copy operations. A LNK file whose TrackerDataBlock MachineID differs from the host the LNK was found on is evidence the LNK was created elsewhere and transplanted — common in:

- **User moving shortcut bundles between machines** (benign)
- **Attacker staging artifacts** on a jump-host (malicious)
- **Roaming profile replication** (benign — LNK has source machine of original profile host)
- **Recovered/carved LNKs** from external drives (investigative goldmine — the MachineID identifies the source system)

## Encoding variations

| Artifact | Where |
|---|---|
| ShellLNK | `ExtraData\TrackerDataBlock\MachineID` — 16-byte ASCII (NUL-padded) |
| AutomaticDestinations | per-entry LNK-format structures embed the same block |
| CustomDestinations | embedded LNK streams carry it |

## Known quirk
Some LNK parsers report only the first 15 bytes; others preserve up through the NUL terminator of the 16-byte field. Compare parser output when the MachineID string is unusual — truncation can change the interpretation.
