---
name: FILETIME100ns
kind: value-type
lifetime: persistent
link-affinity: timestamp
description: |
  Microsoft Windows FILETIME — a 64-bit unsigned integer counting
  100-nanosecond intervals since midnight UTC on January 1, 1601
  (Gregorian). The canonical timestamp encoding across the Windows
  kernel, filesystem ($MFT / $FILE_NAME timestamps), registry
  (key-last-write), event log ($TimeCreated), and most DFIR-relevant
  binary structures.
canonical-format: "uint64-le; value = 100-ns ticks since 1601-01-01T00:00:00Z UTC"
aliases: [FILETIME, FT100ns, WindowsFileTime, filetime-le, 100-nanosecond-interval-timestamp]
roles:
  - id: absoluteTimestamp
    description: "Point-in-time value recorded by a Windows subsystem (kernel, filesystem, event log, registry)"
  - id: durationDelta
    description: "Difference between two FILETIMEs — used for age / interval computations"
  - id: fractionalPrecisionSignal
    description: "Low-order 100-ns ticks as a forensic precision-vs-tool tell (see Galhuber 2022 timestomp research)"

known-containers:
  # All artifacts with filetime-le encoding on any timestamp field. Populated
  # across the corpus via references-data declarations on field entries.
  # Count: ~150+ artifacts. This is the most-shared value-type in the registry.
  - MFT
  - UsnJrnl
  - LogFile
  - Run-Keys
  - USBSTOR
  - Security-4624
  - Prefetch
  - Amcache-InventoryApplicationFile
  - ShellBags
  - Recent-LNK
  - ShellLNK
  # ... and many more; full list materializes via references-data on timestamp fields
provenance:
  - ms-ntfs-on-disk-format-secure-system-f
  - carrier-2005-file-system-forensic-analysis
  - libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
---

# FILETIME100ns

## What it is

The Windows kernel's 64-bit canonical timestamp format. A uint64 little-endian value counting 100-nanosecond intervals since **1601-01-01T00:00:00Z UTC**. Appears everywhere Windows records time: MFT records ($SI + $FN), registry key last-write timestamps, event log `System\TimeCreated`, prefetch first-run-time, hibernation file, kernel structures, tons of binary file formats, etc.

## Why 100-nanosecond ticks

The 100-ns granularity derives from the Windows kernel's timekeeping precision (the interrupt-timer tick resolution on original NT). Modern hardware exceeds this by orders of magnitude, but the 100-ns FILETIME is the lingua-franca forensic analysts cite when reasoning across artifacts.

## Resolution vs precision

**Critical tier-3 distinction** (Galhuber 2022 / H-001 item C):

- **Resolution** = granularity of the encoding (100-ns always)
- **Precision** = how accurately the recorded value reflects the actual event time

Different FILETIME consumers produce different precision:
- **Kernel-written** (MFT $FN, Security.evtx, Sysmon events): typically ±µs precision — the kernel writes at interrupt time
- **User-mode-written** (MFT $SI post-touch, registry LastWrite on many keys): ±ms-to-seconds precision — writes happen when the user-mode caller gets scheduled
- **Timestomped**: whatever the attacker set, often with zero-nanosecond fractional (see anti-forensic note below)

Quoting the 100-ns resolution doesn't mean ±100-ns precision. Timeline construction must account for this.

## Anti-forensic: the zero-nanosecond-fractional pattern

Per Galhuber 2022 (Univ. Vienna, peer-reviewed) — legitimate Windows operations produce FILETIME values with varied low-order 100-ns ticks. **Timestomp tools typically set timestamps to whole-second values** (e.g., `2023-01-01 12:00:00.0000000`), leaving zero-fraction fingerprints. A cluster of files with zero-nanosecond fractional components on $SI timestamps — especially when other indicators (parent-directory timestamp, $FN values, $LogFile LSN chain) disagree — is a strong timestomp detection signal.

Survives common evasions: the `rename-or-move` trick that defeats $SI/$FN comparison (by copying stomped $SI values into a new $FN on rename) still preserves zero-fractional values.

## Conversion hints (command-forward)

| Direction | Tool |
|---|---|
| FILETIME hex → ISO8601 UTC | PowerShell: `[DateTime]::FromFileTimeUtc(0x<hex>)` |
| FILETIME int → local datetime | `datetime(1601,1,1) + timedelta(microseconds=int/10)` (Python) |
| ISO8601 → FILETIME | `(DateTime.UtcNow - DateTime(1601,1,1)).Ticks` (C#) |
| Raw byte-swap | `w32tm /ntte <value>` ( value is 100ns ticks integer) |

## Practice hint

On a clean NTFS volume, create a file and parse its $MFT record with MFTECmd. Compare the four $SI timestamps against the four $FN timestamps — note how the fractional parts differ slightly even though the seconds agree (due to kernel write timing). Run a timestomp tool (e.g., SetMace for kernel-level or simpler user-mode tools for $SI only) — re-parse, observe zero-fractional fingerprint appear.
