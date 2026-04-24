---
name: EMDMgmt
aliases:
- External Memory Device Management
- ReadyBoost volume enumeration
- ReadyBoost cache registry
link: device
tags:
- tamper-easy
- timestamp-carrying
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
    note: Server SKUs do not enable ReadyBoost — enumeration subkeys are still created on Server 2008/2012 but may be absent on 2016+; verify per-host
location:
  hive: SOFTWARE
  path: Microsoft\Windows NT\CurrentVersion\EMDMgmt\<volume-identifier-string>
  addressing: hive+key-path
  acquisition-notes: 'Live system: SOFTWARE hive is open and NOT copyable via simple file copy —

    use `reg save HKLM\SOFTWARE software.hiv` or VSS-shadow. Offline image:

    copy `%WINDIR%\System32\config\SOFTWARE` directly. Do NOT skip the

    transaction logs (SOFTWARE.LOG1, SOFTWARE.LOG2) — they retain evidence

    of recently-deleted EMDMgmt subkeys.

    '
fields:
- name: volume-identifier-string
  kind: identifier
  location: subkey name — long composite string embedding DeviceSerial + VolumeLabel + FilesystemVolumeSerial
  encoding: ascii
  references-data:
  - concept: DeviceSerial
    role: usbDevice
  - concept: VolumeLabel
    role: deviceLabel
  - concept: FilesystemVolumeSerial
    role: runtimeSerial
  note: "Canonical format (Vista–11):\n  _??_USBSTOR#Disk&Ven_<Vendor>&Prod_<Product>&Rev_<Revision>#<USBSTOR-Instance-ID>#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}<VolumeLabel>_<VolumeSerialDecimal>\nFour\
    \ extractable identifiers in ONE subkey name:\n  (1) USBSTOR instance id — the hardware serial (or OS-synthesized &0 suffix)\n  (2) Class GUID {53f56307-...} — DiskDrive class, constant\n  (3) VolumeLabel\
    \ — shell-visible label at evaluation time\n  (4) VolumeSerial — DECIMAL uint32 (NOT hex); convert to hex to join other artifacts\nParser: split on '#' then on final two '_' (VolumeLabel may contain\
    \ embedded _).\nThe safest parse is to anchor on the trailing digits (VolumeSerial) and the class-GUID.\n"
- name: volume-label
  kind: identifier
  location: subkey name — segment between final class-GUID and final '_<decimal>'
  encoding: ascii
  note: Duplicated link to VolumeLabel from the composite string, broken out for parser clarity. Shell-visible volume label at ReadyBoost evaluation time.
- name: volume-serial-number
  kind: identifier
  location: final numeric segment of the subkey name (after the last '_')
  encoding: 'decimal (NOT hex) — EMDMgmt stores the FS VSN as a decimal integer (uint32). Other artifacts (LNK, Prefetch, Partition/Diagnostic Vbr0) store it hex. Convert for cross-artifact join: dec→hex,
    zero-pad to 8 chars, format XXXX-XXXX.'
  note: 'Common parser pitfall. Example: EMDMgmt value `3472651852` converts to

    hex `0xCF08D94C` → conventional display `CF08-D94C`. That hex form is

    what appears in LNK `DriveSerialNumber`, Prefetch volumes section, and

    Partition/Diagnostic-1006 Vbr0 offset 0x48/0x43/0x64.

    '
- name: usbstor-serial
  kind: identifier
  location: subkey name — segment after `USBSTOR#Disk&Ven_...&Prod_...&Rev_...#` and before the next `#{classGUID}`
  encoding: ascii
  note: Broken out for parser clarity. Matches the <InstanceID> in USBSTOR keys byte-for-byte. If 2nd char is '&' the serial is OS-synthesized (not device-firmware reported) — same rule as USBSTOR.
- name: cache-status
  kind: enum
  location: subkey value `CacheStatus`
  type: REG_DWORD
  encoding: uint32
  note: "ReadyBoost eligibility/configuration status for this volume.\nCommon observed values (not all publicly documented):\n  0 = not evaluated / pending\n  1 = eligible + enabled (ReadyBoost cache active)\n\
    \  2 = eligible but not configured\n  3 = ineligible\nPresence of this value = Windows ran the ReadyBoost test on this device.\n"
- name: cache-size-bytes
  kind: counter
  location: subkey value `CacheSizeInBytes`
  type: REG_QWORD
  encoding: uint64
  note: Active ReadyBoost cache size in bytes. Non-zero only when cache-status = 1. Forensically secondary — indicates cache configuration.
- name: device-status
  kind: enum
  location: subkey value `DeviceStatus`
  type: REG_DWORD
  encoding: uint32
  note: Per-device ReadyBoost eligibility result. Distinct from cache-status — one is device eligibility, the other is cache state.
- name: read-speed-kbs
  kind: counter
  location: subkey value `ReadSpeedKBs`
  type: REG_DWORD
  encoding: uint32 — read throughput in KiB/s observed during ReadyBoost performance test
  note: Kernel-measured device read performance. Forensically circumstantial but can distinguish flash classes (USB 2.0 ~20-40 MB/s, USB 3.0 ~80-200 MB/s).
- name: write-speed-kbs
  kind: counter
  location: subkey value `WriteSpeedKBs`
  type: REG_DWORD
  encoding: uint32
  note: Kernel-measured device write throughput. Together with read-speed, fingerprints the device performance profile.
- name: physical-device-size
  kind: counter
  location: subkey value `PhysicalDeviceSize`
  type: REG_QWORD
  encoding: uint64 — device capacity in bytes
  note: 'Byte-accurate device capacity. Cross-references Partition/Diagnostic-1006

    EventData\Capacity for the same device. Two devices with matching USB

    vendor/product/revision but different PhysicalDeviceSize values are

    genuinely different hardware.

    '
- name: failure-reason
  kind: enum
  location: subkey value `FailureReason` (present when device failed ReadyBoost test)
  type: REG_DWORD
  encoding: uint32
  note: Reason code for ReadyBoost ineligibility — e.g., too small, too slow, on system drive. Presence at all = Windows evaluated the device. Absence could mean pass OR never-evaluated.
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: set-on-any-value-change-within-key
  note: 'Subkey last-write time corresponds to when ReadyBoost last updated

    this device''s entry — typically first evaluation on initial plug-in,

    re-evaluation if device characteristics changed, or cache reconfiguration.

    NOT a per-connection timestamp like USBSTOR''s FIRST/LAST INSTALL.

    '
observations:
- proposition: CONNECTED
  ceiling: C3
  note: 'EMDMgmt subkey existence + key-last-write establishes "Windows evaluated

    this specific device for ReadyBoost at time T" — which requires the

    device to have been plugged in long enough for the performance test

    (~30 seconds minimum on modern Windows). Ceiling C3 because the subkey

    name uniquely identifies the device via USBSTOR-matching serial + VSN;

    tamper requires direct SOFTWARE-hive offline edit and leaves transaction

    log evidence.

    '
  qualifier-map:
    peer.device-serial: field:usbstor-serial
    peer.volume-label: field:volume-label
    peer.volume-serial: field:volume-serial-number
    peer.capacity: field:physical-device-size
    time.start: field:key-last-write
    time.end: field:key-last-write
  preconditions:
  - SOFTWARE hive retained
  - Anti-forensic cleaner did not target EMDMgmt (most do not)
- proposition: EXISTS
  ceiling: C3
  note: Subkey name carries enough device-identity substance (USB serial + VSN + label + capacity) to establish the device existed in this filesystem-formatted state at evaluation time.
  qualifier-map:
    entity.device-serial: field:usbstor-serial
    entity.volume-serial: field:volume-serial-number
    entity.capacity: field:physical-device-size
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  audit-trail: 'SOFTWARE hive transaction logs (SOFTWARE.LOG1, SOFTWARE.LOG2) retain

    evidence of recently-deleted EMDMgmt subkeys. `yarp-print` (yarp toolkit)

    or regipy''s `transaction_log_analyzer` can extract. Registry Explorer

    also replays transaction logs.

    '
  known-cleaners:
  - tool: USBOblivion (1.16+)
    typically-removes: true
    note: Explicit EMDMgmt target added in 1.16; earlier versions miss it.
  - tool: USBOblivion (pre-1.16)
    typically-removes: false
  - tool: CCleaner
    typically-removes: false
    note: CCleaner's registry cleaner targets HKCU primarily; EMDMgmt is HKLM and consistently survives.
  - tool: Privazer
    typically-removes: partial
  - tool: manual reg.exe delete
    typically-removes: true
  survival-signals:
  - EMDMgmt subkey present + USBSTOR entry absent = USBSTOR-specific cleaner (pre-1.16 USBOblivion, custom script) hit Enum\USBSTOR but missed EMDMgmt. HIGH-CONFIDENCE cleanup-attempt signal.
  - EMDMgmt transaction-log entry exists but live subkey gone = EMDMgmt was recently deleted. Cross-check hive SOFTWARE.LOG1 within last few days.
  - EMDMgmt subkey for device X + no MountPoints2\<VolumeGUID> for same X under any NTUSER = device plugged in at machine scope but never mounted into a user session (rare; worth investigating)
provenance:
- aboutdfir-nd-usb-devices-windows-artifact-r
- hedley-2024-usbstor-install-first-install
---

# EMDMgmt (ReadyBoost Volume Enumeration)

## Forensic value
The single most concentrated USB-identity artifact in the Windows registry. A single EMDMgmt subkey NAME embeds **four** forensically-pivotal identifiers:

1. **USBSTOR instance-id** (→ `DeviceSerial` concept) — the hardware serial
2. **VolumeLabel** (→ `VolumeLabel` concept) — shell-visible label at evaluation time
3. **FilesystemVolumeSerial** (→ `FilesystemVolumeSerial` concept) — decimal-encoded FS VSN
4. **Device class GUID** — constant, but confirms "this was a disk drive"

Plus subkey values that add:
5. **PhysicalDeviceSize** — byte-accurate capacity (cross-references Partition/Diagnostic-1006 Capacity)
6. **ReadSpeedKBs / WriteSpeedKBs** — kernel-measured performance fingerprint
7. **Key last-write time** — first evaluation (typically == first-connection within ~30 seconds)

No other single registry location combines device serial + volume label + filesystem serial + capacity. That's what makes EMDMgmt a high-density identity anchor.

Ceiling: C3. Subkey name is a composite string resistant to partial tamper (editing one segment breaks parser-alignment without matching cleanup elsewhere); transaction log retains deletion evidence. Not C4 — admin can still offline-edit the whole hive.

## Why it's overlooked and why that's useful
ReadyBoost itself is obsolete. Since Windows 8, systems with ≥4GB RAM skip active ReadyBoost caching entirely. Analysts accustomed to "ReadyBoost is dead" often skip EMDMgmt — but **the enumeration still happens**. Windows still tests every attached USB device for eligibility, still creates the subkey, still records the composite-name identity, even on systems that will never use the cache.

That obscurity is a feature, not a bug. Consumer registry cleaners track popular forensic artifacts (USBSTOR, MountPoints2, shell bags, jump lists). They routinely miss EMDMgmt. Older USBOblivion versions (pre-1.16) don't touch it at all. When the headline USB artifacts have been wiped and USBSTOR is empty, EMDMgmt frequently still holds the full device roster.

## Subkey name parser recipe

```
Format: _??_USBSTOR#Disk&Ven_<V>&Prod_<P>&Rev_<R>#<InstanceID>#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}<Label>_<VsnDecimal>

Parsing steps:
  1. Strip leading  _??_USBSTOR#Disk
  2. Split on #  →  [ &Ven_<V>&Prod_<P>&Rev_<R>,  <InstanceID>,  {GUID}<Label>_<VsnDecimal> ]
  3. On segment[0]: split on & → extract Ven_*, Prod_*, Rev_*
  4. segment[1] IS the USBSTOR InstanceID (direct match to Enum\USBSTOR\<ven&prod>\<instance>)
  5. On segment[2]: strip leading {53f56307-...} → remainder is <Label>_<VsnDecimal>
  6. From remainder: split on LAST underscore → VolumeLabel (may contain '_'), VsnDecimal
  7. Convert VsnDecimal to uint32 hex, format XXXX-XXXX for cross-artifact join
```

## Cross-references

| Joined to | Via | How |
|---|---|---|
| **USBSTOR** | InstanceID substring | Byte-identical match to Enum\USBSTOR\<ven&prod>\<instance> key name |
| **MountedDevices** | InstanceID substring | MountedDevices binding-data Format 1 contains this InstanceID as UTF-16LE |
| **MountPoints2** | VolumeGUID | Indirect — MountedDevices resolves InstanceID → VolumeGUID, MountPoints2 keyed on VolumeGUID |
| **Partition/Diagnostic-1006** | Capacity field | `PhysicalDeviceSize` value == EventData\Capacity for same device |
| **ShellLNK / ShellBags / jump lists** | VSN | Convert VsnDecimal → hex; match to LNK DriveSerialNumber / shell-item serial |
| **FAT32-Boot / exFAT-Boot / $Boot** | VSN | Same decimal-to-hex conversion; boot-sector VSN is the authoritative source |

## Parsers

| Tool | Strengths |
|---|---|
| RegRipper (`emdmgmt.pl` by Harlan Carvey) | Canonical parser. Decomposes subkey name, reports all values. Works on offline SOFTWARE hive. |
| Registry Explorer (Eric Zimmerman) | GUI browsing + transaction-log replay to recover deleted subkeys. |
| `regipy` (Python) | Programmatic access. Pair with `regipy.plugins.software.emdmgmt` where available, or iterate subkeys manually. |
| `yarp` (libyal) | Python library for hive + transaction-log parsing. `yarp-print -r` on SOFTWARE.LOG1 recovers deleted EMDMgmt subkeys. |
| KAPE targets | `RegistryHives_System` collects SOFTWARE + logs; EMDMgmt falls out for offline analysis. |

## Known quirks

- **Subkey name IS the data.** Unlike normal registry artifacts where values carry the content, EMDMgmt's forensic payload is the subkey NAME. Values are ReadyBoost metrics (useful but secondary). Don't skip the name parse.
- **VsnDecimal ↔ VsnHex conversion.** THE most common analyst mistake. EMDMgmt stores `3472651852`; LNK stores `CF08D94C`. Both are the same VSN. Always convert before cross-referencing.
- **Label segment may contain underscores.** `TESTVOL_BACKUP_3472651852` — split on the LAST `_`, not the first. Volume labels on FAT32/exFAT are ASCII and may contain any filename-legal character including underscore.
- **Unlabeled volumes produce `_<decimal>` with empty label**. The parser must handle zero-length labels: `{53f56307-...}_3472651852` is valid and means "no label set."
- **Class GUID is always `{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`** (GUID_DEVCLASS_DISKDRIVE). If you see a different GUID, it's not a USB-disk entry — EMDMgmt occasionally holds entries for other removable-storage classes on older Windows versions.
- **Windows 11 behavior**: still creates the subkey, still populates identity fields, may skip most ReadyBoost DWORD values (CacheStatus, ReadSpeedKBs) on systems where ReadyBoost is disabled. The identity data survives regardless.

## Anti-forensic assessment
USBOblivion 1.16+ explicitly targets EMDMgmt; older versions and most other cleaners do not. CCleaner never does (HKCU-focused). This uneven coverage means EMDMgmt is frequently THE surviving USB-identity artifact after consumer cleanup.

The transaction-log recovery path (`SOFTWARE.LOG1`, `SOFTWARE.LOG2`) extends EMDMgmt's forensic life beyond simple reg.exe deletions. On a Windows 10/11 system with default hive-dirty-page flushing, the logs typically retain 30-60 minutes of pre-delete state, sometimes longer.

## Practice hint

- **Live system**: `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt" /s > emdmgmt.txt`. Inspect — every subkey name is one USB device.
- **Parse a subkey name by hand**. Pick one; extract USB serial, volume label, VSN-decimal. Convert VSN-decimal to hex; run `vol X:` on a currently-mounted USB and compare (if the device is still plugged in).
- **Cross-reference**: for the same device, check `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` for the matching InstanceID — it should appear as a subkey under the `Disk&Ven_*&Prod_*&Rev_*` parent.
- **Test survival**: run CCleaner registry clean on a test VM → confirm EMDMgmt subkeys remain. Run USBOblivion (fresh version) → confirm they're gone. The difference IS the forensic signal.
- **Transaction log recovery**: delete a test EMDMgmt subkey via reg.exe. Immediately copy SOFTWARE + SOFTWARE.LOG1 offline. Run `yarp-print -r SOFTWARE.LOG1` — the deleted subkey name should be recoverable.

## Corroboration ceiling note
EMDMgmt alone is C3. Paired with USBSTOR (same InstanceID substring, tamper-independent source), composite CONNECTED rises to C4. Paired with USBSTOR + Partition/Diagnostic-1006 (three independent tamper-paths agreeing on the same device), C5 is achievable — the maximum this schema permits for non-cryptographic USB attribution.
