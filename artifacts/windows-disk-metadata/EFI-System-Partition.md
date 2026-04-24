---
name: EFI-System-Partition
title-description: "EFI System Partition (ESP) — UEFI boot-chain contents: bootmgfw.efi, boot config, bootkit surface"
aliases: [ESP, EFI System Partition, UEFI boot files, \EFI\Microsoft\Boot]
link: system
link-secondary: persistence
tags: [boot-chain, bootkit-hunt, pre-os]
volatility: persistent
interaction-required: none
substrate: windows-disk-metadata
substrate-instance: EFI-System-Partition
substrate-hub: Disk Metadata
platform:
  windows: {min: '8', max: '11'}
  windows-server: {min: '2012', max: '2022'}
  note: "Only present on UEFI-boot systems. Legacy BIOS systems use the active-partition MBR boot code instead."
location:
  mount-default: "hidden — mount with `mountvol X: /s` (elevated) to access as drive letter"
  partition-type-guid: "C12A7328-F81F-11D2-BA4B-00A0C93EC93B (EFI System Partition GPT type)"
  filesystem: "FAT32 (by spec)"
  primary-paths:
    - "\\EFI\\Microsoft\\Boot\\bootmgfw.efi (Windows UEFI boot manager)"
    - "\\EFI\\Microsoft\\Boot\\BCD (Boot Configuration Data — separate artifact)"
    - "\\EFI\\Boot\\bootx64.efi (fallback boot path)"
    - "\\EFI\\Microsoft\\Recovery\\BCD"
  addressing: partition-region + file-path
  note: "The EFI System Partition is a FAT32 partition marked with the EFI-System GPT partition type GUID, holding the UEFI bootloader files + BCD. On UEFI systems this is the pre-OS boot surface. Bootkit attacks (BlackLotus, CosmicStrand, MoonBounce) persist HERE — replacing bootmgfw.efi, adding rogue .efi files, or hijacking the boot chain before Windows kernel loads. ESP is normally hidden (no drive letter) but acquirable offline or via mountvol."
fields:
- name: bootmgfw-efi-hash
  kind: hash
  location: "\\EFI\\Microsoft\\Boot\\bootmgfw.efi content hash"
  encoding: sha-256
  references-data: [{concept: ExecutableHash, role: contentHash}]
  note: "SHA-256 of the boot manager. Known-good hashes per Windows build are published by Microsoft. Unknown hash = replaced / tampered boot manager (bootkit). Compare against Microsoft's published baseline AND against the file's Authenticode signature (must chain to Microsoft UEFI CA)."
- name: bootmgfw-efi-mtime
  kind: timestamp
  location: "\\EFI\\Microsoft\\Boot\\bootmgfw.efi $SI modified time"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime... actually FAT32 on ESP, so 2-second resolution. Legitimate updates happen via Windows Update — mtime outside update windows = drive-by modification."
- name: bcd-file
  kind: path
  location: "\\EFI\\Microsoft\\Boot\\BCD (on ESP — distinct from BCD on Windows volume)"
  references-data: [{concept: ExecutablePath, role: configuredPersistence}]
  note: "Boot Configuration Data hive. Separate artifact (BCD-Store). Its location on the ESP (vs. legacy-BIOS C:\\Boot\\BCD) matters for acquisition — forgetting to acquire from ESP misses the UEFI BCD."
- name: extra-efi-files
  kind: content
  location: "\\EFI\\ directory tree — any .efi / .efi.bak / unknown file"
  note: "Legitimate ESP contents are Microsoft boot files + vendor tool partitions (Dell, HP, Lenovo). Unexpected .efi files = candidate bootkit. Known bootkit signatures: BlackLotus drops 'winload.efi' replacements, SecurityCert revocation bypasses, 'mcupdate_AuthenticAMD.dll' replacements."
- name: revocation-list-state
  kind: content
  location: "UEFI Secure Boot revocation list (dbx) — UEFI variable, NOT ESP file"
  note: "Secure Boot dbx (forbidden-signature list) is stored in UEFI NVRAM (not on ESP). Attacker bootkits known to add / remove dbx entries. Not directly an ESP artifact but must be checked alongside ESP for full bootkit triage."
- name: partition-size
  kind: counter
  location: partition table entry
  encoding: uint64 LBA count
  note: "ESP is typically 100-500 MB. Significantly larger ESP = may indicate attacker tooling stashed there (older bootkits used ESP for payload storage)."
observations:
- proposition: BOOT_CHAIN_INTEGRITY
  ceiling: C4
  note: 'The ESP is the pre-OS persistence surface for bootkit-class threats. BlackLotus (2023), CosmicStrand (2022), MoonBounce (2022), Bootlicker (various) all use ESP as their persistence vector. Routinely skipped in standard DFIR acquisitions because ESP is not mounted by default — you must explicitly acquire it. For any host where Secure Boot posture is questioned OR boot behavior is anomalous, ESP acquisition + hash-comparison against Microsoft baseline + Authenticode verification is mandatory. Pair with BCD-Store registry and SYSTEM-channel boot events.'
  qualifier-map:
    setting.file: "\\EFI\\Microsoft\\Boot\\bootmgfw.efi"
    object.hash: field:bootmgfw-efi-hash
    time.start: field:bootmgfw-efi-mtime
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: Authenticode signing (Secure Boot) — bootkits either bypass by turning Secure Boot off via BCD-Store OR use signed-but-vulnerable shims (BlackLotus = signed baton.efi exploit)
  known-cleaners:
  - tool: "bcdboot reinstall / Windows recovery"
    typically-removes: restores Microsoft boot manager from recovery image
  survival-signals:
  - bootmgfw.efi hash not matching Microsoft baseline for the Windows build = candidate replacement
  - Unexpected .efi files in \EFI\Microsoft\Boot\ or \EFI\Boot\ that don't match Microsoft + OEM catalog = bootkit component
  - BCD (UEFI path) with testsigning=Yes / nointegritychecks=Yes OR missing = pre-OS integrity bypass prep
  - UEFI dbx variable (Secure Boot revocation list) with recent edits = attacker bypass of revocation protection
provenance:
  - ms-efi-system-partition-uefi-boot-arch
  - eset-2023-blacklotus-bootkit-first-uefi
  - great-2022-cosmicstrand-uefi-firmware-roo
  - mitre-t1542-003
---

# EFI System Partition (ESP)

## Forensic value
The ESP is the hidden FAT32 partition on UEFI-boot systems holding the Windows UEFI boot manager (`bootmgfw.efi`), Boot Configuration Data (BCD), and fallback boot files. Bootkit-class threats (BlackLotus, CosmicStrand, MoonBounce) persist here because the execution happens BEFORE the Windows kernel loads — below any EDR / Defender / endpoint-security reach.

## Primary paths on ESP
- `\EFI\Microsoft\Boot\bootmgfw.efi` — Windows boot manager (primary bootkit target)
- `\EFI\Microsoft\Boot\BCD` — boot configuration (see BCD-Store artifact for detail)
- `\EFI\Boot\bootx64.efi` — fallback boot path (bootkit secondary target)
- `\EFI\Microsoft\Recovery\BCD` — recovery BCD

## Acquisition
ESP is hidden by default — must mount explicitly:
```cmd
mountvol X: /s      :: elevated; mounts ESP as X:
dir X:\EFI\Microsoft\Boot
```

Or acquire from offline disk image — the ESP is a distinct partition with GPT type `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`.

## Integrity checks
```powershell
# Hash bootmgfw.efi, compare against Microsoft-baseline for current Windows build
Get-FileHash "X:\EFI\Microsoft\Boot\bootmgfw.efi" -Algorithm SHA256
```

Cross-reference against Microsoft's published UEFI-signed binary catalog. Any deviation = bootkit candidate.

## Cross-reference
- **BCD-Store** — UEFI BCD hive on ESP
- **System EVTX** — boot-related events (12 = boot start, 41 = unexpected reboot)
- **Sysmon-6** — any driver loaded after boot can reveal bootkit follow-on DLLs

## Practice hint
On a UEFI Windows 10/11 VM: `mountvol X: /s`, inspect `X:\EFI\Microsoft\Boot\`. Hash bootmgfw.efi. Compare against a freshly-installed VM's hash for the same Windows build — they should match exactly. Any mismatch on a production host = investigate immediately.
