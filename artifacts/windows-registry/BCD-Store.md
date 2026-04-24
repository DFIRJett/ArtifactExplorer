---
name: BCD-Store
title-description: "Boot Configuration Data (BCD) store — registry-hive file controlling Windows bootmgr / winload paths"
aliases:
- BCD
- Boot Configuration Data
- bcdedit store
link: persistence
tags:
- boot-persistence
- tamper-signal
- itm:PR
- itm:AF
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: BCD
platform:
  windows:
    min: Vista
    max: '11'
    note: "Replaced the legacy boot.ini starting with Vista. Same format (registry hive) on every subsequent Windows release. UEFI systems store BCD on the EFI System Partition; legacy-BIOS systems store it on the active partition."
  windows-server:
    min: '2008'
    max: '2022'
location:
  hive: BCD (loaded on demand to HKLM\BCD00000000)
  path-uefi: "<ESP>\\EFI\\Microsoft\\Boot\\BCD"
  path-legacy-bios: "<SystemVolume>\\Boot\\BCD"
  live-access: "bcdedit /enum all /v"
  addressing: hive+key-path
  note: "BCD is a registry-hive format file (same format as SOFTWARE / SYSTEM) but lives OUTSIDE the Windows registry tree — it's loaded on demand by bootmgr. Acquire as a file; parse with Registry Explorer, RegRipper, or bcdedit. On UEFI systems the ESP is not mounted by default — use 'mountvol' to mount it before acquisition."
fields:
- name: boot-entry-osdevice
  kind: path
  location: "BCD Object {GUID} → Element 0x21000001 (OSDevice) value data"
  type: BCD element data (device format)
  note: "Device identifier of the partition the OS loader reads Windows from. Attacker modification of OSDevice on the active boot entry = redirect to a different partition (another-OS boot, rescue-environment boot). Usually a secondary tamper signal since direct OSDevice changes are visible in bcdedit output."
- name: boot-entry-path
  kind: path
  location: "BCD Object {GUID} → Element 0x22000002 (Path) value data"
  type: REG_SZ (element-embedded)
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Path on the OSDevice to the OS loader (\\Windows\\system32\\winload.efi or \\Windows\\system32\\winload.exe). Redirecting this to an attacker binary = the single most privileged persistence on Windows because winload.efi runs before the OS itself (kernel-mode bootkit territory)."
- name: bootmgr-path
  kind: path
  location: "BCD Object {9dea862c-...} (bootmgr) → Element 0x22000002"
  note: "Path to bootmgfw.efi / bootmgr.exe itself. Change = attacker replaced the boot manager (full-chain bootkit)."
- name: secure-boot-disable
  kind: flags
  location: "bcdedit /set testsigning on | disable-integrity-checks | loadoptions DISABLE_INTEGRITY_CHECKS"
  encoding: BCD boolean element
  note: "testsigning=Yes / nointegritychecks=Yes / disable-vbs on the active boot entry = security mitigations disabled. Any of these on a production host without an explicit kernel-driver-development use case = deliberate bypass of driver-signing enforcement — usually a precursor to loading an unsigned (attacker-signed or self-signed) kernel driver."
- name: safeboot-alternateshell
  kind: flags
  location: "bcdedit /set safeboot network|minimal + alternateshell"
  note: "alternateshell=Yes puts safe-mode boot into 'safeboot with alternate shell' — cmd.exe in place of explorer.exe. Attacker persistence that uses safe-mode-with-alt-shell can control the system during safe-mode-based recovery sessions. Rare signal but high-value when present."
- name: recovery-sequence
  kind: identifier
  location: "BCD Object {GUID} → Element 0x24000001 (RecoverySequence)"
  type: BCD GUID element
  note: "GUID pointing at the recovery environment BCD entry. Attacker-redirected recovery sequence points the Windows-Recovery entry at attacker tooling — triggered when the user holds Shift while clicking Restart or when automatic repair kicks in."
- name: bcd-file-mtime
  kind: timestamp
  location: BCD file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime of the BCD hive file. BCD is rarely modified in steady-state operation (OS install, feature upgrade, driver-install that changes boot, manual bcdedit). Any mtime change outside those events is forensically material."
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'BCD is the highest-privilege persistence substrate on Windows.
    Changes here control what runs BEFORE the kernel — Boot Manager,
    OS Loader, Hypervisor, Secure Boot enforcement, integrity
    checking, test-signing acceptance. Attacker-useful BCD
    modifications include: disabling kernel-driver signing
    enforcement (testsigning=On, nointegritychecks=Yes), redirecting
    the OS loader to attacker binaries (bootkit), planting a custom
    recovery environment, enabling safe-boot with alternate shell.
    Because bcdedit output is rarely baseline-compared in DFIR,
    this artifact is under-inspected relative to its criticality.'
  qualifier-map:
    setting.registry-path: "BCD\\Objects\\{GUID}\\Elements"
    setting.dll: field:boot-entry-path
    time.start: field:bcd-file-mtime
anti-forensic:
  write-privilege: admin
  integrity-mechanism: "hive-level checksum; no per-element signing. Secure Boot enforces signed boot images; BCD config itself is not signed."
  known-cleaners:
  - tool: bcdedit /deletevalue or bcdedit /delete <GUID>
    typically-removes: a specific element or entry (leaves hive mtime update as evidence)
  - tool: bcdedit /export / /import (restore from clean snapshot)
    typically-removes: comprehensive reset
  survival-signals:
  - bcdedit output shows testsigning=Yes / nointegritychecks=Yes / hypervisorlaunchtype=Off on a host that does not legitimately develop/test kernel drivers = integrity bypass
  - OS loader path (\\Windows\\system32\\winload.*) replaced with unfamiliar path = bootkit
  - Extra BCD Objects / non-stock boot entries = dual-boot injection
  - BCD file mtime inside incident window = boot-chain was touched
provenance:
  - ms-boot-configuration-data-bcd-archite
  - mitre-t1542-003
exit-node:
  is-terminus: true
  primary-source: mitre-t1542-003
  attribution-sentence: 'Adversaries may use bootkits to persist on systems (MITRE ATT&CK, n.d.).'
  terminates:
    - BOOT_INTEGRITY
    - CONFIGURED_DEFENSE
  sources:
    - ms-boot-configuration-data-bcd-archite
    - mitre-t1542-003
  reasoning: >-
    The Boot Configuration Data store holds the authoritative boot-entry
    definitions, OS loader paths, secure-boot policy flags, and boot-
    integrity knobs (testsigning, nointegritychecks, disableelamdrivers,
    hypervisorlaunchtype). No upstream: the BCD IS what the Windows
    Boot Manager reads at power-on to decide what loads. Forensic
    terminus for "how was this system configured to boot?"
  implications: >-
    Attacker-set testsigning=Yes on a production host = self-signed
    kernel driver to be loaded; expect a bootkit or unsigned-ELAM
    driver install. disableelamdrivers=Yes + Defender-5001 in the
    same window = coordinated protection-bypass. Extra BCD objects
    pointing at non-stock loaders = dual-boot injection.
  preconditions: >-
    Read access to \\EFI\\Microsoft\\Boot\\BCD (UEFI) or \\Boot\\BCD
    (legacy BIOS). Administrator token required for reads on a running
    system; offline parsing via regf / reg-format library works against
    a mounted partition image.
  identifier-terminals-referenced: []
---

# BCD (Boot Configuration Data) Store

## Forensic value
BCD replaced `boot.ini` starting with Windows Vista. It is a registry-hive format file (same binary layout as SOFTWARE / SYSTEM) that lives OUTSIDE the Windows registry tree — loaded on demand by `bootmgr` during boot to decide which OS loader to invoke, where to find the Windows directory, and whether to enforce driver signing / kernel-integrity protections.

Because BCD controls the boot chain, modifications here have the highest possible privilege impact:

- Disable driver-signing enforcement → load unsigned (attacker) kernel drivers
- Redirect OS loader → bootkit
- Redirect recovery sequence → custom recovery environment under attacker control
- Enable safe-mode with alternate shell → control of safe-mode session

## Where it lives
- **UEFI**: `<EFI System Partition>\EFI\Microsoft\Boot\BCD` — ESP is not mounted by default on a running system; use `mountvol X: /s` to mount before acquiring
- **Legacy BIOS**: `<System Volume>\Boot\BCD`

Both are acquired as flat files and parsed as registry hives.

## Concept reference
- ExecutablePath (OS loader path, bootmgr path, recovery loader path)

## Triage (live)
```cmd
bcdedit /enum all /v
bcdedit /store <path-to-BCD>  :: offline
```

Check for forensic red flags in the output:
- `testsigning` set to `Yes`
- `nointegritychecks` set to `Yes`
- `hypervisorlaunchtype` set to `Off` (VBS / credential-guard disabled)
- `path` of the OS loader not matching `\Windows\system32\winload.efi` (UEFI) or `\Windows\system32\winload.exe` (legacy)
- Extra top-level boot entries beyond Windows + Windows RE
- `safeboot` / `safebootalternateshell` set when no admin use case

## Triage (offline)
Load the BCD file in Registry Explorer. Structure:
- `Objects\{GUID}\Elements\<element-id>` — each element holds a typed value (boolean, string, GUID, integer)
- `Description\Keywords` — friendly name of the entry

Key element IDs:
- `0x12000002` — Path
- `0x21000001` — OSDevice
- `0x22000002` — BootPath
- `0x24000001` — RecoverySequence
- `0x25000010` — AllowNxIntegrity flags

## Cross-reference
- **Security-4672** — special privileges assigned to bcdedit invocation (SeTakeOwnership, SeBackup, SeRestore required)
- **Security-4688** — process creation for `bcdedit.exe` with command-line arguments indicating the change
- **System-7045** — companion driver service registration (unsigned driver often needs testsigning mode)

## Practice hint
On a test VM: run `bcdedit /enum all /v > baseline.txt` as a clean-state snapshot. Then toggle `bcdedit /set testsigning on` — reboot — check again. BCD file mtime updated; testsigning=Yes appears in bcdedit output. This is exactly the state an attacker creates before loading an unsigned rootkit. Revert with `bcdedit /deletevalue testsigning` + reboot.
