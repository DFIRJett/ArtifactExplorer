---
name: WSL-Lxss
title-description: "Windows Subsystem for Linux distro registry (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss)"
aliases:
- WSL distro registry
- Lxss installation keys
- WSL inventory
link: application
tags:
- edr-bypass
- itm:ME
- per-user
volatility: persistent
interaction-required: user-action
substrate: windows-registry-hive
substrate-instance: NTUSER.DAT
platform:
  windows:
    min: '10'
    max: '11'
    note: "Requires WSL feature enabled. WSL2 is the current default; Lxss key is populated for both WSL1 and WSL2 installs."
  windows-server:
    min: '2019'
    max: '2022'
location:
  hive: NTUSER.DAT
  path: "Software\\Microsoft\\Windows\\CurrentVersion\\Lxss"
  addressing: hive+key-path
  note: "Per-user WSL state. Each installed Linux distribution has a {GUID} subkey under Lxss with DistributionName, BasePath, State, Version, DefaultUid, Flags, and package metadata. Absence of WSL on a managed workstation that has a populated Lxss key is itself the finding — the user installed WSL without administrator involvement via Store-sideload or .appx tricks."
fields:
- name: distribution-name
  kind: label
  location: "Lxss\\{GUID}\\DistributionName value"
  type: REG_SZ
  encoding: utf-16le
  note: "Human-readable distro name as registered — 'Ubuntu-22.04', 'kali-linux', 'Debian', or an attacker-renamed value. Unusual or pentesting-oriented distro (kali, parrot) on a business endpoint is a strong signal."
- name: base-path
  kind: path
  location: "Lxss\\{GUID}\\BasePath value"
  type: REG_SZ / REG_EXPAND_SZ
  encoding: utf-16le
  note: "Windows filesystem path holding the distro's rootfs (ext4.vhdx for WSL2; chroot dir for WSL1). Acquiring this path gives you the entire Linux environment including bash history, /tmp contents, and installed tools."
- name: packagefamily-name
  kind: identifier
  location: "Lxss\\{GUID}\\PackageFamilyName value"
  type: REG_SZ
  note: "AppX package family — joins with Store install telemetry and StateRepository. Empty/missing PackageFamilyName with a populated BasePath = sideloaded distro (installed via .appx file or wsl --import, bypassing Store provenance)."
- name: default-uid
  kind: identifier
  location: "Lxss\\{GUID}\\DefaultUid value"
  type: REG_DWORD
  note: "Default Linux UID the distro launches as. 0 (root) on an interactive distro is unusual — typical Store distros default to a newly-created non-root user."
- name: flags
  kind: flags
  location: "Lxss\\{GUID}\\Flags value"
  type: REG_DWORD
  note: "Bitmask — 0x1 WSL_DISTRIBUTION_FLAGS_ENABLE_INTEROP (Windows exe invocation from inside), 0x2 APPEND_NT_PATH, 0x4 ENABLE_DRIVE_MOUNTING, 0x8 (reserved). 0x4 cleared would block /mnt/c access (rare); 0x1 set is the default and enables the 'WSL → Windows binary' bypass vector."
- name: version
  kind: label
  location: "Lxss\\{GUID}\\Version value"
  type: REG_DWORD
  note: "1 = WSL1 (pico-process translation), 2 = WSL2 (managed VM with ext4.vhdx). WSL2 is stealthier for host-EDR because Linux syscalls happen inside a utility VM the host agent can't inspect."
- name: default-distro
  kind: identifier
  location: "Lxss\\DefaultDistribution value"
  type: REG_SZ
  note: "GUID of the distro `wsl.exe` launches by default when invoked with no argument. Joins back to a {GUID} subkey."
- name: key-last-write
  kind: timestamp
  location: Lxss\{GUID} key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on each distro's GUID subkey reflects install / first-run / version-upgrade time. New LastWrite on a managed workstation without a corresponding IT ticket = user self-installed WSL."
observations:
- proposition: INSTALLED_RUNTIME
  ceiling: C4
  note: 'WSL is a first-class EDR bypass on modern Windows. Host EDR
    agents that instrument Win32 syscalls see nothing that happens
    inside a WSL2 distro''s utility VM — the Linux process tree, file
    accesses, network sockets, and command invocations are invisible to
    the host. An attacker or insider can install WSL, mount /mnt/c,
    copy/exfiltrate/stage data from inside Linux, then return
    to Windows with no host-side telemetry. The Lxss registry is the
    one durable on-disk footprint that proves WSL was installed and
    when — making this key a mandatory check on every insider-threat
    and lateral-movement investigation on modern Windows.'
  qualifier-map:
    setting.registry-path: "Software\\Microsoft\\Windows\\CurrentVersion\\Lxss"
    object.path: field:base-path
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  survival-signals:
  - Lxss\{GUID} present on a system with no IT-provisioned WSL use case = self-installed subsystem worth investigating
  - Lxss\{GUID} with DefaultUid=0 + Flags=0x7 + Distro-name 'kali-linux' / 'parrot-os' = pentesting distro, strong red-team/insider tell
  - BasePath pointing to a user-controlled directory (not the default %LOCALAPPDATA%\Packages\...) = wsl --import'd distro from an external .tar.gz = likely out-of-Store install to dodge enterprise allow-listing
  - Lxss\{GUID} removed (wsl --unregister) but orphan ext4.vhdx file still on disk in %LOCALAPPDATA% = deliberate cleanup that didn't finish the job
provenance:
  - ms-windows-subsystem-for-linux-registr
  - mitre-t1202
  - matrix-nd-dt061-detect-text-authored-in
---

# WSL Lxss registry (distro inventory)

## Forensic value
Every WSL distribution — Store-installed, sideloaded, or `wsl --import`'d — registers itself under `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss` with a GUID subkey holding its name, rootfs path, default UID, flags, and version. This key is the definitive answer to three questions:

1. **Is WSL installed, and which distros?**
2. **Where is the rootfs to acquire?** (`BasePath`)
3. **When was it installed?** (key LastWrite)

WSL represents an EDR blindspot — host agents rarely instrument Linux syscalls inside a WSL2 utility VM — so insiders and red-team operators prefer it for staging, archiving, and exfiltration work they want hidden from the Windows telemetry pipeline. The Lxss key is the durable on-disk footprint that gives the WSL install away even when /mnt/c access and Linux-side activity are invisible.

## Concept references
- ExecutablePath (via BasePath pointing to ext4.vhdx or legacy chroot dir)

## Triage
```powershell
# Enumerate all installed distros
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss" |
    ForEach-Object {
        $k = Get-ItemProperty $_.PSPath
        [PSCustomObject]@{
            GUID = $_.PSChildName
            Name = $k.DistributionName
            BasePath = $k.BasePath
            Version = $k.Version
            DefaultUid = $k.DefaultUid
            Flags = ('0x{0:X}' -f $k.Flags)
        }
    }
```

Then acquire the rootfs:
```powershell
# WSL2
Copy-Item "$BasePath\ext4.vhdx" -Destination .\evidence\ext4.vhdx
# Mount offline (Linux analyst box):
# sudo mount -o loop ext4.vhdx /mnt/wsl-evidence
```

Inside the mounted rootfs, prioritize `/home/<user>/.bash_history`, `/root/.bash_history`, `/tmp`, `/var/log`, and the user's home for SSH keys / scripts / staged archives.

## Cross-reference hooks
- Store install telemetry: `PackageFamilyName` joins `Lxss\{GUID}` to StateRepository-Machine.srd (Packages table).
- WSL binary execution: Prefetch entry for `wsl.exe` / `wslhost.exe` = first-run confirmation.
- Interop bypass evidence: Security-4688 for `wsl.exe -e <windows-command>` = pivoting from Linux back into Windows through interop (`Flags & 0x1`).

## Practice hint
On a test VM: `wsl --install -d Ubuntu`, accept the username prompt, then `wsl --shutdown`. Inspect `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss` — a new {GUID} subkey exists with Ubuntu's details. Copy `ext4.vhdx` from the BasePath. Run `wsl --unregister Ubuntu` and watch the registry key disappear while — on an older WSL build or if the unregister fails mid-way — the vhdx may linger as orphan evidence.
