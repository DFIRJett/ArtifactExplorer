---
name: Uninstall-Keys
title-description: "Installed-programs Uninstall registry keys — MSI / third-party installer inventory with install timestamps"
aliases:
- Uninstall registry
- Add/Remove Programs registry
- installed applications key
link: application
tags:
- software-inventory
- install-timeline
volatility: persistent
interaction-required: user-session
substrate: windows-registry-hive
substrate-instance: SOFTWARE and NTUSER.DAT
platform:
  windows:
    min: NT4.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SOFTWARE (HKLM) and NTUSER.DAT (HKCU)
  path-machine-64bit: "Microsoft\\Windows\\CurrentVersion\\Uninstall\\<GUID-or-product-name>"
  path-machine-wow64: "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\<GUID-or-product-name>"
  path-user: "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\<GUID-or-product-name>"
  addressing: hive+key-path
  note: "Three scopes to check: HKLM\\SOFTWARE\\...\\Uninstall (machine-wide, 64-bit apps), HKLM\\SOFTWARE\\Wow6432Node\\...\\Uninstall (machine-wide, 32-bit apps on 64-bit Windows), HKCU\\Software\\...\\Uninstall (per-user installs, no admin required). Each subkey = one installed application registered via MSI or a compliant third-party installer. The key IS the software-inventory list that appears in 'Apps & Features' Control Panel. Distinct from Amcache/ShimCache (which track all EXECUTED binaries): Uninstall only has INSTALLED-via-installer apps, skipping portable executables and manually-deployed binaries. The pairing of BOTH gives the fullest software picture."
fields:
- name: display-name
  kind: label
  location: "<UninstallKey>\\DisplayName value"
  type: REG_SZ
  note: "Human-readable application name. Usually the same as the vendor's advertised product name. Attacker-installed 'Apps' (deployed via MSI sometimes) show up here — masquerading as 'Microsoft Edge Update' or 'System Monitoring Tool' or similar."
- name: display-version
  kind: label
  location: "<UninstallKey>\\DisplayVersion value"
  type: REG_SZ
  note: "Version string. Legitimate apps match vendor-published versions; attacker apps often have obvious placeholders ('1.0.0.0', '0.0.0.1') or version fields that contain suspicious content."
- name: publisher
  kind: label
  location: "<UninstallKey>\\Publisher value"
  type: REG_SZ
  note: "Vendor name (e.g., 'Microsoft Corporation', 'Google LLC', 'Adobe Inc.'). Attacker MSIs sometimes leave Publisher blank, use 'System' / 'Default Manufacturer', or copy a legitimate vendor name to blend. Baseline-compare against known-good publishers."
- name: install-location
  kind: path
  location: "<UninstallKey>\\InstallLocation value"
  type: REG_SZ / REG_EXPAND_SZ
  references-data:
  - concept: ExecutablePath
    role: ranProcess
  note: "Directory where the app is installed. Legitimate apps install to %ProgramFiles% / %ProgramFiles(x86)% / %LocalAppData%\\Programs. Attacker MSIs may install to %TEMP%, %APPDATA%, or user-writable paths — a path outside Program Files is a signal."
- name: install-source
  kind: path
  location: "<UninstallKey>\\InstallSource value"
  type: REG_SZ / REG_EXPAND_SZ
  note: "Directory from which the installer was run. For enterprise-managed installs this is often a UNC path (SCCM content share, DFS share). For attacker installs run from USB or from a downloaded .msi in Downloads, InstallSource reveals the drop-location at install time — potentially BEFORE the attacker cleaned up Downloads."
- name: install-date
  kind: timestamp
  location: "<UninstallKey>\\InstallDate value"
  type: REG_SZ
  encoding: "yyyyMMdd (8-digit date string; no time component)"
  clock: system
  resolution: 1d
  note: "Install date as a string. Only day-level resolution. For sub-second install-timing use the key LastWrite + UsnJrnl entries. BUT: this is the most directly-readable install date available and shows up in reports unchanged."
- name: uninstall-string
  kind: content
  location: "<UninstallKey>\\UninstallString value"
  type: REG_SZ / REG_EXPAND_SZ
  note: "Command run to uninstall the app. Legitimate apps have 'msiexec /x{GUID}' or a path to vendor-provided uninstaller.exe. Attacker MSIs may have blank / garbage UninstallString to frustrate removal attempts by IR teams."
- name: estimated-size
  kind: counter
  location: "<UninstallKey>\\EstimatedSize value"
  type: REG_DWORD
  note: "Estimated footprint in KB. Not forensically critical; occasionally useful for sanity-checking that the app size matches expected vendor product size."
- name: key-last-write
  kind: timestamp
  location: <UninstallKey> subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "Precise (100ns-resolution) install timestamp. Superior to InstallDate's day-granularity string. This is the pivot timestamp to use for timeline work."
observations:
- proposition: INSTALLED
  ceiling: C4
  note: 'The Uninstall registry is the single authoritative source for
    MSI-registered software on Windows. For any investigation that
    asks "what software is installed on this host?" — Uninstall keys
    are the first sweep. Because per-user HKCU Uninstall entries do
    not require admin, low-privilege attackers can install MSI-
    packaged payloads in their own scope and persist with an
    installer-backed application. Triple-sweep (HKLM\\Uninstall +
    HKLM\\Wow6432Node\\Uninstall + HKCU\\Uninstall) is mandatory —
    checking only one misses the other two scopes.'
  qualifier-map:
    object.name: field:display-name
    object.path: field:install-location
    time.start: field:key-last-write
anti-forensic:
  write-privilege: user
  integrity-mechanism: MSI package signing (optional) — enforces nothing about the Uninstall registry itself
  survival-signals:
  - DisplayName / Publisher not matching any known vendor or internal-IT-approved deployment = candidate rogue install
  - InstallLocation outside %ProgramFiles% / %ProgramFiles(x86)% for non-portable apps = suspicious
  - InstallSource in %TEMP% / Downloads / a USB-drive path = drop-location preserved
  - HKCU Uninstall entries on a user profile that normally doesn't install software = low-privilege attacker persistence
  - InstallDate / key-last-write matching incident timeline = install event
provenance:
  - ms-uninstall-registry-key-applications
  - nirsoft-2023-uninstallview-enumerate-instal
---

# Uninstall Registry Keys

## Forensic value
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<subkey>` and its siblings hold one subkey per installed application registered via MSI or a compliant third-party installer. The values under each subkey (DisplayName, DisplayVersion, Publisher, InstallLocation, InstallSource, InstallDate, UninstallString) describe the installation.

Three scopes, all mandatory to sweep:
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` (64-bit machine-wide)
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\` (32-bit machine-wide)
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\` (per-user)

## Uninstall vs Amcache vs ShimCache
- **Amcache**: every executable the OS saw run (whether installed or not)
- **ShimCache**: every executable the OS considered for shim application
- **Uninstall**: only apps installed via MSI / compliant-installer; populated from the installer manifest

Uninstall is NOT an execution-evidence artifact — it's an installation-inventory artifact. The complement of Uninstall (apps in Amcache but NOT in Uninstall) = portable / manually-dropped binaries. The complement (apps in Uninstall but NOT recently in Amcache) = installed but never run.

## Concept reference
- ExecutablePath (InstallLocation binary paths, UninstallString commands)

## Triage
```powershell
# Full three-scope sweep
$scopes = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($s in $scopes) {
    Get-ChildItem $s -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath
        [PSCustomObject]@{
            Scope        = $s
            Key          = $_.PSChildName
            DisplayName  = $p.DisplayName
            Publisher    = $p.Publisher
            Version      = $p.DisplayVersion
            InstallDate  = $p.InstallDate
            InstallLoc   = $p.InstallLocation
            InstallSrc   = $p.InstallSource
            Uninst       = $p.UninstallString
            LastWrite    = (Get-Item $_.PSPath).LastWriteTime  # key-level mtime
        }
    }
} | Format-Table -AutoSize
```

Triage red flags:
- Publisher is blank / 'System' / 'Default Manufacturer'
- InstallLocation outside Program Files for a non-portable vendor
- InstallSource in %TEMP% / Downloads / USB
- HKCU entries on a user who doesn't normally install software
- DisplayName suggests an attacker tool (RMM / pentesting / remote-access labeled ambiguously)

## Cross-reference
- **Amcache InventoryApplicationFile** — executable hash of binaries under InstallLocation (tie install to specific file contents)
- **UsnJrnl** — file-creation events in InstallLocation at install time (per-file install record)
- **Application EVTX channel** — MsiInstaller event IDs 1033 (installed), 1034 (uninstalled), 11707 (succeeded)
- **Security-4688** — msiexec.exe invocation with argument indicating the source .msi path

## Practice hint
On a lab VM: install any test app (Notepad++, 7-Zip). Inspect `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` — a new subkey with matching DisplayName is present. Note InstallDate (day-only), DisplayVersion, InstallLocation. Compare the key's LastWriteTime against the install event in Application EVTX (MsiInstaller 1033) — they align to the second. That timestamp correlation is the pivot for install-timeline work.
