---
name: RegistryKeyPath
kind: value-type
lifetime: persistent
link-affinity: system
link-affinity-secondary: persistence
description: |
  Registry key path string (e.g., "HKLM\\SOFTWARE\\Microsoft\\Windows\\
  CurrentVersion\\Run"). Value-type concept — two registry artifacts
  that reference the same key-path are corroborating observations of
  that key, not proof of identity. The on-disk registry hive + key
  name together IDENTIFY a key absolutely; the string representation
  is the portable form analysts use for reporting and cross-referencing.
canonical-format: "canonical registry path — 'HKLM\\<hive>\\...\\<subkey>' or hive-relative '<hive>\\<subkey>'"
aliases: [registry-path, reg-path, key-path, registry-location]
roles:
  - id: subjectKey
    description: "The registry key this artifact primarily describes (e.g., Run-Keys records HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run as its subject)."

known-containers:
  - Run-Keys
  - Services
  - Scheduled-Tasks
  - Winlogon-Userinit-Shell
  - Winlogon-Extended
  - SessionManager-Persistence
  - CredentialProviders
  - COM-HijackKeys
  - ImageFileExecutionOptions
  - AeDebug
  - Shell-COM-Hooks
  - Defender-Exclusions
  - Defender-ASR-Rules
  - LSA-Protection-RunAsPPL
  - LSA-Packages
  - LSA-Cached-Logons
  - RootCertificate-Store
  - PrintNightmare-PointAndPrint
  - Intune-PolicyManager
  - DNS-NRPT
  - BitLocker-FVE
  - Credential-Guard-State
  - SChannel-TLS-Config
  - Windows-Firewall-Profiles
  - FirewallRules
  - ETW-Autologger
  - WMI-Subscriptions
  - NLA-Cache-Intranet
  - NLA-Signatures-Unmanaged
  - NetworkList-profiles
  - BCD-Store
  - MountedDevices
  - MountPoints2
  - USBSTOR
  - USB-Enum
  - UserAssist
  - RecentDocs
  - RecentApps
  - RunMRU
  - TypedPaths
  - TypedURLs
  - WordWheelQuery
  - OpenSavePidlMRU
  - LastVisitedPidlMRU
  - ShellBags
  - ProfileList
  - TimeZoneInformation
  - OS-Version
  - ComputerName
  - Audit-Policy
  - AutoLogon
  - AppCertDlls
  - AppInit-DLLs
  - AppPaths
  - Port-Monitors
  - Time-Providers
  - Netsh-Helpers
  - Active-Setup
  - Screensaver-Hijack
  - Start-TrackProgs
  - WSL-Lxss
  - Uninstall-Keys
  - Installer-Products-SourceList
  - CommandProcessor-AutoRun
  - WinSock2-LSP
  - Regedit-LastKey
  - Registered-Owner
  - RegBack-Hives
  - Registry-Transaction-Logs
  - ShutdownTime
  - Credentials-cached
  - LSA-Secrets
  - DNSCache
  - EMDMgmt
  - FeatureUsage
  - BAM
  - DAM
  - MUICache
  - OfficeMRU
  - TaskbarLayout
  - TS-Client-MRU
  - TerminalServerClient-Default
  - WindowsPortableDevices
---

# Registry Key Path

## What it is
The canonical string representation of a registry key location. Registry artifacts in this graph live inside a specific hive + key-path — the path is the ADDRESS, and as a value-type concept it serves as a cross-artifact corroboration key: different artifacts that reference the same registry path are independent observations of that configuration.

## Forensic value
- **Cross-artifact corroboration**: when multiple artifacts reference the same registry path (e.g., GroupPolicy-Registry-Pol writes a policy for a path that Defender-Exclusions also monitors), they form a corroboration pair.
- **Persistence-location enumeration**: grouping artifacts by the paths they subject lets analysts build a map of persistence surfaces.
- **Reporting shorthand**: registry-path strings are the portable forensic-writing form.

## Why value-type
Two artifacts referencing the same registry-path are BOTH describing the same real-world location — this is corroboration, not identity. No single artifact uniquely OWNS a path (policy files, registry hives, EVTX audit events, and Sysmon all observe the same paths). That's value-type semantics, not identifier.

## Canonical format
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — fully-qualified
- `SOFTWARE\Microsoft\Windows Defender\Exclusions` — hive-relative (hive named separately)
- Case-preserved but case-insensitive match semantics
