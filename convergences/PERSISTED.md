---
name: PERSISTED
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: PERSISTED
  ceiling: C3
inputs:
  - BOOT_CHAIN_INTEGRITY
  - CONFIGURED
  - CONFIGURED_BY_POLICY
  - CONFIGURED_DEFENSE
  - CONFIGURED_RESOLUTION_OVERRIDE
  - EXISTS
  - HAD_CONFIGURATION
  - INSTALLED
  - INSTALLED_RUNTIME
  - LOADED_DRIVER
input-sources:
  - proposition: BOOT_CHAIN_INTEGRITY
    artifacts:
      - EFI-System-Partition
  - proposition: CONFIGURED
    artifacts:
      - Active-Setup
      - AeDebug
      - AppInit-DLLs
      - Application-Shim-SDB
      - BCD-Store
      - COM-HijackKeys
      - CommandProcessor-AutoRun
      - CredentialProviders
      - DNS-NRPT
      - Defender-Exclusions
      - ETW-Autologger
      - LSA-Packages
      - Netsh-Helpers
      - Port-Monitors
      - PowerShell-Profile
      - RootCertificate-Store
      - Run-Keys
      - Scheduled-Tasks
      - ScheduledTask-XML
      - Screensaver-Hijack
      - Security-4657
      - Services
      - SessionManager-Persistence
      - Shell-COM-Hooks
      - SilentProcessExit-Monitor
      - Start-TrackProgs
      - Time-Providers
      - WMI-CIM-Repository
      - WMI-Subscriptions
      - WinSock2-LSP
      - Winlogon-Extended
      - Winlogon-Userinit-Shell
  - proposition: CONFIGURED_BY_POLICY
    artifacts:
      - GPP-SYSVOL-XML
      - GroupPolicy-Registry-Pol
      - Intune-PolicyManager
  - proposition: CONFIGURED_DEFENSE
    artifacts:
      - AppLocker-Policy-Cache
      - Credential-Guard-State
      - Defender-ASR-Rules
      - LSA-Protection-RunAsPPL
      - SChannel-TLS-Config
      - Windows-Firewall-Profiles
  - proposition: CONFIGURED_RESOLUTION_OVERRIDE
    artifacts:
      - Hosts-File
  - proposition: HAD_CONFIGURATION
    artifacts:
      - RegBack-Hives
      - Registry-Transaction-Logs
  - proposition: INSTALLED
    artifacts:
      - Uninstall-Keys
  - proposition: INSTALLED_RUNTIME
    artifacts:
      - WSL-Lxss
  - proposition: LOADED_DRIVER
    artifacts:
      - Sysmon-6
join-chain:
  - concept: ExecutablePath
    join-strength: moderate
    sources:
      - mitre-t1547
      - mitre-t1547-001
      - mitre-t1546
      - mitre-t1543-003
      - ms-event-4657
      - carvey-2022-windows-forensic-analysis-tool
    primary-source: ms-event-4657
    description: |
      Dominant pivot across the registry-ASEP persistence subfamily.
      Most PERSISTED inputs record a persistence CONFIGURATION that
      references a target binary: Run-Keys / AppInit-DLLs / Services /
      Active-Setup / AeDebug / CommandProcessor-AutoRun /
      CredentialProviders / Netsh-Helpers / PowerShell-Profile /
      Screensaver-Hijack / Shell-COM-Hooks / SilentProcessExit-Monitor /
      Winlogon-Userinit-Shell / WinSock2-LSP / Time-Providers /
      Port-Monitors / LSA-Packages / COM-HijackKeys / Scheduled-Tasks /
      ScheduledTask-XML / Application-Shim-SDB / Uninstall-Keys all
      carry the referenced executable path. Joining on ExecutablePath
      threads "the persistence mechanism" to "the binary that will run"
      — closing the PERSISTED(entity, system) claim. Moderate strength:
      paths are evadable via relocation, impersonation, or fileless
      mechanisms (PowerShell-Profile scriptblocks, WMI-Subscriptions
      with embedded WQL actions) — for fileless variants see the other
      pivots (TriggerMechanism, WMI query-body).
    artifacts-and-roles:
      - artifact: Run-Keys
        role: configuredPersistence
      - artifact: AppInit-DLLs
        role: configuredPersistence
      - artifact: Services
        role: configuredPersistence
      - artifact: Active-Setup
        role: configuredPersistence
      - artifact: AeDebug
        role: configuredPersistence
      - artifact: CommandProcessor-AutoRun
        role: configuredPersistence
      - artifact: CredentialProviders
        role: configuredPersistence
      - artifact: Netsh-Helpers
        role: configuredPersistence
      - artifact: PowerShell-Profile
        role: configuredPersistence
      - artifact: Screensaver-Hijack
        role: configuredPersistence
      - artifact: Shell-COM-Hooks
        role: configuredPersistence
      - artifact: SilentProcessExit-Monitor
        role: configuredPersistence
      - artifact: Winlogon-Userinit-Shell
        role: configuredPersistence
      - artifact: Winlogon-Extended
        role: configuredPersistence
      - artifact: WinSock2-LSP
        role: configuredPersistence
      - artifact: Time-Providers
        role: configuredPersistence
      - artifact: Port-Monitors
        role: configuredPersistence
      - artifact: LSA-Packages
        role: configuredPersistence
      - artifact: COM-HijackKeys
        role: configuredPersistence
      - artifact: Scheduled-Tasks
        role: configuredPersistence
      - artifact: ScheduledTask-XML
        role: configuredPersistence
      - artifact: Application-Shim-SDB
        role: configuredPersistence
      - artifact: Uninstall-Keys
        role: configuredPersistence
      - artifact: SessionManager-Persistence
        role: configuredPersistence
  - concept: Location
    join-strength: weak
    sources:
      - ms-event-4657
      - ms-the-system-registry-is-no-longer-ba
      - suhanov-2019-windows-registry-forensics-par
      - isc-2020-checking-the-hosts-file-as-an
    primary-source: ms-event-4657
    description: |
      Persistence-location pivot for artifacts that ARE the configuration
      record (not the referenced binary). Security-4657 records the
      ObjectName + ObjectValueName where the persistence was set;
      RegBack-Hives / Registry-Transaction-Logs preserve the hive path
      where the mechanism lived pre-cleanup; Hosts-File names the
      fixed-path resolution-override. Weak pivot because different
      artifacts carry different path-forms (registry path vs. filesystem
      path vs. UEFI-partition path vs. SYSVOL-share UNC). Forensic
      role: when the attacker cleaned the primary persistence but the
      transaction-log replay or RegBack copy preserves the original
      configuration, the Location pivot ties the surviving evidence to
      the mechanism's original place. Complements ExecutablePath —
      ExecutablePath answers "what ran," Location answers "from where
      it was configured."
    artifacts-and-roles:
      - artifact: Security-4657
        role: registryPath
      - artifact: RegBack-Hives
        role: preservedPath
      - artifact: Registry-Transaction-Logs
        role: preservedPath
      - artifact: Hosts-File
        role: resolutionOverridePath
      - artifact: EFI-System-Partition
        role: bootChainPath
      - artifact: BCD-Store
        role: bootChainPath
      - artifact: GPP-SYSVOL-XML
        role: policyPath
      - artifact: GroupPolicy-Registry-Pol
        role: policyPath
      - artifact: Intune-PolicyManager
        role: policyPath
  - concept: UserSID
    join-strength: strong
    sources:
      - mitre-t1547-014
      - mitre-t1546
      - carvey-2022-windows-forensic-analysis-tool
    description: |
      Scope pivot for per-user persistence mechanisms. Active-Setup
      (HKCU\Software\Microsoft\Active Setup\Installed Components,
      triggered on every logon where HKCU version < HKLM version) is
      user-scoped. Start-TrackProgs binds to the user's HKCU settings.
      Shell-COM-Hooks, Screensaver-Hijack, CommandProcessor-AutoRun
      (HKCU variant), PowerShell-Profile (per-user $PROFILE) are all
      per-user ASEPs. Joining on UserSID distinguishes "machine-wide
      persistence" from "this user specifically targeted" — affects
      scope of affected-user inference and blast-radius analysis.
    artifacts-and-roles:
      - artifact: Active-Setup
        role: targetedUser
      - artifact: Start-TrackProgs
        role: targetedUser
      - artifact: Shell-COM-Hooks
        role: targetedUser
      - artifact: PowerShell-Profile
        role: targetedUser
      - artifact: Screensaver-Hijack
        role: targetedUser
exit-node:
  - WMI-CIM-Repository
  - Services
  - Scheduled-Tasks
notes:
  - 'Application-Shim-SDB: Fires on every launch of the target executable — persistence trigger is process-creation of a commonly-run binary.'
  - 'AppLocker-Policy-Cache: Policy cache is re-consulted on every AppIDSvc start (boot) and on every GPO refresh.'
  - 'GPP-SYSVOL-XML: GPP policies are re-applied on every refresh to every target client.'
  - 'GroupPolicy-Registry-Pol: GPO-enforced registry settings are re-applied on every refresh (typically every 90 minutes + 30 min random offset).'
  - 'WMI-CIM-Repository: Survives reboot; triggered by Winmgmt service start + whatever WQL trigger is embedded in the Filter.'
  - 'EFI-System-Partition: Bootkit persistence executes before OS — reboot always re-triggers.'
  - 'Security-4657: When the ObjectName + ObjectValueName combination matches a known persistence mechanism (Run key, Services subkey, AppInit_DLLs, IFEO Debugger, Winlogon Shell/Userinit, etc.), the CONFIGURED proposition directly satisfies PERSISTED''s input.'
  - 'Sysmon-6: Kernel driver loaded into the running kernel; persists until unload OR next reboot.'
  - 'Active-Setup: Triggers on every user''s logon where HKCU\Version < HKLM\Version — broad reach, admin-level plant, user-context execution.'
  - 'AeDebug: Fires on any process crash — persistent until registry entry is cleared.'
  - 'BCD-Store: Persists across reboots by definition — every reboot consults BCD.'
  - 'CommandProcessor-AutoRun: Triggered on every cmd.exe launch — high-frequency.'
  - 'Credential-Guard-State: CG state persists across reboot (and across UEFI power-cycle when UEFI-locked).'
  - 'Defender-Exclusions: Exclusions "persist" the attacker''s freedom to operate rather than their code itself.'
  - 'DNS-NRPT: NRPT rules persist across reboot and are consulted on every DNS lookup.'
  - 'ETW-Autologger: Autologger config persists across reboot — takes effect at next boot.'
  - 'Intune-PolicyManager: MDM policy re-applies at every refresh cycle; cached value is enforced between refreshes.'
  - 'LSA-Protection-RunAsPPL: Value is read at boot; persists across reboot until explicitly changed.'
  - 'Netsh-Helpers: Trigger is every netsh.exe invocation — constant in normal Windows operation.'
  - 'Port-Monitors: Trigger is Print Spooler service start — automatic on boot.'
  - 'RegBack-Hives: RegBack preserves prior persistence configurations even after attacker cleanup — offline diff surfaces what was removed.'
  - 'Registry-Transaction-Logs: Log-replayed hive recovers persistence configurations that attacker cleanup had removed from the primary hive.'
  - 'RootCertificate-Store: Root certs persist until explicitly removed; no reboot or logon trigger needed (cert is consulted on every TLS / Authenticode validation).'
  - 'Run-Keys: combined with EXISTS(entity=referenced exe on disk), Run-Keys closes PERSISTED(entity, system, via=run-key)'
  - 'SChannel-TLS-Config: Schannel reads these values at TLS negotiation time — persistent effect across reboots.'
  - 'Scheduled-Tasks: task-scheduler is a mature persistence class; all scheduled tasks are PERSISTED unless actively disabled'
  - 'Screensaver-Hijack: Triggers on every user-idle period meeting the timeout — persistent within the interactive session.'
  - 'Services: auto-start services (Start=2) are PERSISTED by definition; the CONFIGURED + PERSISTED composite captures both the presence and the activation trigger'
  - 'Shell-COM-Hooks: Trigger is every interactive logon (explorer.exe start) — effectively a boot-persistent hook per user session.'
  - 'SilentProcessExit-Monitor: Trigger is the target process''s exit. For lsass target, fires on every shutdown.'
  - 'Start-TrackProgs: Persists until the user toggles the Settings UI back on or registry is edited.'
  - 'Time-Providers: Trigger is W32Time service start — automatic at boot.'
  - 'Uninstall-Keys: Installed apps persist across reboot until explicitly uninstalled.'
  - 'Windows-Firewall-Profiles: Profile state persists across reboot and is re-applied when MpsSvc starts.'
  - 'WinSock2-LSP: LSP loads into every new process that links ws2_32.dll — persistence is implicit in every network app on the system.'
  - 'WSL-Lxss: Distro survives reboot; uninstalling via wsl --unregister removes the registry entry + rootfs — look for orphan ext4.vhdx files if the user tried to cover up.'
  - 'Hosts-File: Survives reboot; persists until manually edited.'
  - 'PowerShell-Profile: Trigger is every PowerShell session start — high frequency on admin / developer workstations.'
  - 'ScheduledTask-XML: Task fires on whatever trigger is embedded — boot, logon, time, event — until deleted or disabled.'
provenance:
  - ms-efi-system-partition-uefi-boot-arch
  - eset-2023-blacklotus-bootkit-first-uefi
  - great-2022-cosmicstrand-uefi-firmware-roo
  - mitre-t1542-003
  - ms-active-setup-internet-explorer-depl
  - mitre-t1547-014
  - robbins-2022-group-policy-preferences-and-t
  - project-2023-windowsbitsqueuemanagerdatabas
  - ms-configuring-automatic-debugging-aed
  - mitre-t1546-012
  - mitre-t1546
  - mitre-t1546-010
  - online-2021-registry-hive-file-format-prim
  - libyal-libregf
  - mitre-t1546-011
  - mandiant-2015-shim-me-the-way-application-co
  - ballenthin-2015-python-sdb-sdb-explorer-parsin
  - ms-application-compatibility-toolkit-s
  - ms-boot-configuration-data-bcd-archite
  - ms-registering-com-servers
  - mitre-t1546-015
  - enigma0x3-2017-userland-persistence-with-sche
  - ms-cmd-exe-d-switch-and-autorun-regist
  - ms-credential-providers-in-windows
  - mitre-t1556-002
  - ms-name-resolution-policy-table-nrpt-r
  - mitre-t1071-004
  - ms-configure-and-validate-exclusions-f
  - ms-protect-security-settings-with-tamp
  - mitre-t1562-001
  - ms-event-tracing-for-windows-etw-autol
  - mitre-t1562-002
  - palantir-2021-etw-attack-surface-disabling-e
  - ms-configuring-additional-lsa-protecti
  - delpy-nd-mimikatz-mimilib-dll-as-a-noti
  - mitre-t1547-002
  - mitre-t1547-005
  - mitre-t1546-007
  - ms-netsh-helper-architecture-and-exten
  - ms-print-spooler-port-monitor-architec
  - mitre-t1547-010
  - ms-about-profiles-powershell-profile-s
  - mitre-t1546-013
  - canary-2022-powershell-profile-persistence
  - ms-windows-certificate-stores-registry
  - ms-microsoft-trusted-root-program-list
  - mitre-t1553-004
  - labs-2019-dangers-of-installing-root-cer
  - mitre-t1547
  - mitre-t1547-001
  - ms-task-scheduler-1-0-legacy-format-re
  - ms-task-scheduler-2-0-xml-schema-refer
  - mitre-t1053-005
  - ms-desktop-window-manager-screensaver
  - mitre-t1546-002
  - ms-event-4657
  - uws-event-4657
  - mitre-t1574
  - mitre-t1543
  - mitre-t1543-003
  - ms-session-manager-subsystem-smss-exe
  - carvey-2022-windows-forensic-analysis-tool
  - ms-ishellexecutehook-interface-and-reg
  - ms-monitoring-silent-process-exit
  - mitre-t1562-006
  - matrix-nd-dt061-detect-text-authored-in
  - ms-windows-time-service-time-providers
  - mitre-t1547-003
  - ms-windows-management-instrumentation
  - mitre-t1546-003
  - ballenthin-2016-python-cim-wmi-cim-repository
  - ms-winsock-service-provider-interface
  - ms-winlogon-registry-entries
  - mitre-t1547-004
  - ms-kb2962486-ms14-025-vulnerability-in
  - mitre-t1552-006
  - schroeder-2016-get-gpppassword-powershell-one
  - ms-group-policy-registry-extension-and
  - mitre-t1484-001
  - ms-configuration-service-provider-csp
  - ms-applocker-policy-storage-and-enforc
  - ms-wdac-policy-file-format-and-enforce
  - ms-credential-guard-manage-configure-a
  - mitre-t1003-001
  - ms-attack-surface-reduction-rules-rule
  - ms-controlled-folder-access-anti-ranso
  - ms-tls-registry-settings-schannel-conf
  - stig-2023-windows-10-11-security-technic
  - ms-windows-defender-firewall-registry
  - mitre-t1562-004
  - ms-tcp-ip-and-nbt-configuration-parame
  - mitre-t1562
  - isc-2020-checking-the-hosts-file-as-an
  - ms-the-system-registry-is-no-longer-ba
  - suhanov-2019-windows-registry-forensics-par
  - ms-uninstall-registry-key-applications
  - nirsoft-2023-uninstallview-enumerate-instal
  - ms-windows-subsystem-for-linux-registr
  - mitre-t1202
  - ms-sysmon-system-monitor
  - project-2024-living-off-the-land-drivers-vu
  - mitre-t1014
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - ms-advanced-audit-policy
  - regripper-plugins
---

# Convergence — PERSISTED

Tier-2 convergence yielding proposition `PERSISTED`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: Active-Setup, AeDebug, AppInit-DLLs, AppLocker-Policy-Cache, Application-Shim-SDB, BCD-Store, COM-HijackKeys, CommandProcessor-AutoRun, Credential-Guard-State, CredentialProviders, DNS-NRPT, Defender-ASR-Rules, Defender-Exclusions, EFI-System-Partition, ETW-Autologger, GPP-SYSVOL-XML, GroupPolicy-Registry-Pol, Hosts-File, Intune-PolicyManager, LSA-Packages, LSA-Protection-RunAsPPL, Netsh-Helpers, Port-Monitors, PowerShell-Profile, RegBack-Hives, Registry-Transaction-Logs, RootCertificate-Store, Run-Keys, SChannel-TLS-Config, Scheduled-Tasks, ScheduledTask-XML, Screensaver-Hijack, Security-4657, Services, SessionManager-Persistence, Shell-COM-Hooks, SilentProcessExit-Monitor, Start-TrackProgs, Sysmon-6, Time-Providers, Uninstall-Keys, WMI-CIM-Repository, WMI-Subscriptions, WSL-Lxss, WinSock2-LSP, Windows-Firewall-Profiles, Winlogon-Extended, Winlogon-Userinit-Shell.
