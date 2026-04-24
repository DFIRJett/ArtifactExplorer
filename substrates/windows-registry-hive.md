---
name: windows-registry-hive
kind: binary-structured-file
substrate-class: Registry
aliases: [regf, registry hive, NT registry file]

format:
  magic: "regf"
  endianness: little
  block-size: 4096
  header-size: 4096
  authoritative-spec:
    - title: "Windows NT Registry File (REGF) format specification"
      author: Joachim Metz
      url: https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
    - title: "The Internal Structure of the Windows Registry"
      author: Peter Norris
      note: academic reference

structure:
  header:
    name: REGF
    size-bytes: 4096
    key-fields:
      - name: primary-sequence-number
        offset: 0x04
      - name: secondary-sequence-number
        offset: 0x08
        semantics: if != primary, hive is dirty (LOG replay required)
      - name: last-modified
        offset: 0x0C
        encoding: FILETIME-LE
        resolution: 100ns
        clock: system
      - name: root-cell-offset
        offset: 0x24
      - name: hive-name
        offset: 0x30
        encoding: UTF-16LE
        size-bytes: 64
  body:
    unit: HBIN-block
    block-size: 4096
    cell-types:
      NK: { name: key-node,   holds: subkey-metadata-and-last-write }
      VK: { name: value-key,  holds: value-metadata-and-pointer-to-data }
      SK: { name: security-key, holds: ACL-information }
      LI: { name: subkey-list-index, holds: flat-list-of-subkey-offsets }
      LF: { name: subkey-list-fast,  holds: hashed-subkey-list }
      LH: { name: subkey-list-hash,  holds: XOR-hashed-subkey-list }
      RI: { name: root-index, holds: list-of-LF/LH/LI-pointers }
      DB: { name: big-data,  holds: value-data > 16344 bytes }
  addressing:
    scheme: cell-offset
    width: 32-bit
    base: start-of-hive-header
    note: offsets are to the cell size prefix, not cell data

nested-containers:
  - type: registry-key
    parent-relation: subkey-of
    addressing-within-parent: key-name (UTF-16LE, case-preserved but case-insensitive match)
    carries:
      - last-write-timestamp  # FILETIME on the NK cell
      - class-name
      - security-descriptor-ref
      - subkey-count
      - value-count
  - type: registry-value
    parent-relation: value-of
    addressing-within-parent: value-name (UTF-16LE; empty name = "(default)")
    carries:
      - type-tag  # REG_SZ | REG_DWORD | REG_QWORD | REG_MULTI_SZ | REG_BINARY | REG_EXPAND_SZ | REG_LINK | REG_NONE
      - data

# instance-implications: concepts that a specific substrate-instance IMPOSES
# on every artifact stored inside it, regardless of whether the individual
# artifact explicitly references the concept. The per-user registry hives
# (NTUSER.DAT, UsrClass.dat) live at user-profile-scoped paths and are
# cryptographically bound to a specific SID — every key inside inherits that
# user-identity context as a matter of substrate, not per-artifact declaration.
instance-implications:
  NTUSER.DAT:
    inherits-concepts:
      - concept: UserSID
        role: profileOwner
        rationale: "Every key in NTUSER.DAT is scoped to the profile that owns the hive file (C:\\Users\\<name>\\NTUSER.DAT). The owning SID is inherited by every artifact inside."
  UsrClass.dat:
    inherits-concepts:
      - concept: UserSID
        role: profileOwner
        rationale: "UsrClass.dat lives under %LOCALAPPDATA% and is the per-user Shell\\Classes hive — same SID-binding as NTUSER.DAT."

persistence:
  live-system-location:
    SYSTEM:   "%WINDIR%\\System32\\config\\SYSTEM"
    SOFTWARE: "%WINDIR%\\System32\\config\\SOFTWARE"
    SAM:      "%WINDIR%\\System32\\config\\SAM"
    SECURITY: "%WINDIR%\\System32\\config\\SECURITY"
    DEFAULT:  "%WINDIR%\\System32\\config\\DEFAULT"
    NTUSER:   "%USERPROFILE%\\NTUSER.DAT"
    USRCLASS: "%LOCALAPPDATA%\\Microsoft\\Windows\\UsrClass.dat"
    Amcache:  "%WINDIR%\\AppCompat\\Programs\\Amcache.hve"
  locked-on-live-system: true
  acquisition:
    methods:
      - VSC-based copy (vssadmin, shadowcopy)
      - raw-disk read (FTK Imager, dd over kernel driver)
      - reg.exe save (requires SYSTEM token for non-user hives)
      - volume snapshot (cloud agents, EDR)
    caveat: live copies from C:\Windows\System32\config without VSC will fail sharing violation

transaction-log:
  files:
    - <hive>.LOG1
    - <hive>.LOG2
  format: HvLE (Win8.1+) or older DIRT header
  role: write-ahead log for dirty pages
  replay-requirement: MANDATORY before parsing if secondary-sequence-number != primary-sequence-number
  risk-if-skipped:
    - stale values reported as current
    - recent writes invisible
    - evidentiary error rising to C1 (contradicts ground truth)
  tools-that-replay: [RegistryExplorer, regipy, yarp, python-registry (partial)]

parsers:
  - name: Registry Explorer / RECmd
    author: Eric Zimmerman
    strengths: [transaction log replay, deleted-key recovery, GUI + bulk mode]
    weaknesses: [Windows-only binary]
  - name: regipy
    author: Martin Korman
    strengths: [Python, transaction log replay, plugin system]
  - name: RegRipper / rip.pl
    author: Harlan Carvey
    strengths: [battle-tested plugins, bulk extraction]
    weaknesses: [no transaction log replay in older versions; check plugin age]
  - name: python-registry
    author: Willi Ballenthin
    strengths: [programmatic access, clean API]
    weaknesses: [no transaction log replay]
  - name: Volatility registry plugins
    strengths: [live-memory hive extraction]
    weaknesses: [memory-resident only; on-disk hives better parsed elsewhere]
  - name: yarp
    author: Maxim Suhanov
    strengths: [format-correctness focus, transaction log aware, deleted-cell recovery]

forensic-relevance:
  - deleted-keys-recoverable:
      scope: unallocated cells within HBIN blocks
      caveat: recovery is opportunistic; overwrite probability rises with registry activity
      tools: [yarp, Registry Explorer, regipy recovery mode]
  - slack-space:
      scope: padding within allocated cells + freed cells in HBINs
      value: can retain fragments of prior values after value-data rewrite
  - security-descriptors:
      scope: SK cells
      value: historical ACL state; rarely examined but material in insider-threat cases
  - last-write-timestamps:
      scope: NK cells (keys only — values do not have their own timestamps)
      update-trigger: any value add/delete/modify within the key; any subkey add/delete
      NOT-updated-by: reading a value; opening the key; listing children
      clock-skew-sensitivity: high — system clock drift propagates directly

integrity:
  signing: none
  mac: none
  audit:
    available: yes (Object Access audit policy, SACLs on specific keys)
    default: off
    per-value-granularity: no (audit is per-key)
  tamper-vectors:
    - direct write via reg.exe / regedit.exe (requires write perms)
    - offline hive edit (no audit trail)
    - transaction log tampering (pre-commit dirty pages can be replayed to rewrite state)
    - unallocated cell overwrite (destroys deleted-key recovery)

anti-forensic-concerns:
  - tool: USBOblivion
    effect: targeted key removal; leaves detectable gaps in related logs
  - tool: CCleaner (registry module)
    effect: broad but shallow; often misses Properties subkeys and per-user scope
  - tool: manual reg.exe delete
    effect: surgical; hardest to detect from registry alone
  - technique: transaction-log-only rollback
    effect: restores pre-change state while LOG files still carry dirty pages — forensic artifact
  - technique: null-byte overwrite of cell
    effect: destroys readable content but cell allocation pattern remains

known-artifacts:
  # Container-declared artifact roster. The `authored` list below was the
  # seed set — the project has since grown far beyond it; the authoritative
  # roster is now whatever `artifacts/windows-registry/*.md` files exist.
  # The `unwritten` list below is the only part that still drives behavior:
  # names listed there without a matching artifact file produce GHOST nodes
  # in the graph (telling the analyst "this artifact is expected but not
  # yet authored"). Keep unwritten: entries current; the authored: list is
  # now informational.
  authored:
    - Amcache-InventoryApplicationFile
    - Amcache-InventoryApplication
    - Amcache-InventoryApplicationShortcut
    - Amcache-InventoryDevicePnp
    - Amcache-InventoryDeviceContainer
    - Amcache-InventoryDriverBinary
    - Amcache-InventoryDriverPackage
    - AppInit-DLLs
    - BAM
    - Credentials-cached
    - DNSCache
    - EMDMgmt
    - LastVisitedPidlMRU
    - MountedDevices
    - MountPoints2
    - MUICache
    - NetworkList-profiles
    - OpenSavePidlMRU
    - ProfileList
    - RecentDocs
    - Run-Keys
    - SAM
    - Scheduled-Tasks
    - Services
    - ShellBags
    - ShimCache
    - TaskbarLayout
    - TimeZoneInformation
    - TS-Client-MRU
    - USBSTOR
    - UserAssist
    - WindowsPortableDevices
    - Winlogon-Userinit-Shell
    - WMI-Subscriptions
    - FirewallRules
    - USB-Enum
  unwritten:
    # Genuine not-yet-authored registry artifacts the project expects to
    # author later. Build-time ghost nodes appear for any name listed here
    # without a matching artifacts/windows-registry/<name>.md file. Previous
    # seed entries (TypedPaths, TypedURLs, WordWheelQuery, OfficeMRU, DAM,
    # ComputerName, OS-Version, LSA-Secrets, Audit-Policy, RunMRU,
    # FeatureUsage, RecentApps, ImageFileExecutionOptions, AppPaths,
    # AutoLogon, AppCertDlls, TerminalServerClient-Default) have since
    # been authored and were removed from this list.
    - name: UserShellFolders
      location: NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
      value: known-folder path overrides — Desktop/Downloads/AppData redirection for evasion
    - name: PendingFileRenameOperations
      location: SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations
      value: queued post-reboot file moves/deletes — precursor to cleanup on next boot
    - name: TcpIp-Parameters-Interfaces
      location: SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\<adapter-guid>
      value: DHCP-learned + static IP / DNS / gateway per interface; lease source; persistent network config
    - name: WDigest-UseLogonCredential
      location: SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
      value: cleartext-cred-in-lsass enable flag; attacker sets to 1 to force lsass to hold plaintext passwords
    - name: NGC-Policy
      location: SOFTWARE\Microsoft\Policies\PassportForWork
      value: Windows Hello for Business policy state — PIN complexity requirements, biometric permissions

cross-references:
  related-containers:
    - windows-ntfs-metadata   # $MFT timestamps on the hive file itself
    - windows-evtx            # Security.evtx 4657 (registry value modified) when auditing enabled
  canonical-hives:
    - SYSTEM
    - SOFTWARE
    - SAM
    - SECURITY
    - DEFAULT
    - NTUSER.DAT
    - UsrClass.dat
    - Amcache.hve
    - COMPONENTS
    - BBI

platform-scope:
  windows:
    min: XP
    max: "11"
  windows-server:
    min: 2003
    max: "2025"
provenance:
  - aboutdfir-nd-usb-devices-windows-artifact-r
  - libyal-libfwsi
  - libyal-libregf
  - regripper-plugins
  - winreg-kb-most-recently-used
  - winreg-kb-mounted-devices
  - winreg-kb-mountpoints2
  - winreg-kb-typed-paths
  - carvey-2022-windows-forensic-analysis-tool
  - ms-attack-surface-reduction-rules-rule
  - ms-bitlocker-registry-configuration-re
  - ms-cached-credentials-cachedlogonscoun
  - ms-cmd-exe-d-switch-and-autorun-regist
  - ms-configuration-service-provider-csp
  - ms-configuring-automatic-debugging-aed
  - ms-controlled-folder-access-anti-ranso
  - ms-credential-guard-manage-configure-a
  - ms-group-policy-registry-extension-and
  - ms-name-resolution-policy-table-nrpt-r
  - ms-network-list-service-and-the-signat
  - ms-registry-editor-navigation-state-pe
  - ms-the-system-registry-is-no-longer-ba
  - ms-tls-registry-settings-schannel-conf
  - ms-uninstall-registry-key-applications
  - ms-windows-certificate-stores-registry
  - ms-windows-defender-firewall-registry
  - ms-windows-install-registry-values-cur
  - ms-windows-installer-products-registry
  - ms-windows-subsystem-for-linux-registr
  - ms-winlogon-registry-entries
  - online-2021-registry-hive-file-format-prim
  - stig-2023-windows-10-11-security-technic
---

# Windows Registry Hive (REGF)

## Forensic value
The registry is the highest-density structured artifact container on Windows. A single hive carries thousands of forensically relevant keys spanning device history, program execution, user activity, persistence mechanisms, network configuration, and authentication state. No other substrate produces as many distinct artifacts per file.

The format is well-documented and stable — the REGF layout has been unchanged in material ways since Windows 2000. This stability is what makes registry forensics teachable: parsers built against the Metz/Norris specifications work across 20+ years of Windows versions with only additive feature handling.

## Addressing within a hive

An artifact inside this container names itself via a key-path relative to the hive's root:

```
SYSTEM\CurrentControlSet\Enum\USBSTOR\<class-id>\<instance-id>
```

The hive name (`SYSTEM`) is the container; the remainder is the path. Where `CurrentControlSet` appears, it's a runtime symlink to whichever `ControlSet00N` is current — parsers may return the literal `ControlSet001` (or whichever) depending on whether they resolve the link.

For individual values, address as `<key-path>\<value-name>`. The default (unnamed) value is conventionally written as `(default)` or `@`.

## The transaction log trap

Every examiner eventually hits this. A hive read without LOG replay can show:

1. **Values absent that are present** — a value written but not yet flushed to the primary file lives only in LOG1/LOG2. Skipping replay makes it invisible.
2. **Values present that are stale** — LOG entries supersede the on-disk primary. Reading the primary without replay returns pre-write state.
3. **Last-write times that are wrong** — NK cell timestamps in the primary may predate the last real write by the LOG flush interval.

The secondary-sequence-number check in the REGF header is the authoritative signal: if it doesn't match the primary-sequence-number, the hive is dirty. Treat every live-system hive acquisition as dirty unless proven otherwise.

## Deleted-key recovery

When a key is deleted:
- The NK cell is marked unallocated (size field becomes positive rather than negative)
- Subkey list entries referencing it are updated
- The cell contents are NOT zeroed

Result: the NK header, class name, and last-write timestamp survive in unallocated space until the cell is reallocated for another purpose. Recovery tools (yarp, Registry Explorer's recovery mode, regipy) walk HBIN unallocated space and reassemble what they find.

Evidentiary caveat: recovered deleted keys cannot be placed in the hierarchy with certainty — the parent pointer may have been overwritten. Report them as "a key with this name and last-write existed in this hive; parent context uncertain."

## Parser disagreements you will encounter

- **CurrentControlSet resolution**: some parsers return the literal `ControlSet001`; others resolve and return `CurrentControlSet`. Affects key-path string matching in triage scripts.
- **Transaction log replay coverage**: Win8.1 introduced HvLE log format; older parsers silently skip replay on modern hives. Check parser version dates.
- **Value-data decoding for REG_MULTI_SZ with missing terminators**: varies between parsers. Some return all strings, some truncate at the first malformed terminator.
- **Embedded NULs in REG_SZ**: Windows tolerates them; some parsers truncate; some preserve.

## Collection notes

Live acquisition of `C:\Windows\System32\config\*` fails with sharing violations. Use one of:
- `reg save HKLM\SYSTEM C:\out\SYSTEM` (requires SYSTEM token for non-user hives; admin insufficient for SAM)
- Shadow copy + file copy from the snapshot path
- Raw-disk imaging with FTK Imager or dd+kernel driver
- EDR tooling that has kernel-level file access

NTUSER.DAT and UsrClass.dat for logged-in users are also locked. For the interactive user, their hive is loaded under `HKEY_USERS\<SID>` and can be `reg save`d from there.

## Anti-forensic caveats

See the YAML `anti-forensic-concerns:` block for tool-level summary. The operational takeaway: registry cleanup tools almost never cover the full footprint of the artifact they're targeting. A "clean" USBSTOR with residual entries in MountedDevices, MountPoints2, DriverFrameworks events, Partition/Diagnostic events, and setupapi.dev.log is a signal that cleanup was attempted — the absence itself is an affirmative finding.

## Practice hints

- Use yarp's `yarp-print` to dump a known hive with deleted-cell recovery enabled. Compare output against Registry Explorer.
- Take a baseline SYSTEM hive, run USBOblivion on a VM, re-acquire. Diff the hives using Registry Explorer's "compare" feature. Observe which related artifacts (MountedDevices, Properties subkeys, security descriptors) the tool missed.
- Deliberately break a hive's integrity: edit a value via regedit, then inspect LOG1/LOG2 with yarp before restart. See the dirty-page content before flush.
