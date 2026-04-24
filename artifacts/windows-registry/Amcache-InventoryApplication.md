---
name: Amcache-InventoryApplication
aliases:
- Amcache installed-programs inventory
- Amcache application registration
link: application
tags:
- timestamp-carrying
- software-inventory
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: Amcache.hve
platform:
  windows:
    min: '10'
    max: '11'
location:
  hive: Amcache.hve
  path: Root\InventoryApplication\<ProgramID>
  addressing: hive+key-path
fields:
- name: program-id
  kind: identifier
  location: subkey name
  note: installer-assigned program ID (hash of name+version+publisher)
- name: Name
  kind: identifier
  location: Name value
  type: REG_SZ
  note: installed program display name (matches Add/Remove Programs)
- name: Publisher
  kind: identifier
  location: Publisher value
  type: REG_SZ
- name: Version
  kind: identifier
  location: Version value
  type: REG_SZ
- name: RootDirPath
  kind: path
  location: RootDirPath value
  type: REG_SZ
  note: install location of the application
  references-data:
  - concept: ExecutablePath
    role: shellReference
- name: InstallDate
  kind: timestamp
  location: InstallDate value
  type: REG_SZ
  encoding: 'MM/DD/YYYY HH:MM:SS'
  clock: system
  resolution: 1s
- name: InstallDateArpLastModified
  kind: timestamp
  location: InstallDateArpLastModified value
  type: REG_SZ
  note: last Add/Remove-Programs touch — uninstall/repair tracking
- name: Source
  kind: label
  location: Source value
  type: REG_SZ
  note: 'MsiInstaller | Win32-installer | Store | AddRemoveProgramsRegistry | Unknown'
- name: Type
  kind: label
  location: Type value
  type: REG_SZ
  note: Application / Patch / MsuPatch / LiveTile / AppX
- name: UninstallString
  kind: command
  location: UninstallString value
  type: REG_SZ
- name: RegistryKeyPath
  kind: path
  location: RegistryKeyPath value
  note: Add/Remove Programs registry key backing this entry
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: on install, uninstall, or major update
observations:
- proposition: INSTALLED
  ceiling: C3
  note: Software-inventory artifact — distinct from InventoryApplicationFile (PE execution). Captures what the OS considers a 'program' (registered in Add/Remove Programs or Store).
  qualifier-map:
    object.software.name: field:Name
    object.software.publisher: field:Publisher
    object.software.version: field:Version
    time.installed: field:InstallDate
anti-forensic:
  write-privilege: admin
  known-cleaners:
  - tool: clean uninstall
    typically-removes: flips entry to reflect uninstall
  - tool: manual hive edit
    typically-removes: surgical
provenance: []
provenance: [libyal-libregf, regripper-plugins]
---

# Amcache-InventoryApplication

## Forensic value
The "what's installed" root of Amcache. Independent of InventoryApplicationFile (which is PE-file scoped), InventoryApplication tracks registered programs — the same set Add/Remove Programs shows, plus Store apps and MSI patches.

Forensically distinct from InventoryApplicationFile because:
- **Per program, not per binary.** A program with 50 PE files has 1 InventoryApplication entry but 50 InventoryApplicationFile entries.
- **Install-date-centric.** `InstallDate` + `InstallDateArpLastModified` date the software lifecycle, not individual binaries.
- **Captures non-PE apps.** UWP/Store/AppX apps are recorded here but not (all) in InventoryApplicationFile.

## Triage questions answered
- "What was installed on this machine?" — list InventoryApplication
- "When was software X installed?" — InstallDate for matching Name
- "Any unauthorized / unsigned publishers?" — filter Publisher for empty/Unknown
- "What was uninstalled recently?" — InstallDateArpLastModified > recent, but Name still present

## Cross-references
- **Amcache-InventoryApplicationFile** — the PE files belonging to this program; joined via containing directory or publisher
- **SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall** — the Add/Remove Programs registry source
- **Services** — for programs that install services
- **Scheduled-Tasks** — for programs that install tasks

## Practice hint
```
AmcacheParser.exe -f Amcache.hve --csv .\out
```
Eric Zimmerman's tool exports each Amcache root separately. Look at `*_InventoryApplication.csv` specifically.
