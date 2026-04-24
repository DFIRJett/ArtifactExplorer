---
name: Installer-Products-SourceList
title-description: "MSI Installer Products SourceList — UNC / network path each installed MSI came from"
aliases:
- Installer Products SourceList
- MSI install source path
- SourceList Net key
link: application
tags:
- install-provenance
- supply-chain-trace
volatility: persistent
interaction-required: user-session
substrate: windows-registry-hive
substrate-instance: SOFTWARE and NTUSER.DAT
platform:
  windows:
    min: '2000'
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SOFTWARE (HKCR merged view) and NTUSER.DAT
  path-machine: "HKEY_CLASSES_ROOT\\Installer\\Products\\<packed-GUID>\\SourceList\\Net\\<index>"
  path-user: "HKCU\\SOFTWARE\\Microsoft\\Installer\\Products\\<packed-GUID>\\SourceList\\Net\\<index>"
  addressing: hive+key-path
  note: "Every MSI-installed application registers a ProductCode GUID under Installer\\Products. The SourceList\\Net subkey holds the source network / UNC path(s) the MSI was installed from. Each indexed value ('1', '2', '3'...) is a distinct source path. The packed-GUID format is a reordered form of the ProductCode GUID (groups 1-3 reversed) — parsers like RECmd handle the unpack. Crucial for supply-chain investigations: SourceList\\Net reveals WHERE the MSI payload came from — an attacker who installed an MSI from a staged share leaves the share path here even after removing the share."
fields:
- name: source-path
  kind: path
  location: "SourceList\\Net\\<index> value data"
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "UNC path or local path of the MSI source directory. Legitimate: '\\\\fileserver\\software$\\Office365\\', 'C:\\Installers\\'. Attacker: '\\\\attacker-c2\\share\\', '\\\\compromised-fileshare\\staged\\', or a drive letter matching a removable USB. This value persists EVEN AFTER the source share is taken down — preserving the attacker's staging location for investigators."
- name: packed-guid
  kind: identifier
  location: "Installer\\Products\\<packed-GUID> subkey name"
  encoding: reordered-guid (groups 1-3 byte-swapped)
  note: "The MSI ProductCode, reordered for lexical indexing. Unpack by reversing groups 1 and 2 (8+4+4 chars) and pairwise-swapping group 3 (16 chars). Join to the Uninstall-Keys artifact by computing the ProductCode → matches the Uninstall subkey's DisplayName / ProductCode."
- name: package-name
  kind: label
  location: "Installer\\Products\\<packed-GUID>\\SourceList\\PackageName value"
  type: REG_SZ
  note: "Filename of the .msi package as installed (e.g., 'VisualStudioCode.msi', 'attacker-payload.msi'). Combined with source-path reveals the full original install location."
- name: product-name
  kind: label
  location: "Installer\\Products\\<packed-GUID>\\ProductName value"
  type: REG_SZ
  note: "Product name as registered by the MSI. Cross-references to the Uninstall-Keys DisplayName for the same ProductCode."
- name: last-used-source
  kind: counter
  location: "SourceList\\LastUsedSource value"
  type: REG_SZ
  note: "Index of the most-recently-used source from the Net subkey. Useful when multiple sources are listed — identifies the one actually used for the last installer operation (install / repair / update)."
- name: media-source
  kind: path
  location: "SourceList\\Media\\<index> value data"
  type: REG_SZ
  note: "Media source (local or CD-ROM / DVD path). Sibling to Net, captures non-network install sources. USB-delivered MSIs often appear here with a drive-letter path matching the USB's mount at install time."
- name: key-last-write
  kind: timestamp
  location: SourceList\\Net subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on SourceList or SourceList\\Net reflects last-install / last-repair write time. Correlate with Uninstall-Keys InstallDate / key-last-write for the same product to confirm install event timing."
observations:
- proposition: INSTALLED_FROM_SOURCE
  ceiling: C4
  note: 'MSI SourceList is the authoritative record of WHERE each
    installed MSI package came from. For supply-chain investigations,
    the SourceList\\Net path is direct evidence of the attacker''s
    staging server, compromised file share, or USB drop-vector.
    Because this value persists through application lifecycle events
    (repair, upgrade, normal operation), it is a durable witness even
    long after the source location has been cleaned up or
    decommissioned. Crucial complement to Uninstall-Keys: Uninstall
    tells you WHAT is installed; SourceList tells you WHERE IT CAME
    FROM.'
  qualifier-map:
    peer.path: field:source-path
    object.name: field:package-name
    time.start: field:key-last-write
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  survival-signals:
  - SourceList\\Net with UNC path to a file share not in the enterprise documented share inventory = candidate staging server
  - Source path pointing to a local %TEMP% / Downloads / USB drive = attacker MSI drop-location captured
  - PackageName resembling attacker-common product names ('Update', 'System', 'Config') with uncommon source path = attacker MSI
provenance:
  - ms-windows-installer-products-registry
---

# Installer Products SourceList

## Forensic value
Every MSI-installed application registers a ProductCode GUID under `Installer\Products\`. Under each ProductCode's `SourceList\Net\` subkey, Windows records the source UNC / local path(s) the MSI was installed from.

This is **install provenance**: not just "what is installed" (that's Uninstall-Keys) but "where did it come from."

## Why this matters for supply-chain / attacker investigations
An attacker who delivers malware via a staged MSI (compromised file share, attacker-controlled UNC, sideloaded from USB) leaves a durable pointer to their staging location here. When the attacker later cleans up:
- Removes the share
- Takes down the file server
- Extracts the USB
- Deletes the original .msi

The local `SourceList\Net\1 = \\attacker-share\path\` value persists. Long after the source has vanished, this key is the last witness to where the payload originated.

## Concept reference
- ExecutablePath (via source-path and package-name composition)

## Paths to check
Both scopes:
- `HKEY_CLASSES_ROOT\Installer\Products\<packed-GUID>\SourceList\Net\`
- `HKCU\Software\Microsoft\Installer\Products\<packed-GUID>\SourceList\Net\`

## Packed-GUID decode
The subkey name is the ProductCode with byte-groups reordered:
- Group 1 (8 chars) — reversed
- Group 2 (4 chars) — reversed
- Group 3 (4 chars) — reversed
- Group 4 + 5 (4 + 12 chars) — pairwise swap

E.g., packed `2F9C4A6B...` unpacks to `B4A6C9F2-...`. Reverse this to match against Uninstall-Keys ProductCode.

## Triage
```powershell
# Enumerate all SourceList\Net paths
Get-ChildItem "HKCR:\Installer\Products" | ForEach-Object {
    $net = Join-Path $_.PSPath "SourceList\Net"
    if (Test-Path $net) {
        $paths = Get-ItemProperty $net
        [PSCustomObject]@{
            PackedGUID = $_.PSChildName
            ProductName = (Get-ItemProperty $_.PSPath).ProductName
            Sources = ($paths.PSObject.Properties | Where-Object Name -match '^\d+$' | ForEach-Object { $_.Value }) -join '; '
        }
    }
} | Where-Object Sources | Format-Table -AutoSize
```

## Cross-reference
- **Uninstall-Keys** — join on ProductCode; unified install-inventory + provenance
- **MsiInstaller Application EVTX events** — event 1033 (install success) logged immediately after SourceList is written
- **UsnJrnl** — file-creation events for the .msi package if it was saved locally before running (reveals drop-location)
- **Security-4688** — msiexec.exe invocation with /i argument showing the source path

## Practice hint
On a lab VM: install any .msi package from a specific path (e.g., download Notepad++ installer to `C:\Users\<user>\Downloads\`). After install, navigate to `HKEY_CLASSES_ROOT\Installer\Products\` and find the packed-GUID subkey for Notepad++. Its `SourceList\Net\1` or `Media\1` will contain `C:\Users\<user>\Downloads\` (or similar). Delete the .msi file — the registry value persists. That post-deletion survival is the forensic property.
