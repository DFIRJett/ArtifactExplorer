---
name: Amcache-InventoryDriverPackage
aliases:
- Amcache driver package inventory
- Amcache driver install catalog
link: persistence
tags:
- timestamp-carrying
- kernel-adjacent
- install-history
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
  path: Root\InventoryDriverPackage\<PackageID>
  addressing: hive+key-path
fields:
- name: package-id
  kind: identifier
  location: subkey name
  note: INF package identifier (typically oem<N>.inf_<hash>)
- name: Inf
  kind: path
  location: Inf value
  type: REG_SZ
  note: INF file path (often %WINDIR%\INF\oem<N>.inf) — names the driver-install manifest that caused this driver package to be registered
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
- name: Class
  kind: label
  location: Class value
  type: REG_SZ
  note: driver class (Display / Net / HIDClass / DiskDrive / USB / SCSIAdapter / ...)
- name: ClassGuid
  kind: identifier
  location: ClassGuid value
  type: REG_SZ
- name: Date
  kind: timestamp
  location: Date value
  type: REG_SZ
  note: driver-package signing/build date as declared in the INF
- name: Version
  kind: identifier
  location: Version value
  type: REG_SZ
- name: Provider
  kind: label
  location: Provider value
  type: REG_SZ
- name: SubmissionId
  kind: identifier
  location: SubmissionId value
  type: REG_SZ
  note: WHQL submission ID (if Microsoft-certified)
- name: Hwids
  kind: identifier
  location: Hwids value
  type: REG_MULTI_SZ
  note: hardware IDs the driver claims to support — useful for mapping driver to device
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: driver-package install or reconfig
observations:
- proposition: DRIVER_INSTALLED
  ceiling: C3
  note: Install-level record of driver packages. Complements InventoryDriverBinary (per-file) with package-level metadata — publisher, INF, submission status.
  qualifier-map:
    object.driver.provider: field:Provider
    object.driver.class: field:Class
    object.driver.inf: field:Inf
    time.declared: field:Date
    time.installed: field:key-last-write
anti-forensic:
  write-privilege: admin
  known-cleaners:
  - tool: pnputil /delete-driver
    typically-removes: driver removal; Amcache entry may persist
detection-priorities:
  - SubmissionId empty AND Class IN (Display, DiskDrive, SCSIAdapter) — non-WHQL kernel-proximity driver, suspicious if not from a recognized OEM
  - Provider empty or mismatched with expected OEM — supply-chain or typosquat driver signing
provenance: []
---

# Amcache-InventoryDriverPackage

## Forensic value
Install-level driver catalog. Each entry represents a **driver package** (an INF and its dependent files) rather than an individual .sys binary. Complements Amcache-InventoryDriverBinary at a higher abstraction level.

Where InventoryDriverBinary lets you answer "is driver X.sys on this machine?", InventoryDriverPackage answers "what driver packages have been installed, by whom, and when?"

## INF + Hwids pivot
The `Inf` value points at %WINDIR%\INF\oem<N>.inf — the INF catalog lives on disk and can be parsed for install details that aren't captured in Amcache. The `Hwids` value lists hardware IDs the driver claims to serve — cross-reference with Amcache-InventoryDevicePnp entries to find which physical devices used this driver.

## WHQL status
Microsoft's Windows Hardware Quality Labs (WHQL) signing is tracked via `SubmissionId`. Populated SubmissionId = Microsoft-certified driver package. Empty SubmissionId = third-party signed (kernel-driver) OR test-signed (developer/attacker).

On a production endpoint, SubmissionId-empty entries with Class in the kernel-proximity taxonomy (DiskDrive, Display, SCSIAdapter, HIDClass) are worth enumerating — the set should be small, and unexpected entries merit investigation.

## Cross-references
- **Amcache-InventoryDriverBinary** — per-.sys-file view of the same driver ecosystem
- **setupapi-dev-log** — text log of driver install operations; complementary timeline source
- **Services** — for driver packages that register services
- **System-20001 / System-20003** — PnP device-install events for matching timestamps

## Practice hint
Driver provenance triage:
```
AmcacheParser.exe -f Amcache.hve --csv .\out
```
Then in `Amcache_InventoryDriverPackage.csv`:
```
WHERE SubmissionId = ''
  AND Class IN ('DiskDrive', 'Display', 'SCSIAdapter', 'HIDClass', 'SystemDevices')
ORDER BY key-last-write DESC
```
Review top entries for unexpected providers.
