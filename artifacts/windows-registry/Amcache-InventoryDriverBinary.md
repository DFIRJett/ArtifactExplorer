---
name: Amcache-InventoryDriverBinary
aliases:
- Amcache driver binary inventory
- Amcache kernel driver cache
link: persistence
tags:
- timestamp-carrying
- kernel
- persistence-adjacent
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
  path: Root\InventoryDriverBinary\<DriverPath>
  addressing: hive+key-path
fields:
- name: DriverName
  kind: path
  location: DriverName value
  type: REG_SZ
  note: full path to the driver file (typically .sys)
  references-data:
  - concept: ExecutablePath
    role: loadedModule
- name: DriverId
  kind: hash
  location: DriverId value
  type: REG_SZ
  note: Microsoft-computed identifier for the driver
- name: DriverCheckSum
  kind: hash
  location: DriverCheckSum value
  type: REG_DWORD
- name: DriverCompany
  kind: label
  location: DriverCompany value
  type: REG_SZ
  note: signing publisher
- name: DriverVersion
  kind: identifier
  location: DriverVersion value
  type: REG_SZ
- name: Product
  kind: label
  location: Product value
  type: REG_SZ
- name: Service
  kind: identifier
  location: Service value
  type: REG_SZ
  note: if the driver registers a service, its service-name — cross-references HKLM\SYSTEM\...\Services\<name>
- name: WdfVersion
  kind: version
  location: WdfVersion value
  type: REG_SZ
  note: Windows Driver Framework version (null for pure-kernel drivers)
- name: ImageSize
  kind: size
  location: ImageSize value
  type: REG_DWORD
- name: Inf
  kind: path
  location: Inf value
  type: REG_SZ
  note: driver install INF file reference
- name: IsKernelMode
  kind: flag
  location: IsKernelMode value
  type: REG_DWORD
- name: Signed
  kind: flag
  location: Signed value
  type: REG_DWORD
  note: 1 = driver signature verified; 0 = unsigned (test-signing / PatchGuard bypass setup)
- name: DriverSigned
  kind: flag
  location: DriverSigned value
  type: REG_DWORD
- name: DriverLastWriteTime
  kind: timestamp
  location: DriverLastWriteTime value
  type: REG_QWORD
  encoding: filetime-le
  note: most-recent filesystem modification time of the driver binary
- name: DriverTimeStamp
  kind: timestamp
  location: DriverTimeStamp value
  type: REG_DWORD
  encoding: unix-epoch-seconds
  note: PE compile timestamp from the driver's header
- name: key-last-write
  kind: timestamp
  location: subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: DRIVER_PRESENT
  ceiling: C3
  note: Evidence that a specific driver file was observed on the system. Critical for BYOVD (bring-your-own-vulnerable-driver) investigations and kernel-persistence hunts.
  qualifier-map:
    object.driver.path: field:DriverName
    object.driver.company: field:DriverCompany
    object.driver.signed: field:Signed
    time.compile: field:DriverTimeStamp
    time.last_modified: field:DriverLastWriteTime
anti-forensic:
  write-privilege: admin
  known-cleaners:
  - tool: manual hive edit
    typically-removes: surgical
detection-priorities:
  - Signed=0 drivers present — unsigned drivers on Win10/11 require test-signing or attacker-enabled signature bypass
  - DriverCompany empty OR '<unknown>' with IsKernelMode=1 — anonymous kernel-mode driver, strong BYOVD indicator
  - DriverTimeStamp far older than DriverLastWriteTime on a legitimate-looking driver path — recently dropped an old vulnerable driver
provenance: []
---

# Amcache-InventoryDriverBinary

## Forensic value
Kernel-mode driver catalog. Every driver file the OS observed — built-in Microsoft drivers, third-party vendor drivers, and most importantly any **attacker-dropped drivers** (BYOVD attacks).

## BYOVD hunt
Bring-Your-Own-Vulnerable-Driver attacks drop a legitimately-signed but exploitable driver (classic targets: `RTCore64.sys`, `Gdrv.sys`, `AsIO.sys`, `BIOS.sys`, various OEM-accessory drivers) and exploit it to get kernel code execution. Detection chain via InventoryDriverBinary:

1. Enumerate all entries with IsKernelMode=1
2. Filter DriverCompany against an allowlist (Microsoft, Intel, NVIDIA, known AV vendors)
3. Remaining entries are worth investigating
4. Cross-reference DriverTimeStamp (PE compile) against DriverLastWriteTime (disk mod time) — legitimate old drivers dropped fresh onto the system have a dramatic gap

## Cross-references
- **Services** — for drivers that register as services; join via the Service field
- **Sysmon-6** (Driver Loaded) — real-time event for the same driver load
- **CodeIntegrity-3077** — WDAC/HVCI blocked-driver events
- **System-7045** — if the driver is installed as a service
- **Security-4697** — service-install audit with installer context

## Practice hint
Hunting for signed-but-vulnerable drivers:
```
AmcacheParser.exe -f Amcache.hve --csv .\out
```
Then in `Amcache_InventoryDriverBinary.csv`:
```sql
-- pseudo-SQL; use jq/pandas/Excel equivalent
WHERE IsKernelMode=1
  AND Signed=1
  AND DriverCompany NOT IN (whitelist)
  AND DriverName LIKE '%\Users\%' OR '%\Temp\%' OR '%\AppData\%'
```
High-risk paths with kernel-mode signed drivers are the BYOVD signature.
