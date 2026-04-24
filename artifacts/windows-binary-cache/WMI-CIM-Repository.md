---
name: WMI-CIM-Repository
title-description: "WMI CIM repository files — OBJECTS.DATA / INDEX.BTR / MAPPINGx.MAP holding compiled MOF class instances"
aliases:
- WMI repository
- CIM repository
- OBJECTS.DATA
- WBEM repository
link: persistence
link-secondary: application
tags:
- persistence-primary
- offline-forensics
- itm:PR
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: WMI-CIM-Repository
platform:
  windows:
    min: NT5.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  path: "%WINDIR%\\System32\\wbem\\Repository\\"
  addressing: file-path
  note: "Three-file set forming the compiled WMI database: OBJECTS.DATA (the class-instance store), INDEX.BTR (B-tree index into OBJECTS.DATA), and MAPPINGx.MAP pairs (transactional mapping of logical-page-to-physical-offset, numbered 1/2/3 rotating). All three are required for coherent parsing — acquire the entire Repository directory. The companion live interface is the WMI namespace (root\\subscription for persistence filters); THIS artifact is the on-disk form that survives when wmiprvse.exe / Winmgmt service are offline or the database is unmountable on the live system."
fields:
- name: class-instance
  kind: content
  location: "OBJECTS.DATA — instance blob keyed by logical page ID"
  encoding: CIM binary-encoded class instance
  note: "Every class instance committed to the repository — user-authored MOF compilations, __EventFilter / __EventConsumer / __FilterToConsumerBinding (persistence primitives), and all inbox WMI classes. Attacker-installed persistence lives here alongside legitimate content; differencing the repository against a clean-install baseline reveals adds."
- name: event-filter
  kind: identifier
  location: "OBJECTS.DATA — __EventFilter instances (under root\\subscription namespace)"
  encoding: CIM-encoded
  note: "WQL queries that define trigger conditions. Attacker-created filters often watch timer events (__IntervalTimerInstruction) or process-creation events (__InstanceCreationEvent for Win32_Process). A filter with a query that obviously matches attacker triggering semantics and a non-Microsoft Name = persistence primitive."
- name: event-consumer
  kind: path
  location: "OBJECTS.DATA — CommandLineEventConsumer / ActiveScriptEventConsumer / LogFileEventConsumer instances"
  encoding: CIM-encoded
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Action invoked when a Filter fires. CommandLineEventConsumer with an ExecutablePath field pointing outside System32 / Program Files = classic WMI-persistence attacker consumer. ActiveScriptEventConsumer with ScriptingEngine='VBScript' holding a base64 / obfuscated script body = scripted payload."
- name: filter-to-consumer-binding
  kind: identifier
  location: "OBJECTS.DATA — __FilterToConsumerBinding instances"
  encoding: CIM-encoded references
  note: "Glue object that pairs a specific Filter to a specific Consumer. The three (Filter + Consumer + Binding) together complete the persistence — any one missing = partial plant that won't fire. Look for triples where Filter name, Consumer name, and Binding references all line up against non-Microsoft identifiers."
- name: namespace-provider
  kind: label
  location: "OBJECTS.DATA — __Provider instances in root\\subscription and root\\default"
  encoding: CIM-encoded
  note: "Registered WMI providers (native DLLs serving classes). Providers pointing to non-Microsoft DLLs = provider-hijack variant of WMI persistence. Cross-reference against HKLM\\SOFTWARE\\Microsoft\\WBEM\\CIMOM for live-registered providers."
- name: index-btree
  kind: identifier
  location: "INDEX.BTR — B-tree index nodes"
  encoding: proprietary B-tree format
  note: "Index file enabling class-instance lookup without scanning OBJECTS.DATA sequentially. Not directly forensic but REQUIRED for parser operation. Missing INDEX.BTR = the repository is in an inconsistent state and Winmgmt will attempt auto-repair on next service start (which may destroy forensic-relevant records)."
- name: mapping-file
  kind: identifier
  location: "MAPPING1.MAP / MAPPING2.MAP / MAPPING3.MAP — transactional logical-to-physical mapping"
  encoding: proprietary transactional log
  note: "Pair of mapping files in rotating use; the active one is determined by sequence counter in MAPPINGVERSION.TXT. Holds the logical-page-id → physical-offset mapping that Winmgmt uses to find the committed state as of the last flush. Required for correct parsing."
- name: repository-mtime
  kind: timestamp
  location: "OBJECTS.DATA / INDEX.BTR / MAPPINGx.MAP file $SI modified time"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtimes of the three files. Updates when Winmgmt commits a write — new class registration, new __EventFilter, new __EventConsumer, etc. mtime inside incident window = repository was touched; correlate with WMI-Activity/Operational events 5857 (filter-to-consumer activity), 5858 (query error), 5859 (permanent subscription trigger)."
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'WMI event-based persistence (MITRE T1546.003) stores all its
    state here — Filter, Consumer, Binding triples committed to the
    CIM repository survive reboot, run as LOCAL SYSTEM via wmiprvse,
    and trigger on whatever WQL query the attacker authored. Live
    WMI inspection via Get-WmiObject sees the same state BUT only
    when Winmgmt is healthy — if the service is stopped, the
    repository is corrupted, or the host is offline, the live query
    path fails and the on-disk repository is the only access.
    Proper DFIR acquires the full Repository directory and parses
    offline to recover persistence even when the live namespace is
    unavailable.'
  qualifier-map:
    setting.file: "OBJECTS.DATA / INDEX.BTR / MAPPINGx.MAP"
    setting.command: field:event-consumer
    time.start: field:repository-mtime
anti-forensic:
  write-privilege: kernel-only
  integrity-mechanism: transactional log via MAPPING files; no content signing
  known-cleaners:
  - tool: winmgmt /resetrepository
    typically-removes: full wipe of custom class instances (auto-repair rebuilds stock content from MOF files). Effectively destroys forensic evidence — MOFs get recompiled from %WINDIR%\\System32\\wbem\\*.mof (baseline) but attacker-added subscriptions are gone.
  - tool: rename Repository\ directory while Winmgmt stopped
    typically-removes: forces repository recreation on service restart
  survival-signals:
  - OBJECTS.DATA mtime within incident window = repository was written to; expect to find plant via offline parse
  - CommandLineEventConsumer with ExecutablePath outside System32 = classic persistence
  - ActiveScriptEventConsumer with base64-encoded ScriptText body = obfuscated payload
  - __EventFilter with NAME matching known-bad campaign signatures (check threat-intel feeds for known consumer names)
  - Repository directory missing when Winmgmt log shows recent activity = destroyed repository (rebuild in progress)
provenance:
  - ms-windows-management-instrumentation
  - mitre-t1546-003
  - ballenthin-2016-python-cim-wmi-cim-repository
exit-node:
  is-terminus: true
  primary-source: mitre-t1546-003
  attribution-sentence: 'Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription (MITRE ATT&CK, n.d.).'
  terminates:
    - PERSISTED
    - CONFIGURED
  sources:
    - ms-windows-management-instrumentation
    - mitre-t1546-003
    - ballenthin-2016-python-cim-wmi-cim-repository
  reasoning: >-
    CIM repository (OBJECTS.DATA + INDEX.BTR + MAPPING*.MAP) is the authoritative on-disk store for WMI class definitions, instances, and permanent event subscriptions. For PERSISTED (specifically WMI subscription persistence — ActiveScriptEventConsumer, CommandLineEventConsumer) and CONFIGURED (WMI namespace state), the repository IS the terminus — no alternative store exists. WMI-event-subscription persistence (T1546.003) cannot be evidenced anywhere else.
  implications: >-
    Post-compromise WMI-persistence hunting: parsing OBJECTS.DATA with python-cim or PyWMIPersistenceFinder yields the full subscription graph (filter + consumer + binding triads). Directly answers 'is this host WMI-backdoored?' without corroboration. Survives reboot and most standard cleanup — attacker must run Remove-WmiObject OR hand-edit the repository to remove subscriptions they added.
  preconditions: '%SystemRoot%\System32\wbem\Repository\ files accessible offline'
  identifier-terminals-referenced:
    - ExecutablePath
    - RegistryKeyPath
---

# WMI CIM Repository

## Forensic value
The WMI CIM repository is the on-disk persistent database backing the live WMI namespace hierarchy. Three-file set:

- **`OBJECTS.DATA`** — the class-instance store
- **`INDEX.BTR`** — B-tree index into OBJECTS.DATA
- **`MAPPING1.MAP` / `MAPPING2.MAP` / `MAPPING3.MAP`** — transactional logical-to-physical mapping

Located at `%WINDIR%\System32\wbem\Repository\`.

This is where **WMI event-based persistence** (MITRE T1546.003) lives on disk. The live WMI-Subscriptions artifact covers the live-namespace query path (`Get-WmiObject -Namespace root\subscription ...`) — this artifact covers the on-disk file set, which must be acquired and parsed offline when:

- Winmgmt service is stopped or corrupted
- The host is offline / imaged
- Live-query results are suspected to have been tampered with

## Why this is separate from WMI-Subscriptions
`WMI-Subscriptions.md` in the inventory documents the live WMI view — `root\subscription` Filter / Consumer / Binding objects. This artifact documents the **file-level container** that holds those objects on disk. The distinction matters in two scenarios:

1. **Offline imaging** — you have a disk image, no live system. Parse the repository with `python-cim` offline.
2. **Service-tampered hosts** — an attacker stops Winmgmt or corrupts the namespace to hide live queries; the raw files still hold the evidence.

## Concept reference
- ExecutablePath (via CommandLineEventConsumer ExecutablePath entries)

## Parsing
```bash
# python-cim (FireEye flare-wmi)
pip install python-cim
python -m cim.examples.list_namespaces --path .\Repository\
python -m cim.examples.list_class_instances --path .\Repository\ --namespace root\subscription --class __EventFilter
python -m cim.examples.list_class_instances --path .\Repository\ --namespace root\subscription --class CommandLineEventConsumer
```

Each Filter / Consumer / Binding recovered from offline parse maps 1:1 with what `Get-WmiObject -Namespace root\subscription ...` would have returned if the system were live and healthy.

## Acquisition
```cmd
:: Stop Winmgmt to release file locks (destructive to live operations — use VSC copy instead on production)
net stop Winmgmt
robocopy %WINDIR%\System32\wbem\Repository .\evidence\wmi-repo\ /MIR
net start Winmgmt
```

On a production system prefer VSC-copy or disk-image acquisition rather than stopping the service.

## Cross-reference
- `Microsoft-Windows-WMI-Activity/Operational` EVTX channel
  - Event 5857 — filter-to-consumer activity
  - Event 5858 — query error
  - Event 5859 — permanent subscription triggered
- `HKLM\SOFTWARE\Microsoft\WBEM\CIMOM` — provider DLL registration
- `HKLM\SOFTWARE\Microsoft\WBEM\Transports` — registered transports

## Practice hint
On a test VM, register a harmless permanent subscription:
```powershell
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='DFIRTest'; EventNameSpace='root\cimv2'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System" AND TargetInstance.SystemUpTime >= 200'; QueryLanguage='WQL'}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='DFIRTest'; CommandLineTemplate='cmd /c echo fired > C:\temp\wmi-fired.txt'}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$filter; Consumer=$consumer}
```
Observe OBJECTS.DATA mtime updating. Stop Winmgmt, copy the Repository folder, parse offline with python-cim — you'll find your Filter, Consumer, and Binding triple. Clean up:
```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='DFIRTest'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='DFIRTest'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like '*DFIRTest*' } | Remove-WmiObject
```
