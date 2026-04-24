---
name: Services
aliases:
- Windows Services
- service control manager database
- SCM registry
link: persistence
tags:
- tamper-easy
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: NT4
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SYSTEM
  path: CurrentControlSet\Services\<ServiceName>
  addressing: hive+key-path
fields:
- name: service-name
  kind: identifier
  location: <ServiceName> subkey name
  encoding: utf-16le
  note: short internal name; e.g., 'Spooler', 'lsass', 'Schedule'
  references-data:
  - concept: ServiceName
    role: identitySubject
- name: display-name
  kind: identifier
  location: DisplayName value
  type: REG_SZ
  encoding: utf-16le
  note: human-readable name shown in services.msc
- name: image-path
  kind: path
  location: ImagePath value
  type: REG_SZ or REG_EXPAND_SZ
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: path + arguments to the service executable; may reference environment variables
- name: service-dll
  kind: path
  location: Parameters\ServiceDll value (for svchost-hosted services)
  type: REG_EXPAND_SZ
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: DLL to load into svchost.exe; common injection target
- name: start-type
  kind: enum
  location: Start value
  type: REG_DWORD
  note: 0=boot-driver, 1=system-driver, 2=auto-start, 3=manual, 4=disabled
- name: service-type
  kind: enum
  location: Type value
  type: REG_DWORD
  note: 'bitfield: 0x01=kernel driver, 0x02=file-sys-driver, 0x10=own-process user, 0x20=shared-process user, 0x100=interactive'
- name: object-name
  kind: identifier
  location: ObjectName value
  type: REG_SZ
  note: account the service runs as — 'LocalSystem', 'NT AUTHORITY\LocalService', 'NT AUTHORITY\NetworkService', or a user
    account name
- name: description
  kind: identifier
  location: Description value
  type: REG_SZ
  note: free-form description shown in services.msc; attackers typically match Microsoft descriptions for camouflage
- name: failure-command
  kind: path
  location: FailureActions\Command value
  type: REG_SZ
  note: command to execute on service failure — known persistence/abuse vector
- name: key-last-write
  kind: timestamp
  location: <ServiceName> subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'Service Control Manager registry definition. Auto-start services run

    at boot under the specified ObjectName; manual services run when

    triggered. Classic persistence mechanism with elevated privilege —

    LocalSystem services have SYSTEM token, most powerful local context.

    '
  qualifier-map:
    setting.service-name: field:service-name
    setting.executable: field:image-path
    setting.service-account: field:object-name
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  known-cleaners:
  - tool: sc delete <name>
    typically-removes: full
    note: legitimate service removal; emits Service Control Manager event 7036
  - tool: direct registry delete of the Services\<name> subkey
    typically-removes: full
    note: no audit trail; service still runs until reboot
  survival-signals:
  - ImagePath references a non-Microsoft-signed binary in a non-standard path (user %TEMP%, %APPDATA%, etc.)
  - ObjectName = LocalSystem + ImagePath = suspicious path = top-tier priority
  - Description field matches a legitimate Microsoft service but ServiceName/ImagePath differ = classic masquerade pattern
provenance:
  - mitre-t1574
  - mitre-t1543
  - mitre-t1543-003
exit-node:
  is-terminus: true
  primary-source: mitre-t1543-003
  attribution-sentence: 'Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence (MITRE ATT&CK, n.d.).'
  terminates:
    - PERSISTED
    - CONFIGURED
  sources:
    - mitre-t1574
    - mitre-t1543
    - mitre-t1543-003
  reasoning: >-
    The Services registry subkey (HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>) is the machine-local authoritative definition of every Windows service — ImagePath, ServiceDll, StartType, RequiredPrivileges, Triggers. For the questions 'what service is configured here' and 'what does this service run when started,' the Services key IS the terminus. No downstream artifact provides a more authoritative binding between ServiceName and the binary it executes.
  implications: >-
    Defensible citation for service-persistence attribution. When Security-7045 (service installed) is missing or cleared, the current Services key state plus its last-write timestamp still anchors the claim that service X was configured to run binary Y. Classic attacker patterns (ServiceDll hijack, sc.exe create with binPath= to malicious DLL, COR_ENABLE_PROFILING abuse) all terminate here. Cross-validates with Amcache (file existed) and Prefetch (it ran).
  preconditions: "SYSTEM hive accessible; attacker did not delete the Services subkey (rare — would break the service)"
  identifier-terminals-referenced:
    - ServiceName
    - ExecutablePath
---

# Windows Services

## Forensic value
Registry-backed service definitions. Every Windows Service (auto-start, manual, driver) has a subkey under `SYSTEM\CurrentControlSet\Services\`. Core persistence mechanism with elevated execution context — LocalSystem-hosted services have more privilege than any logged-in user.

Investigative first-pass: enumerate all services, filter by (a) ObjectName = LocalSystem, (b) Start = 2 (auto-start), (c) Signer = unsigned OR non-Microsoft. Anomalies reveal fast.

## Concept reference
- ExecutablePath (ImagePath + ServiceDll for svchost-hosted)
- (Indirectly) UserSID via ObjectName — but ObjectName can be a friendly name like "LocalSystem" rather than a SID, so it's weaker pivot than direct SID fields

## Key investigative patterns
- **svchost.exe shared processes** host many legitimate services but also a popular attacker pivot. Check Parameters\ServiceDll to see what's actually loaded.
- **Failure-command abuse.** Some services define recovery commands that run on failure. Setting a service to fail + FailureCommand = cmd.exe /c ... is a known persistence trick.
- **Driver services (Type=0x01 or 0x02).** Kernel drivers run below Windows itself. Forensic detection is harder; check for unusual driver service entries.

## Practice hint
Compare `Get-Service | Export-Csv services-live.csv` against a reference Win10 baseline. Unique services on your system deserve attention. For each, inspect ImagePath + Description in regedit.
