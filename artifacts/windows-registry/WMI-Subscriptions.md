---
name: WMI-Subscriptions
aliases:
- WMI event subscriptions
- __EventFilter
- __EventConsumer
- WMI persistence
link: persistence
tags: []
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: Vista
    max: '11'
location:
  hive: SYSTEM
  path: CurrentControlSet\Services\ESENT\Parameters\OBJECTS.DATA (binary database — parse via WMI namespace or Autoruns)
  live-access: Get-WmiObject -Namespace root\subscription -Class __EventFilter / __EventConsumer / __FilterToConsumerBinding
  addressing: WMI namespace + class instance
fields:
- name: filter-name
  kind: identifier
  location: __EventFilter class 'Name' property
  encoding: utf-16le
- name: filter-query
  kind: identifier
  location: __EventFilter class 'Query' property
  encoding: utf-16le
  note: WQL query that defines when the consumer fires — e.g., 'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE
    TargetInstance ISA Win32_PerfFormattedData_PerfOS_System AND TargetInstance.SystemUpTime >= 200'
- name: consumer-name
  kind: identifier
  location: __EventConsumer class 'Name' property
  encoding: utf-16le
- name: consumer-type
  kind: enum
  location: __EventConsumer subclass
  encoding: '''CommandLineEventConsumer'' / ''ActiveScriptEventConsumer'' / ''SMTPEventConsumer'' / ...'
  note: CommandLineEventConsumer runs a process; ActiveScriptEventConsumer runs VBScript/JScript inline
- name: consumer-action
  kind: path
  location: CommandLineEventConsumer 'CommandLineTemplate' / 'ExecutablePath' properties
  encoding: utf-16le
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
- name: consumer-script
  kind: identifier
  location: ActiveScriptEventConsumer 'ScriptText' property
  encoding: utf-16le
  note: inline VBScript/JScript payload for script consumers — common malware carrier
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'WMI event-subscription-based persistence. Used extensively by APT

    actors because WMI can be scheduled without Task Scheduler registry

    visibility and can respond to system-state events (uptime, user logon,

    network interface UP, etc.). Classic fileless-persistence mechanism.

    '
  qualifier-map:
    setting.filter: field:filter-query
    setting.consumer: field:consumer-action
    setting.script: field:consumer-script
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  known-cleaners:
  - tool: Remove-WmiObject
    typically-removes: full
  - tool: mofcomp /N:root\subscription deletion-file.mof
    typically-removes: full
  survival-signals:
  - WMI subscription with Consumer-script containing base64 or compressed blob = likely attacker payload
  - subscription using ActiveScriptEventConsumer on a system with no legitimate VBScript/JScript infrastructure = suspicious
provenance:
  - ballenthin-2016-python-cim-wmi-cim-repository
  - mitre-t1546-003
---

# WMI Event Subscriptions (__EventFilter / __EventConsumer)

## Forensic value
Persistence mechanism via Windows Management Instrumentation event subscriptions. A __EventFilter defines when to fire (WQL query over system state); a __EventConsumer defines what to run; a __FilterToConsumerBinding links them.

Uniquely powerful for attackers:
- Not captured in classic persistence-triage tools (Autoruns coverage is partial; requires explicit WMI checks)
- Can trigger on state changes (system uptime, interface up, process start)
- ActiveScriptEventConsumer runs script payloads with no on-disk artifact

## Concept reference
- ExecutablePath (consumer action path for CommandLineEventConsumer)

## Known quirks
- **Storage in ESENT database.** OBJECTS.DATA is binary and opaque to regular registry tools. Access via WMI namespace APIs (`Get-WmiObject`) or Autoruns or dedicated WMI forensic tools.
- **Three-object linkage required.** Filter alone or Consumer alone is inert; the binding is what activates them. An investigator must correlate all three.
- **Legitimate uses exist.** Some monitoring software uses WMI subscriptions. Compare against baseline or whitelist.

## Practice hint
List current subscriptions: `Get-WmiObject -Namespace root\subscription -Class __EventFilter` and `... -Class __EventConsumer` and `... -Class __FilterToConsumerBinding`. On a clean Win10 VM, only Microsoft-legitimate subscriptions should appear; unfamiliar ones warrant investigation.
