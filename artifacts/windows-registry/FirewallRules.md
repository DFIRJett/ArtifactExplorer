---
name: FirewallRules
aliases:
- Windows Firewall Rules
- SharedAccess FirewallPolicy FirewallRules
link: security
tags:
- system-wide
- tamper-easy
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: XP
    max: '11'
location:
  hive: SYSTEM
  path: ControlSet00x\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules
  addressing: hive+key-path
fields:
- name: rule-name
  kind: identifier
  location: "REG_SZ VALUE NAME under FirewallRules key"
  encoding: utf-16le
  note: "value names are rule IDs — either friendly names or {GUIDs}"
  references-data:
  - concept: FirewallRuleName
    role: identitySubject
- name: rule-definition
  kind: policy
  location: REG_SZ value data
  type: REG_SZ
  encoding: "pipe-delimited directive tokens — 'v2.31|Action=Allow|Active=TRUE|Dir=Out|Profile=Public|Profile=Private|...|App=C:\\path\\to\\binary.exe|...'"
  note: attacker-created rules commonly set Action=Allow + Dir=Out + RA=* to whitelist outbound C2 traffic
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
- name: key-last-write
  kind: timestamp
  location: FirewallRules subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "subkey-level; records only the most-recent rule-list mutation"
observations:
- proposition: NETWORK_EXCEPTION_ACTIVE
  ceiling: C3
  note: "Currently-active Windows Firewall rules. Join on rule-name with Firewall-2004/2006/2033 evtx events to rebuild historical rule lifecycle."
  qualifier-map:
    object.rule.name: field:rule-name
    object.rule.target-app: extracted from field:rule-definition App= token
    time.last_mutation: field:key-last-write
anti-forensic:
  write-privilege: admin
  known-cleaners:
  - tool: netsh advfirewall firewall delete rule
    typically-removes: rule from registry; Firewall evtx 2033 emits
provenance:
  - ms-windows-defender-firewall-registry
  - mitre-t1562-004
exit-node:
  is-terminus: true
  primary-source: mitre-t1562-004
  attribution-sentence: 'Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage (MITRE ATT&CK, n.d.).'
  terminates:
    - CONFIGURED
  sources:
    - ms-windows-defender-firewall-registry
    - mitre-t1562-004
  reasoning: >-
    HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules holds every Windows Firewall rule — RuleName, Direction, Action, Protocol, Port, Program, Profile, RemoteAddress. For 'what firewall rule is in effect here,' the registry is the terminus. Live netsh / PowerShell Get-NetFirewallRule queries read from this same data store.
  implications: >-
    Defensible attribution for firewall-state forensics. Proves the policy state at the point of acquisition. Attacker 'netsh advfirewall set allprofiles state off' (T1562.004) leaves traces here — the disabled-profile flags persist. Custom allow-rules for C2 beaconing (often with dns.exe or svchost.exe as Program) are textbook forensic tells; their RuleName + last-modification timestamps anchor the claim.
  preconditions: "SYSTEM hive accessible; attacker did not completely purge the FirewallRules subkey (rare — would trigger reset-to-default and often break the attacker's own rules)"
  identifier-terminals-referenced:
    - FirewallRuleName
    - ExecutablePath
    - IPAddress
---

# FirewallRules

## Forensic value
Registry-side home of every inbound and outbound Windows Firewall rule. Each rule is one REG_SZ value; the value NAME is the rule identifier (friendly name or GUID), the value DATA is a pipe-delimited directive string encoding every property (action, direction, protocol, local/remote addresses, bound app path, scope).

## Join-key forensic use
Paired with Firewall-2004 / 2006 / 2033 evtx events via `FirewallRuleName`. Registry carries CURRENT state; EVTX carries the add/modify/delete TIMELINE. Attacker-added rules that were deleted at cleanup leave no registry trace — only the evtx 2004 (add) + 2033 (delete) sequence survives. Ongoing-persistence rules appear in registry AND have a 2004 but no matching 2033.

## Practice hint
Parse the rule-definition string: split on `|`, filter rules with `Action=Allow` + `Dir=Out` + `Profile=*` + bound `App=` outside standard paths. Cross-reference those App paths against Amcache-InventoryApplicationFile to verify the binary's legitimacy.
