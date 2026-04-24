---
name: Firewall-2006
title-description: "A rule has been deleted from the Windows Firewall exception list"
aliases:
- Firewall rule deleted
link: security
tags:
- rule-lifecycle
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
platform:
  windows:
    min: '7'
    max: '11'
location:
  channel: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
  event-id: 2006
  provider: Microsoft-Windows-Windows Firewall With Advanced Security
fields:
- name: RuleId
  kind: identifier
  location: EventData → RuleId
  references-data:
  - concept: FirewallRuleName
    role: deletedRule
- name: RuleName
  kind: label
  location: EventData → RuleName
- name: ProfileChanged
  kind: flag
  location: EventData → ProfileChanged
- name: ModifyingUser
  kind: identifier
  location: EventData → ModifyingUser
  encoding: sid-string
  availability:
    min-windows: '10.1903'
  references-data:
  - {concept: UserSID, role: actingUser}
  note: "SID of the user context under which the rule-delete occurred. Added in Win10 1903. Combined with rule-delete-time proximity to a specific 4624 session, places the deletion within a user session."
- name: ModifyingApplication
  kind: path
  location: EventData → ModifyingApplication
  encoding: utf-16le
  availability:
    min-windows: '10.1903'
  references-data:
  - {concept: ExecutablePath, role: actingProcess}
  note: "Full path to the executable that deleted the rule. Join to Security-4688 NewProcessName + time-window overlap to identify the deleting process. Forensic IOC: ModifyingApplication of cmd.exe/powershell.exe/wscript.exe during an incident window suggests scripted cleanup."
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
windows-11-renumbering:
  applies-to: "Windows 11 build 22621 and later"
  new-id: 2075
  note: "On Win11 22621+, rule-delete events fire under ID 2075. Union 2006 + 2075 for cross-version coverage."
observations:
- proposition: FIREWALL_RULE_DELETED
  ceiling: C3
  note: "Windows Firewall rule deleted. Preserves RuleId after the registry entry is gone — the ONLY surviving record of deleted rules."
  qualifier-map:
    object.rule.id: field:RuleId
    time.deleted: field:TimeCreated
anti-forensic:
  write-privilege: service
provenance:
  - ms-windows-defender-firewall-registry
  - mitre-t1562-004
---

# Firewall-2006

## Forensic value
Rule-delete event. The decisive artifact for attacker-cleanup patterns: a 2006 emitted during an incident window for a RuleId that is ALSO absent from the current FirewallRules registry means the rule once existed, was used, and was cleaned up. Without 2006, the rule's existence would be invisible.

## Join-key use
RuleId — compare against Firewall-2004 (add) for the same ID: if present, you have the full create-and-destroy sequence with timestamps. Pair with 2033 if the rule was modified between 2004 and 2006.
