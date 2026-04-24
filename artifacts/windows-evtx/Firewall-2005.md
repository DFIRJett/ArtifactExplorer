---
name: Firewall-2005
title-description: "A rule has been modified in the Windows Firewall exception list"
aliases: [Firewall rule modified]
link: security
tags: [rule-lifecycle, tamper-indicator]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
platform:
  windows: {min: '7', max: '11'}
  note: "renumbered to 2074 on Windows 11 build 22621+"
location:
  channel: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
  event-id: 2005
  provider: Microsoft-Windows-Windows Firewall With Advanced Security
fields:
- name: RuleId
  kind: identifier
  location: EventData → RuleId
  references-data:
  - {concept: FirewallRuleName, role: modifiedRule}
- name: RuleName
  kind: label
  location: EventData → RuleName
- name: ApplicationPath
  kind: path
  location: EventData → ApplicationPath
  references-data:
  - {concept: ExecutablePath, role: configuredPersistence}
- name: Direction
  kind: flag
  location: EventData → Direction
- name: Action
  kind: flag
  location: EventData → Action
- name: Profiles
  kind: flag
  location: EventData → Profiles
- name: ModifyingUser
  kind: identifier
  location: EventData → ModifyingUser
  references-data:
  - {concept: UserSID, role: actingUser}
- name: ModifyingApplication
  kind: path
  location: EventData → ModifyingApplication
  references-data:
  - {concept: ExecutablePath, role: actingProcess}
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: FIREWALL_RULE_MODIFIED
  ceiling: C3
  note: "Existing rule's properties changed. Post-change values are captured in the event — scope widened, action flipped (block→allow), protocol opened. Critical for detecting weakening of existing rules as an alternative to adding attacker rules."
  qualifier-map:
    object.rule.id: field:RuleId
    actor.user.sid: field:ModifyingUser
    time.modified: field:TimeCreated
anti-forensic:
  write-privilege: service
windows-11-renumbering:
  applies-to: "Windows 11 build 22621 and later"
  new-id: 2074
  note: "Union 2005 + 2074 for cross-version coverage."
detection-priorities:
  - "Action flip: existing Block → Allow"
  - "Protocol widening: specific-port → Any"
  - "Profile scope widening: Domain → All profiles"
provenance:
  - ms-windows-defender-firewall-registry
  - mitre-t1562-004
---

# Firewall-2005

## Forensic value
Missing companion to Firewall-2004 / Firewall-2006. Tracks rule MODIFICATIONS — an often-overlooked attacker vector: rather than adding a new rule (2004 is conspicuous), modify an existing one to weaken its scope (2005 is less scrutinized). Watch for rules where Action or Profiles widened.

## Join-key use
RuleId joins to FirewallRules registry (current state) and to Firewall-2004 (original add event) — the triple 2004 → 2005 → optional 2006 reveals the full lifecycle of a modified rule.

## Windows 11 22621+
Renumbered to 2074 with one additional ErrorCode field. Union both IDs.
