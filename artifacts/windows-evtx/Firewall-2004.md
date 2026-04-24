---
name: Firewall-2004
title-description: "A rule has been added to the Windows Firewall exception list"
aliases:
- Firewall rule added
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
  event-id: 2004
  provider: Microsoft-Windows-Windows Firewall With Advanced Security
fields:
- name: RuleId
  kind: identifier
  location: EventData → RuleId
  references-data:
  - concept: FirewallRuleName
    role: addedRule
- name: RuleName
  kind: label
  location: EventData → RuleName
- name: ApplicationPath
  kind: path
  location: EventData → ApplicationPath
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
- name: Direction
  kind: flag
  location: EventData → Direction
  note: "inbound | outbound"
- name: Action
  kind: flag
  location: EventData → Action
  note: "allow | block"
- name: Profiles
  kind: flag
  location: EventData → Profiles
  note: "Domain | Private | Public"
- name: ModifyingUser
  kind: identifier
  location: EventData → ModifyingUser
  encoding: sid-string
  availability:
    min-windows: '10.1903'
  references-data:
  - {concept: UserSID, role: actingUser}
  note: "SID of the user context under which the rule-add occurred. Added in Win10 1903 — earlier 2004 events omit this field. When present, joins to Security-4624 (TargetUserSid) for session correlation."
- name: ModifyingApplication
  kind: path
  location: EventData → ModifyingApplication
  encoding: utf-16le
  availability:
    min-windows: '10.1903'
  references-data:
  - {concept: ExecutablePath, role: actingProcess}
  note: "Full path to the executable that added the rule (typically svchost.exe for Group Policy, powershell.exe for script-based, wf.msc wrapper for GUI). Join to Security-4688 where NewProcessName matches this path and TimeCreated window overlaps — yields the exact 4688 process-creation event that preceded this rule-add."
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: FIREWALL_RULE_ADDED
  ceiling: C3
  note: "A new Windows Firewall rule was added. Preserves historical record even if the rule is later deleted. Critical for detecting attacker-created exceptions."
  qualifier-map:
    object.rule.id: field:RuleId
    object.rule.app: field:ApplicationPath
    time.created: field:TimeCreated
anti-forensic:
  write-privilege: service
detection-priorities:
  - Direction=outbound + Action=allow + ApplicationPath in %TEMP% / %APPDATA% — C2 egress whitelist
  - 2004 with no matching 2033 (delete) — rule still active
windows-11-renumbering:
  applies-to: "Windows 11 build 22621 and later"
  new-id: 2071
  note: "On Win11 22621+, rule-add events fire under ID 2071 (with one additional ErrorCode field). SIEM queries targeting only 2004 will silently miss activity. Union 2004 + 2071 for cross-version coverage."
provenance:
  - ms-windows-defender-firewall-registry
  - mitre-t1562-004
---

# Firewall-2004

## Forensic value
Rule-add event. Pair with Firewall-2006 (modify) and Firewall-2033 (delete) to rebuild the full rule lifecycle. The registry shows only CURRENT rules — an attacker who added an exception and deleted it at cleanup leaves no registry trace, but Firewall-2004 preserves the RuleId, ApplicationPath, and timestamp.

## Join-key use
RuleId joins to FirewallRules registry artifact (current state). Pair of 2004 without matching 2033 = rule still active. 2004 + 2033 within an incident window = created-then-removed attacker rule.
