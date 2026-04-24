---
name: Firewall-2033
title-description: "All rules have been deleted from the Windows Firewall configuration"
aliases:
- Firewall all-rules cleared
- Firewall policy reset
link: security
tags:
- rule-lifecycle
- tamper-indicator
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
  event-id: 2033
  provider: Microsoft-Windows-Windows Firewall With Advanced Security
fields:
- name: ProfileChanged
  kind: flag
  location: EventData → ProfileChanged
- name: ModifyingUser
  kind: identifier
  location: EventData → ModifyingUser
  references-data:
  - concept: UserSID
    role: actingUser
- name: ModifyingApplication
  kind: path
  location: EventData → ModifyingApplication
  references-data:
  - concept: ExecutablePath
    role: actingProcess
- name: TimeCreated
  kind: timestamp
  location: System → TimeCreated
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: FIREWALL_POLICY_RESET
  ceiling: C3
  note: "All firewall rules in a profile cleared / policy reset. A ModifyingApplication outside netsh/Group Policy context is a strong tamper signal."
  qualifier-map:
    actor.user.sid: field:ModifyingUser
    actor.process: field:ModifyingApplication
    time.observed: field:TimeCreated
anti-forensic:
  write-privilege: service
detection-priorities:
  - "ModifyingApplication not in (mpssvc, netsh, wmiprvse, explicit Group Policy agent) — mass rule clearing by unusual process"
provenance:
  - ms-windows-defender-firewall-registry
  - mitre-t1562-004
---

# Firewall-2033

## Forensic value
Mass rule-clearing event. Records ModifyingUser (SID) and ModifyingApplication (path) — the WHO of the policy change. This event accompanies attacker workflows like `netsh advfirewall firewall delete rule name=all` or programmatic policy resets, which would otherwise leave only gaps in the current FirewallRules registry state.

## Join-key use
ModifyingApplication (ExecutablePath) joins to Prefetch / Amcache for actor-process attribution. ModifyingUser joins to ProfileList / SAM for account identity.
