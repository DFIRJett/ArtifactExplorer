---
name: FirewallRuleName
kind: identifier
lifetime: persistent
link-affinity: security
description: |
  Windows Firewall rule identifier — a string name or GUID that uniquely
  identifies a firewall rule. Appears as a subkey value in the FirewallRules
  registry path and as the RuleId field in Firewall/Firewall evtx events.
canonical-format: "string (friendly name) OR GUID in registered-rule format"
aliases: [wfp-rule-name, firewall-rule-id]
roles:
  - id: identitySubject
    description: "Rule's canonical identifier — registry value name and evtx RuleId match"
  - id: addedRule
    description: "Rule name on add events (2004)"
  - id: modifiedRule
    description: "Rule name on modify events (2006)"
  - id: deletedRule
    description: "Rule name on delete events (2033)"

known-containers:
  - FirewallRules
  - Firewall-2004
  - Firewall-2006
  - Firewall-2033
provenance: [ms-windows-defender-firewall-registry]
---

# Firewall Rule Name

## What it is
Unique identifier for a Windows Firewall rule. Rules are stored in `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules` with the rule ID as the value NAME and the rule definition as the value DATA. The same ID appears as the `RuleId` field in every rule-mutation event on the `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` channel.

## Forensic join key
Rules that ATTACKERS add to create command-and-control exceptions are often deleted at cleanup. Registry carries only CURRENT rules; EVTX retains the historical add/modify/delete sequence. Join on RuleName to surface:
- Rules added during incident window, still present (ongoing persistence)
- Rules added during incident window, later deleted (cleanup evidence)
- Rules modified to weaken scope (block→allow, inbound-only→any)

## Detection pattern
A 2004 (rule added) with direction=outbound, action=allow, protocol=any, remote-address=any, followed by no 2033 (delete) — that rule is still permitting egress. Cross-reference against current FirewallRules registry contents for the same RuleName.
