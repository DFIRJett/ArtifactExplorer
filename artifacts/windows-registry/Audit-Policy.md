---
name: Audit-Policy
aliases: [PolAdtEv, LSA audit configuration, audit subcategories]
link: security
tags: [system-wide, tamper-hard, meta-forensic]
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SECURITY
platform:
  windows: {min: Vista, max: '11'}
location:
  hive: SECURITY
  path: "Policy\\PolAdtEv"
  addressing: hive+key-path
fields:
- name: audit-policy-blob
  kind: binary
  location: "default value of PolAdtEv key"
  type: REG_BINARY
  encoding: "packed per-subcategory flags — 53 subcategories on modern Windows, each with Success/Failure bits"
  note: "decoded gives the complete audit policy: which Security.evtx event categories are ON, OFF, or mixed"
observations:
- proposition: AUDIT_POLICY_STATE
  ceiling: C4
  note: "Ground-truth map of what Security.evtx SHOULD be capturing. Absence of expected Security events can ONLY be interpreted after reading this artifact."
  qualifier-map:
    object.policy.snapshot: field:audit-policy-blob
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - {tool: auditpol /set, typically-removes: partial}
provenance: []
exit-node:
  is-terminus: true
  primary-source: mitre-t1562-002
  attribution-sentence: 'Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits (MITRE ATT&CK, n.d.).'
  terminates:
    - CONFIGURED_DEFENSE
  sources:
    - ms-advanced-audit-policy
  reasoning: >-
    The PolAdtEv blob under HKLM\SECURITY\Policy is the authoritative
    record of which Security.evtx subcategories are ON, OFF, or mixed
    (Success-only / Failure-only). Every "was this event class logged
    here?" question terminates at this blob — event absence from the
    Security log is either explained by this policy (category disabled)
    or indicates tampering / wipe. No upstream: the blob IS the policy.
  implications: >-
    Blob decode showing core subcategories disabled (Logon, Object
    Access, Process Creation) on a managed enterprise endpoint is an
    audit-bypass indicator. Correlate with Security-4719 (audit policy
    changed) in the incident window — if 4719 is absent but blob shows
    recent-disabled state = Security log wipe or blob tamper without
    corresponding event. Blob last-modified timestamp (via key
    LastWrite) pins when the current policy was installed.
  preconditions: >-
    SYSTEM token required to read HKLM\SECURITY directly. Offline
    parsing of SECURITY hive via auditpol-offline parsers or raw blob
    decode (per ms-advanced-audit-policy subcategory-bitmap spec).
  identifier-terminals-referenced: []
---

# Audit-Policy (PolAdtEv)

## Forensic value
Meta-forensic artifact: tells you which Security.evtx event categories the system was configured to record. Essential context for every "why isn't event X in the log?" question — was the event filtered by audit policy, or did it not happen?

Decoded on live systems via `auditpol /get /category:*`; offline, parse the binary blob. Tools: Impacket `secretsdump.py --security` or direct `libsecretsdump`/regipy policy plugins.

## Cross-references
- **Every Security-* evtx artifact** — all depend on the relevant audit subcategory being ON
- **Security-4719** (System audit policy was changed) — emits when this key is modified
- **LSA-Secrets** — adjacent hive region with complementary security-policy state
