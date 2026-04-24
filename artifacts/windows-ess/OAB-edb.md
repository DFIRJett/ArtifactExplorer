---
name: OAB-edb
aliases: [Offline Address Book, Outlook address cache]
link: user
tags: [per-user, org-directory]
volatility: persistent
interaction-required: user-action
substrate: windows-ess
substrate-instance: OAB-edb
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%LOCALAPPDATA%\\Microsoft\\Outlook\\Offline Address Books\\<OAB-GUID>\\"
  note: "not strictly .edb — consists of .lzx / .oab files with indexed address-book data. Grouped here with the ESE family because the surrounding store structure parallels ESE's role"
  addressing: oab-file-set
fields:
- name: email-address
  kind: label
  location: per-entry OAB record
  references-data:
  - {concept: EmailAddress, role: recipient}
- name: display-name
  kind: label
  location: per-entry OAB record
- name: phone-number
  kind: label
  location: per-entry OAB record
- name: department
  kind: label
  location: per-entry OAB record
- name: manager
  kind: label
  location: per-entry OAB record
observations:
- proposition: ORG_DIRECTORY_SNAPSHOT
  ceiling: C3
  note: "Offline cache of the organization's Global Address List. On a compromised host, the OAB gives the attacker the org chart — every email, display name, phone, department, manager. Reconnaissance gold for insider-threat and BEC investigations."
  qualifier-map:
    object.directory.address: field:email-address
anti-forensic:
  write-privilege: unknown
provenance: []
---

# OAB (Offline Address Book)

## Forensic value
Cached organization directory — the Exchange Global Address List mirrored to every client. For IR, a populated OAB on a host tells you what org information was available to the user (and attacker). For exfil / insider cases, the OAB often reveals the victim set the attacker already enumerated.

## Cross-references
- **Outlook-OST** — paired Outlook cache; shares the OAB directory reference
- **Exchange-Mailbox-edb** — server-side canonical mail store
