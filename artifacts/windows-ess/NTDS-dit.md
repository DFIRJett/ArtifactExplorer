---
name: NTDS-dit
aliases: [Active Directory database, ntds.dit]
link: security
tags: [server-only, credential-material]
volatility: persistent
interaction-required: none
substrate: windows-ess
substrate-instance: NTDS-dit
platform:
  windows-server: {min: '2000', max: '2025', note: "domain-controller role only"}
location:
  path: "%WINDIR%\\NTDS\\ntds.dit"
  addressing: ese-table-row
fields:
- name: datatable
  kind: record
  location: ntds.dit → datatable
  note: "central table holding all AD objects (users, groups, computers, OUs). ~900 columns per row; relevant subset: sAMAccountName, objectSid, pwdLastSet, lastLogonTimestamp, unicodePwd, ntPwdHistory"
- name: user-sid
  kind: identifier
  location: datatable → objectSid column
  references-data:
  - {concept: UserSID, role: identitySubject}
- name: username
  kind: label
  location: datatable → sAMAccountName
- name: ntlm-hash
  kind: ciphertext
  location: datatable → unicodePwd (encrypted with PEK — Password Encryption Key)
  note: "extract with Impacket secretsdump, dsdumper, or mimikatz lsadump::dcsync. Decryption requires PEK from SYSTEM hive's BootKey-wrapped RID cipher"
- name: pwd-last-set
  kind: timestamp
  location: datatable → pwdLastSet
  encoding: filetime-le
observations:
- proposition: DOMAIN_ACCOUNT_DATABASE
  ceiling: C4
  note: "Active Directory canonical database. Contains every domain user's NT hash (extractable offline with SYSTEM hive). Primary target in domain-compromise investigations — both for what the attacker can take AND for the authoritative account timeline."
  qualifier-map:
    object.user.sid: field:user-sid
    object.user.name: field:username
    time.pwd_last_set: field:pwd-last-set
anti-forensic:
  write-privilege: unknown
provenance: [mitre-t1003-006, mitre-t1003-003, mitre-t1207, fortra-2022-secretsdump-py-cache-entry-ext, libyal-libesedb, metcalf-2016-adsecurity-dump-ad-credentials, dsinternals-grafnetter, synacktiv-2023-ntdissector, ms-drsr-getncchanges]
exit-node:
  is-terminus: true
  primary-source: mitre-t1003-003
  attribution-sentence: 'Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights (MITRE ATT&CK, n.d.).'
  terminates: []
  sources:
    - mitre-t1003-006
    - fortra-2022-secretsdump-py-cache-entry-ext
    - libyal-libesedb
  reasoning: >-
    NTDS.dit is the domain-controller authoritative store for user principal data — every domain SID-to-account binding originates here. For domain accounts, UserSID resolution terminates at NTDS.dit; no downstream artifact can provide a more authoritative mapping.
  implications: >-
    In a domain environment, NTDS.dit is the defensible citation for 'which account does SID S-1-5-21-... belong to.' Secretsdump / equivalent extractors convert the raw ESE tables into analyst-queryable form. Pair with SAM for local-vs-domain SID disambiguation.
  preconditions: "Domain-joined system; NTDS.dit from a DC (or replicated copy)."
  identifier-terminals-referenced:
    - UserSID
    - DomainName
---

# NTDS.dit

## Forensic value
The crown-jewel artifact on a domain controller. Offline copy + SYSTEM hive = full domain NT-hash dump via `secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL`. Every domain user's credential material, group memberships, password history, and account-state timeline.

## Cross-references
- **SAM** — local-account analog (member server / workstation)
- **Security-4768** / **4769** — Kerberos AS/TGS events reference NTDS-stored accounts
- **LSA-Secrets** — DC's machine account + LSA policy complement
