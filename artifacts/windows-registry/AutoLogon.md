---
name: AutoLogon
aliases: [Winlogon AutoAdminLogon, DefaultPassword]
link: security
tags: [system-wide, tamper-easy, credential-material]
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows: {min: XP, max: '11'}
location:
  hive: SOFTWARE
  path: "Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
  addressing: hive+key-path
fields:
- name: AutoAdminLogon
  kind: flag
  location: AutoAdminLogon value
  type: REG_SZ
  note: "'1' = autologon enabled, '0' or missing = disabled"
- name: DefaultUserName
  kind: label
  location: DefaultUserName value
  type: REG_SZ
  note: "Account name used for auto-logon. Not a SID — joins to SAM.username or ProfileList.profile-image-path for SID resolution."
- name: DefaultDomainName
  kind: label
  location: DefaultDomainName value
  type: REG_SZ
  references-data:
  - {concept: DomainName, role: targetDomain}
  note: "Domain scope of the auto-logon account. For local accounts this is the machine NetBIOS name; for domain accounts, the AD DNS or NetBIOS domain."
- name: DefaultPassword
  kind: ciphertext
  location: DefaultPassword value (legacy plaintext) OR LSA-Secrets DefaultPassword (Vista+)
  type: REG_SZ
  note: "Historically plaintext in HKLM\\SOFTWARE\\...\\Winlogon\\DefaultPassword. Modern configurations store it in LSA-Secrets — but legacy writes and some 3rd-party installers still use the plaintext slot."
- name: AutoLogonCount
  kind: counter
  location: AutoLogonCount value
  type: REG_DWORD
  note: "one-shot autologon enabled with count; decrements each logon"
- name: key-last-write
  kind: timestamp
  location: Winlogon subkey metadata
  encoding: filetime-le
observations:
- proposition: CREDENTIAL_EXPOSED
  ceiling: C4
  note: "AutoAdminLogon=1 with plaintext DefaultPassword = credentials readable by anyone with SOFTWARE-hive read access. Classic misconfiguration."
  qualifier-map:
    actor.user: field:DefaultUserName
    object.credential.exposed: field:DefaultPassword
    time.configured: field:key-last-write
anti-forensic:
  write-privilege: admin
provenance:
  - ms-winlogon-registry-entries
  - mitre-t1552-006
---

# AutoLogon

## Forensic value
Records the credentials Windows uses for automated logon without user prompt. Even when the password has since been moved to LSA-Secrets, the presence of `AutoAdminLogon=1` + `DefaultUserName` is a configuration audit finding (credentials used unattended).

## Cross-references
- **LSA-Secrets** (DefaultPassword) — modern cipher-storage location
- **Security-4624** Logon Type 2 (interactive) events — bounds actual autologon use
- **Winlogon-Userinit-Shell** — sibling Winlogon persistence keys
