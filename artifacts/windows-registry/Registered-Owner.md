---
name: Registered-Owner
title-description: "RegisteredOwner / RegisteredOrganization — attribution fields recorded at Windows install"
aliases:
- RegisteredOwner
- RegisteredOrganization
link: system
tags:
- attribution
- install-provenance
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: NT3.1
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SOFTWARE (HKLM)
  path: "Microsoft\\Windows NT\\CurrentVersion"
  addressing: hive+key-path
  note: "Two REG_SZ values set at Windows setup that persist unchanged across the OS lifecycle: RegisteredOwner (name the installing user provided) and RegisteredOrganization (org name at install). For OEM-provisioned machines, values reflect the OEM's default. For enterprise-imaged machines, values reflect the image's provisioning. Manual installs reflect what the installing user typed. Low-value for tactical DFIR but occasionally pivotal for attribution / provenance of an unknown device."
fields:
- name: registered-owner
  kind: label
  location: "CurrentVersion\\RegisteredOwner value"
  type: REG_SZ
  encoding: utf-16le
  references-data:
  - concept: UserSID
    role: profileOwner
  note: "Name recorded at install. Rarely changes afterward (can be edited manually). For attribution in cases where the installing-user identity matters (seized device of unknown provenance), this value often preserves the original operator name even if the admin / user accounts were later renamed."
- name: registered-organization
  kind: label
  location: "CurrentVersion\\RegisteredOrganization value"
  type: REG_SZ
  encoding: utf-16le
  note: "Organization name at install. For enterprise-imaged machines reveals the imaging source (company / vendor name). For OEM-sold machines shows 'Microsoft' / manufacturer defaults. Empty / blank on self-installed personal machines."
- name: productid
  kind: identifier
  location: "CurrentVersion\\ProductId value"
  type: REG_SZ
  note: "Windows Product ID — install-specific ID derived from the product key. Sibling attribution value set at install time. Joins multiple machines installed from the same product key."
- name: install-date
  kind: timestamp
  location: "CurrentVersion\\InstallDate value"
  type: REG_DWORD
  encoding: unix-epoch seconds
  clock: system
  resolution: 1s
  note: "Unix epoch timestamp of Windows install. More precise than the Registered* label fields for install-time attribution."
- name: key-last-write
  kind: timestamp
  location: CurrentVersion key metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite updates on any sibling value change. Many Windows values live under CurrentVersion — the key-level mtime is noisy and not directly meaningful for these specific install-time values."
observations:
- proposition: INSTALLED
  ceiling: C2
  note: 'RegisteredOwner / RegisteredOrganization are attribution
    artifacts — useful when the question is WHO installed this
    machine and for WHAT organization. Low C-ceiling because the
    values are trivially editable post-install and don''t constitute
    strong corroboration alone. Useful in provenance cases where a
    seized device''s history is unknown.'
  qualifier-map:
    actor.user: field:registered-owner
    actor.organization: field:registered-organization
    time.start: field:install-date
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  survival-signals:
  - RegisteredOrganization value matches known-victim organization = confirms device origin
  - RegisteredOwner blank or 'Administrator' / 'User' default = self-install or OEM default
  - Recently-edited value mtime on an old machine = someone manually tampered with attribution
provenance: [ms-windows-install-registry-values-cur]
exit-node:
  is-terminus: false
  terminates:
    - SYSTEM_IDENTITY
  sources:
    - ms-windows-install-registry-values-cur
  reasoning: >-
    RegisteredOwner + RegisteredOrganization under HKLM\SOFTWARE\
    Microsoft\Windows NT\CurrentVersion hold the authoritative string
    set during Windows install (OOBE) or cloned image. They answer
    "who claimed this OS install / who registered this device" — a
    terminal question for device-origin attribution. No upstream: the
    registry values ARE the claim.
  implications: >-
    RegisteredOrganization matching a known-victim organization on a
    seized device is direct provenance evidence. Matching defaults
    ('Administrator', 'User', vendor OEM string) on an enterprise
    device = OEM default never overwritten, or re-install wiping prior
    identity. Value-mtime on a years-old machine = recent tamper to
    alter attribution; correlate with Security-4657 on this registry
    key when auditing is enabled.
  preconditions: >-
    Read access to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion.
    No crypto chain.
  identifier-terminals-referenced: []
---

# Registered Owner / Organization

## Forensic value
Two sibling REG_SZ values under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`:

- `RegisteredOwner` — name provided at Windows install
- `RegisteredOrganization` — organization at install

Set once at setup and typically left unchanged. Useful for provenance attribution on unknown / seized devices.

## Triage
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOrganization
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v InstallDate
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductId
```

## Practice hint
On any Windows VM inspect these values. For an enterprise-imaged machine, RegisteredOrganization reveals the IT provisioning organization. For an OEM-sold consumer laptop, it shows the manufacturer's default ('Preferred Customer' historically). For a personal install where the user typed a name, you get that name.
