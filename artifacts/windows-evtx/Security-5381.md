---
name: Security-5381
title-description: "Vault credentials were enumerated"
aliases: [5381, vault enumerate, Web Credentials enumerated]
link: user
link-secondary: persistence
tags: [credential-theft, access-audit]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: {min: '10', max: '11'}
  windows-server: {min: '2019', max: '2025'}
location:
  channel: Security
  event-id: 5381
  provider: Microsoft-Windows-Security-Auditing
  addressing: evtx-record
  note: "Fires on VaultEnumerate operations against Windows Vault subsystem (Web Credentials, Windows-account SSO credentials). Paired with 5382 (READ single credential) — NOT with 5379 (which is Credential Manager CredRead on the Credentials folder). Subcategory per UWS: 'System → Other System Events' (corpus previously claimed 'Audit User Account Management' — corrected 2026-04-23, MS Learn's own subcategory doc does not list 5381 there). Corrected 2026-04-23 per sprint r4 audit: title-description was 'Credentials were read from vault' which actually describes 5382; 5381 is the ENUMERATE event."
fields:
- name: vault-id
  kind: identifier
  location: "EventData → VaultId"
  encoding: guid-string
  note: "GUID of the vault whose credentials were read. Well-known: {4BF4C442-9B8A-41A0-B380-DD4A704DDB28} = Web Credentials, {77BC582B-F0A6-4E15-4E80-61736B6F3B29} = Windows Credentials. Attacker reading Web Credentials vault = browser-saved-HTTP-auth exfil."
- name: subject-user-sid
  kind: identifier
  location: "EventData → SubjectUserSid"
  encoding: SID
  references-data: [{concept: UserSID, role: profileOwner}]
- name: subject-logon-id
  kind: identifier
  location: "EventData → SubjectLogonId"
  encoding: hex LUID
  references-data: [{concept: LogonSessionId, role: sessionContext}]
- name: event-time
  kind: timestamp
  location: "System/TimeCreated"
  encoding: xs:dateTime UTC
  clock: system
  resolution: 1ms
observations:
- proposition: CREDENTIAL_READ
  ceiling: C3
  note: '5381 is the Vault-subsystem companion to 5379. Together they capture BOTH file-level Credentials folder reads AND Vault-scheme reads. For comprehensive credential-theft detection enable BOTH subcategories.'
  qualifier-map:
    actor.session: field:subject-logon-id
    object.id: field:vault-id
    time.start: field:event-time
provenance: [ms-event-5381]
---

# Security-5381 — Vault Read
Vault-subsystem credential access event. Companion to 5379. Vault-id GUID identifies whether Web Credentials or Windows Credentials vault was read.
