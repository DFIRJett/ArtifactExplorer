---
name: Security-5379
title-description: "Credential Manager credentials were read"
aliases: [5379, Credential Manager read, vault access]
link: user
link-secondary: persistence
tags: [credential-theft, access-audit]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: {min: '10', max: '11'}
  windows-server: {min: '2016', max: '2022'}
location:
  channel: Security
  event-id: 5379
  provider: Microsoft-Windows-Security-Auditing
  addressing: evtx-record
  note: "Fires when a process calls CredRead / CredEnumerate API — reading credentials from Windows Credential Manager. Paired with 5378 (credentials delegated) and 5381 (credentials read from vault). Subcategory: 'Audit User Account Management' → Credential Manager sub-sub. Requires enabling the sub-category explicitly."
fields:
- name: target-name
  kind: label
  location: "EventData → TargetName"
  encoding: utf-16le
  references-data: [{concept: URL, role: embeddedReferenceUrl}]
  note: "Credential target identifier — 'TERMSRV/<host>' for saved RDP, 'git:https://<host>' for Git credentials, 'LegacyGeneric:target=<service>' for saved Outlook. Reveals WHICH credential was read."
- name: type
  kind: enum
  location: "EventData → Type"
  encoding: "integer enum"
  note: "Credential type: 1=Generic, 2=Domain, 3=Generic-Certificate, 4=Domain-Certificate, 5=Domain-Visible-Password."
- name: subject-user-sid
  kind: identifier
  location: "EventData → SubjectUserSid"
  encoding: SID
  references-data: [{concept: UserSID, role: profileOwner}]
  note: "Account whose Credential Manager was read (is the process running under this user's context)."
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
  note: 'Sensitive — fires when any process reads Credential Manager entries. Attacker tooling (mimikatz vault::cred, SharpDPAPI credentials, direct Credential Manager API calls) generates this event. Baseline legitimate use: Outlook at startup reads its saved Exchange password; Git tools read stored credentials. Anomaly detection: unknown processes accessing many different target-names in short windows = bulk credential harvest.'
  qualifier-map:
    actor.session: field:subject-logon-id
    object.credential: field:target-name
    time.start: field:event-time
provenance: [ms-event-5379, mitre-t1555-004]
---

# Security-5379 — Credential Manager Read

Fires on CredRead / CredEnumerate. Target-name reveals which saved credential the reading process fetched. Attacker-tool signature: one process reads many distinct TargetNames in short order.
