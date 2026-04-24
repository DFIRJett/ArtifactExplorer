---
name: Security-4724
title-description: "An attempt was made to reset an account's password"
aliases: [4724, password reset, admin reset]
link: user
link-secondary: persistence
tags: [credential-tamper, admin-action]
volatility: persistent
interaction-required: none
substrate: windows-evtx
substrate-instance: Security
platform:
  windows: {min: '7', max: '11'}
  windows-server: {min: '2008R2', max: '2022'}
location:
  channel: Security
  event-id: 4724
  provider: Microsoft-Windows-Security-Auditing
  addressing: evtx-record
  note: "Fires when an administrator (or self-service password tool) RESETS an account's password — distinct from 4723 (user-initiated password CHANGE with knowledge of old password). 4724 = forcibly set new password. Subcategory: 'Audit User Account Management'."
fields:
- name: target-user-sid
  kind: identifier
  location: "EventData → TargetSid"
  encoding: SID
  references-data: [{concept: UserSID, role: targetUser}]
  note: "Account whose password was reset. Classic attacker pattern: reset a dormant admin account's password to 'take it over' without knowing the original password."
- name: target-username
  kind: label
  location: "EventData → TargetUserName + TargetDomainName"
  encoding: utf-16le
  note: "SAM account name of the target."
- name: subject-user-sid
  kind: identifier
  location: "EventData → SubjectUserSid"
  encoding: SID
  references-data: [{concept: UserSID, role: actingUser}]
  note: "Account that performed the reset. For attacker-initiated reset this is the compromised admin account."
- name: subject-logon-id
  kind: identifier
  location: "EventData → SubjectLogonId"
  encoding: hex LUID
  references-data: [{concept: LogonSessionId, role: sessionContext}]
  note: "Session LUID of the acting admin."
- name: event-time
  kind: timestamp
  location: "System/TimeCreated"
  encoding: xs:dateTime UTC
  clock: system
  resolution: 1ms
observations:
- proposition: CREDENTIAL_TAMPERED
  ceiling: C3
  note: 'Password reset (4724) is an admin action against another account — distinct from self-change (4723). Alerts fire when: (1) attacker-compromised admin resets a dormant / abandoned account as persistence, (2) insider resets another user''s account to impersonate, (3) pre-departure reset of accounts the departing user wants to retain access to.'
  qualifier-map:
    actor.user: field:subject-user-sid
    object.user: field:target-user-sid
    time.start: field:event-time
provenance: [ms-event-4724]
---

# Security-4724 — Password Reset (Admin Action)

Fires on the machine whose SAM / AD stores the account — for domain accounts fires on a DC. Distinguishes admin-forced resets from user-initiated self-changes (4723). Key detection: 4724 against dormant / privileged accounts = account takeover.
