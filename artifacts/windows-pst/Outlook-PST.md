---
name: Outlook-PST
aliases:
- PST
- OST
- Outlook personal folders
- outlook mail archive
link: application
tags:
- timestamp-carrying
- per-user
volatility: persistent
interaction-required: user-action
substrate: windows-pst
substrate-instance: PST/OST
substrate-hub: User scope
platform:
  windows:
    min: XP
    max: '11'
  macos:
    min: '10.12'
    max: '15'
  linux:
    min: any
    max: any
location:
  path: '%LOCALAPPDATA%\Microsoft\Outlook\<account>.pst (or .ost)'
  addressing: message-id + folder-path within PST
fields:
- name: subject
  kind: identifier
  location: message MAPI PR_SUBJECT
  encoding: utf-16le
- name: from-address
  kind: identifier
  location: message PR_SENDER_EMAIL_ADDRESS
  encoding: utf-16le
  references-data:
  - concept: EmailAddress
    role: sender
  - concept: DomainName
    role: emailDomain
- name: to-addresses
  kind: identifier
  location: message PR_DISPLAY_TO / recipient table
  encoding: utf-16le
  references-data:
  - concept: EmailAddress
    role: recipient
  - concept: DomainName
    role: emailDomain
- name: cc-addresses
  kind: identifier
  location: message PR_DISPLAY_CC
  encoding: utf-16le
  references-data:
  - concept: EmailAddress
    role: recipient
  - concept: DomainName
    role: emailDomain
- name: message-body
  kind: identifier
  location: message PR_BODY / PR_BODY_HTML
  encoding: utf-16le text OR HTML
- name: internet-headers
  kind: identifier
  location: message PR_TRANSPORT_MESSAGE_HEADERS
  encoding: ascii
  note: full RFC-5322 headers — contains Received chain, source IPs, SPF/DKIM results
  references-data:
  - concept: URL
    role: embeddedReferenceUrl
  - concept: IPAddress
    role: relayHop
  - concept: DomainName
    role: emailDomain
- name: sent-time
  kind: timestamp
  location: message PR_CLIENT_SUBMIT_TIME
  encoding: filetime-le
  clock: sender system clock (external)
  resolution: 100ns
  note: 'sender''s clock — UNRELIABLE for chronology; use Received: header timestamps instead'
- name: delivery-time
  kind: timestamp
  location: message PR_MESSAGE_DELIVERY_TIME
  encoding: filetime-le
  clock: receiving mail server (Exchange, SMTP)
  resolution: 100ns
- name: folder-path
  kind: path
  location: folder hierarchy within PST
  encoding: utf-16le
  note: e.g., 'Inbox', 'Sent Items', 'Deleted Items', user-created subfolders
- name: attachment-filename
  kind: identifier
  location: attachment PR_ATTACH_FILENAME / PR_ATTACH_LONG_FILENAME
  encoding: utf-16le
- name: attachment-content
  kind: identifier
  location: attachment PR_ATTACH_DATA_BIN or PR_ATTACH_DATA_OBJ
  encoding: variable (original file bytes)
  note: recoverable as original file; may be hash-matched against ExecutableHash concept if PE
observations:
- proposition: COMMUNICATED
  ceiling: C3
  qualifier-map:
    direction: sent (from-address = user's account) / received (to/cc contains user's account)
    peer: field:from-address  OR  field:to-addresses
    channel: SMTP / Exchange / MAPI
    content-digest: hash of message body or attachment
    time.start: field:delivery-time
  preconditions:
  - PST not repaired with scanpst.exe (destroys forensic integrity)
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: Outlook 'Empty Deleted Items' + compact
    typically-removes: partial
    note: emptied items can persist in PST free-space; compact also doesn't zero data
  - tool: PST file delete
    typically-removes: full
  - tool: scanpst.exe
    typically-removes: partial
    note: '''repair'' tool; modifies PST in place — destroys forensic integrity'
  survival-signals:
  - Deleted Items folder contains items with delivery timestamps long after the user claims inbox was empty
  - Free-space carving yields message fragments not present in any visible folder
provenance:
  - libyal-libpff
  - ms-pst
exit-node:
  is-terminus: true
  primary-source: mitre-t1114-001
  attribution-sentence: 'Adversaries may target user email on local systems to collect sensitive information (MITRE ATT&CK, n.d.).'
  terminates:
    - COMMUNICATED
  sources:
    - ms-pst
    - libyal-libpff
  reasoning: >-
    PST stores the full RFC-5322 Received: chain in the PR_TRANSPORT_MESSAGE_HEADERS
    property (per [MS-PST] / [MS-OXOMSG]), plus sender/recipient EmailAddress,
    DomainName, IPAddress, and any URLs in body/headers — four external-identity
    terminals in a single artifact. No downstream correlation is required to
    establish that a given message was transmitted between identified parties
    at an identified time.
  implications: >-
    Legal-grade communication attribution. The Received: chain is the courtroom
    standard for establishing message transit path and timing; PST preserves it
    indefinitely under normal retention. Analysts reporting on insider-exfil,
    phishing-delivery, or adversarial-C2 cases can cite PST contents as
    self-contained evidence of communication rather than needing mail-server
    logs (which may be outside their collection scope).
  identifier-terminals-referenced:
    - EmailAddress
    - IPAddress
    - URL
    - DomainName
---

# Outlook PST / OST Mailbox

## Forensic value
Self-contained archive of a user's Outlook mailbox. Every message with headers, body, attachments, folder hierarchy, read state. For email-centric investigations, the PST is the primary artifact.

## Concept references
- EmailAddress (sender + recipients)
- DomainName (derived from email addresses + header Received-by chain)
- URL (embedded links in bodies, header references)
- IPAddress (Received: chain source IPs)

## Key investigative fields
- **Internet-headers** — full RFC-5322 headers have the Received-by chain, source IPs, SPF/DKIM/DMARC results. Often the strongest provenance signal.
- **Client-submit-time** is SENDER's clock and unreliable; prefer Received timestamps.
- **Attachments** extract cleanly via libpff/readpst for separate analysis (PE hash matching, sandbox detonation, etc.).

## Practice hint
Acquire a test PST. Parse with `readpst -w outputdir mailbox.pst`. Every message becomes a separate .eml file — standard format for downstream tooling. Grep the .eml corpus for indicators of compromise.
