---
name: Exchange-Mailbox-edb
aliases: [Exchange mailbox database, priv.edb, Mailbox Database.edb]
link: application
tags: [server-only, large-scope]
volatility: persistent
interaction-required: none
substrate: windows-ess
substrate-instance: Exchange-Mailbox-EDB
platform:
  windows-server: {min: '2003', max: '2025'}
location:
  path: "Exchange Server install-dependent; typical: <install-drive>\\Program Files\\Microsoft\\Exchange Server\\V15\\Mailbox\\<DB name>\\<DB name>.edb"
  addressing: ese-table-row
fields:
- name: mailbox-table
  kind: record
  location: per-mailbox tables within the EDB
  note: "each mailbox has its own folder tree with table-per-folder; Inbox, Sent, Drafts, custom folders"
- name: message-body
  kind: content
  location: message-table rows → Body / HtmlBody columns
- name: message-attachments
  kind: content
  location: attachment tables linked to messages
- name: sender
  kind: label
  location: message-table → SenderEmailAddress
  references-data:
  - {concept: EmailAddress, role: sender}
- name: recipient-list
  kind: label
  location: recipient tables → RecipientEmailAddress
  references-data:
  - {concept: EmailAddress, role: recipient}
- name: received-time
  kind: timestamp
  location: message-table → DeliveryTime
  encoding: filetime-le
  clock: system
  resolution: 100ns
observations:
- proposition: SERVER_MAILBOX_CONTENT
  ceiling: C4
  note: "Server-side mail store. Offline access to the EDB + transaction logs gives the full mailbox content for every user — the server-side equivalent of collecting every client's OST."
  qualifier-map:
    actor.user.email: field:sender
    object.recipient: field:recipient-list
    time.received: field:received-time
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - {tool: New-MailboxExportRequest + deletion, typically-removes: mailbox-level}
provenance: [libyal-libesedb]
---

# Exchange-Mailbox-edb

## Forensic value
The server-side canonical mail store. One EDB holds dozens to thousands of mailboxes. Offline acquisition preserves every user's mail (even ones who've never opened the mailbox from a client). For insider-threat / BEC investigations, the EDB is the authoritative source — client-side OST / PST are subsets.

## Cross-references
- **Outlook-OST** — per-user client cache; subset of the EDB for that user
- **Outlook-PST** — user-exported archive; partially overlaps
- **OAB-edb** — Offline Address Book; org-user catalog sibling
