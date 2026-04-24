---
name: Outlook-OST
aliases: [Offline Storage Table, Outlook cached mode cache]
link: application
tags: [per-user]
volatility: persistent
interaction-required: user-action
substrate: windows-pst
substrate-instance: Outlook-OST
substrate-hub: User scope
platform:
  windows: {min: XP, max: '11'}
location:
  path: "%LOCALAPPDATA%\\Microsoft\\Outlook\\*.ost"
  addressing: pff-node-tree
fields:
- name: root-folder
  kind: identifier
  location: OST NBT root node
- name: message-item
  kind: record
  location: per-message NBT nodes
- name: sender
  kind: label
  location: message property PR_SENDER_EMAIL_ADDRESS
  references-data:
  - {concept: EmailAddress, role: sender}
- name: recipient
  kind: label
  location: message recipient table → PR_DISPLAY_NAME / PR_EMAIL_ADDRESS
  references-data:
  - {concept: EmailAddress, role: recipient}
- name: delivery-time
  kind: timestamp
  location: message PR_MESSAGE_DELIVERY_TIME
  encoding: filetime-le
- name: deleted-items-folder
  kind: folder
  location: "Deleted Items NBT node — often retains messages the user believed deleted"
observations:
- proposition: CLIENT_CACHED_MAILBOX
  ceiling: C4
  note: "Cached-mode mailbox. Often contains messages no longer on the server (deleted items, shadow copies, mail from before retention policy kicked in). For insider / BEC cases where the user cleared their server mailbox, the OST may retain the evidence."
  qualifier-map:
    actor.user.email: field:sender
    object.recipient: field:recipient
    time.received: field:delivery-time
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - {tool: scanpst.exe, typically-removes: modifies for repair — destroys forensic integrity}
  - {tool: delete + Outlook re-sync, typically-removes: re-fetches from server (but deleted items may be gone from server too)}
provenance: [libyal-libpff, ms-pst]
exit-node:
  is-terminus: true
  primary-source: mitre-t1114-001
  attribution-sentence: 'Adversaries may target user email on local systems to collect sensitive information (MITRE ATT&CK, n.d.).'
  terminates:
    - COMMUNICATED
    - HAD_CONTENT
  sources:
    - libyal-libpff
    - ms-pst
  reasoning: >-
    Outlook-OST is the cached Exchange mail store for a connected
    Exchange account — full-fidelity copy of messages, attachments,
    calendars, contacts, journal entries synced from the server and
    held locally. For a cached-mode client (default), the OST IS the
    local authority for email content. Parallel to PST (.pst =
    offline-storage archive; .ost = cached Exchange). Terminus for
    COMMUNICATED / HAD_CONTENT when the target user runs Outlook in
    cached mode — which is the default.
  implications: >-
    Ransomware and attacker workflows frequently stage or exfil the
    OST because it's a self-contained email archive; a single file
    can yield years of correspondence. Server-side deletions do NOT
    retroactively remove items from an OST already synced — an
    analyst may recover messages the user's Outlook UI no longer
    shows. scanpst.exe "repair" modifies the OST destructively;
    chain-of-custody requires working on a forensic copy.
  preconditions: >-
    File path: %LOCALAPPDATA%\Microsoft\Outlook\<identity>.ost. No
    encryption by default on the OST itself (unless user-enabled
    Outlook password); parsed with libpff / Aid4Mail / Kernel OST
    viewer. Orphaned OST (no longer paired with Exchange) still
    parses but requires an OST-to-PST tool to mount fully.
  identifier-terminals-referenced:
    - EmailAddress
    - UserSID
---

# Outlook-OST

## Forensic value
Local cached copy of an Exchange mailbox. Same PFF format as PST. Often richer than the current server mailbox because:
- Server-side retention policies may have expired items that remain cached
- Items deleted after last sync still exist locally until the OST syncs the delete
- Soft-deleted items (Deleted Items folder) often persist here after server purge

For email-disappearance investigations where "the server has no record," the OST is frequently the surviving copy.

## Cross-references
- **Outlook-PST** — same PFF format; exported archive
- **Exchange-Mailbox-edb** — server-side canonical store
- **PST-Email-Item** — per-message artifact applicable here too
