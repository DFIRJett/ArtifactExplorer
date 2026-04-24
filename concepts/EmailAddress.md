---
name: EmailAddress
kind: value-type
lifetime: permanent
link-affinity: application
link-affinity-secondary: user
description: |
  RFC-5321 email address — local-part + '@' + domain-part. Captured by email
  clients, anti-phishing telemetry, identity artifacts, and some malware
  that hardcodes C2 email channels.
canonical-format: "local-part@domain (case-insensitive by convention; domain IS case-insensitive per DNS)"
aliases: [email, mailbox, rfc5321-address, smtp-address]
roles:
  - id: sender
    description: "Sender address on a message"
  - id: recipient
    description: "Recipient address (to/cc/bcc) on a message"
  - id: cachedIdentity
    description: "Email-form identity cached for authentication or user-mapping purposes"

known-containers:
  - Outlook-PST
  - Defender-MPLog
  - Credentials-cached
provenance:
  - rfc-5322-internet-message-format
  - rfc-6531-smtputf8-internationalized-email
---

# Email Address

## What it is
RFC-5321 mailbox identifier. Local-part + `@` + domain-part. Contains a `DomainName` as substring — every email address implies a receiving domain.

## Forensic value
- **Phishing reconstruction.** Sender + recipient addresses in PST/OST anchor who-sent-what-to-whom.
- **Account identity.** Same email reused across authentication artifacts (SSO, OAuth tokens) pivots user identity across systems.
- **Threat-intel.** Malicious sender addresses match known campaigns.

## Relationship to DomainName
Every email address yields one DomainName (the part after `@`). Build pipeline does NOT auto-derive; artifacts referencing emails should reference both if investigator should pivot on either.

## Encoding variations

| Artifact | Where |
|---|---|
| Outlook-PST | sender/recipient/cc headers per message |
| Defender-MPLog | email-attachment scan entries show sender address |
| Credentials-cached | cached Windows Hello / work account identities |
