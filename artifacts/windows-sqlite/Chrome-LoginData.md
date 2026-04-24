---
name: Chrome-LoginData
aliases: [Chromium saved passwords, Edge Login Data]
link: security
link-secondary: application
tags: [per-user, credential-material, tamper-easy]
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: Chrome-LoginData
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data"
  alternates:
  - "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data"
  addressing: sqlite-table-row
fields:
- name: origin_url
  kind: url
  location: logins table → origin_url
  references-data:
  - {concept: URL, role: visitedUrl}
- name: username_value
  kind: label
  location: logins table → username_value
  type: TEXT
- name: password_value
  kind: ciphertext
  location: logins table → password_value
  encoding: "Chrome v80+ — AES-GCM with DPAPI-wrapped key in Local State (same scheme as Chrome-Cookies); v79 and earlier — raw DPAPI blob"
- name: date_created
  kind: timestamp
  location: logins table → date_created
  encoding: webkit-microseconds
- name: date_last_used
  kind: timestamp
  location: logins table → date_last_used
  encoding: webkit-microseconds
- name: times_used
  kind: counter
  location: logins table → times_used
observations:
- proposition: CREDENTIAL_STORED
  ceiling: C3
  note: "Saved credentials for web logins. Decryption requires the profile user's DPAPI context. High-value credential-access target."
  qualifier-map:
    actor.user: profile-dir owner
    object.url: field:origin_url
    object.credential.username: field:username_value
    time.last_use: field:date_last_used
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - {tool: Settings → Passwords → Delete, typically-removes: row-level}
provenance: [chromium-history-schema]
---

# Chrome-LoginData

## Forensic value
Browser-saved login credentials. Extractable with the profile user's DPAPI context (live or with stolen DPAPI master key offline). Complements Chrome-Cookies — cookies give resumable sessions, LoginData gives the raw credentials for re-authentication.

## Decryption chain (same as Cookies)
Local State JSON → `os_crypt.encrypted_key` → DPAPI-unwrap → AES-GCM key → decrypt each password_value (v10/v11 prefix + nonce + ciphertext + tag).

## Cross-references
- **Chrome-Cookies** — session tokens for the same domains
- **Chrome-History** — the domains the user actually visited
- **LSA-Secrets** — DPAPI master key storage chain
