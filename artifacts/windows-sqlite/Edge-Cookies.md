---
name: Edge-Cookies
aliases: [Microsoft Edge Chromium cookies]
link: application
tags: [per-user, credential-material]
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: Edge-Cookies
platform:
  windows: {min: '10', max: '11'}
location:
  path: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies"
  addressing: sqlite-table-row
fields:
- name: host_key
  kind: hostname
  location: cookies table → host_key
  references-data:
  - {concept: DomainName, role: httpRequestHost}
- name: name
  kind: label
  location: cookies table → name
- name: encrypted_value
  kind: ciphertext
  location: cookies table → encrypted_value
  encoding: "DPAPI-wrapped AES-GCM (identical scheme to Chrome-Cookies) — key in Local State → os_crypt.encrypted_key"
- name: creation_utc
  kind: timestamp
  location: cookies table → creation_utc
  encoding: webkit-microseconds
- name: last_access_utc
  kind: timestamp
  location: cookies table → last_access_utc
  encoding: webkit-microseconds
- name: expires_utc
  kind: timestamp
  location: cookies table → expires_utc
  encoding: webkit-microseconds
observations:
- proposition: AUTHENTICATED_SESSION
  ceiling: C3
  note: "Edge cookie store. Same format as Chrome — Chromium shared schema. Session tokens extractable with the profile user's DPAPI context."
  qualifier-map:
    object.domain: field:host_key
    time.last_access: field:last_access_utc
anti-forensic:
  write-privilege: unknown
provenance: [chromium-history-schema]
---

# Edge-Cookies

## Forensic value
Microsoft Edge (Chromium) cookies. Byte-for-byte schema match with Chrome-Cookies. Tools built for Chrome work here with only path changes. Critical for corporate-managed Edge installations with AAD sync — extracted cookies may give access to Office 365, SharePoint, Teams.

## Cross-references
- **Chrome-Cookies** — identical schema; shared DPAPI chain
- **Edge-History** — paired visit history
- **WebCache-V01** — legacy IE/Edge-Legacy cookie store (ESE, not SQLite)
