---
name: Chrome-WebData
aliases: [Chromium autofill, Edge Web Data, saved credit cards]
link: user
link-secondary: application
tags: [per-user, credential-material, tamper-easy]
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: Chrome-WebData
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Web Data"
  alternates:
  - "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Web Data"
  addressing: sqlite-table-row
fields:
- name: autofill-entry
  kind: label
  location: autofill table → (name, value, date_created)
  references-data:
  - concept: URL
    role: visitedUrl
  note: "form-field autofill history — captures names, addresses, phone numbers, search terms typed into forms"
- name: credit_card_number_encrypted
  kind: ciphertext
  location: credit_cards table → card_number_encrypted
  encoding: "same DPAPI/AES-GCM scheme as Chrome-Cookies"
- name: name_on_card
  kind: label
  location: credit_cards table → name_on_card
- name: expiration_month
  kind: label
  location: credit_cards table → expiration_month
- name: address_line_1
  kind: label
  location: autofill_profiles table
- name: date_modified
  kind: timestamp
  location: "*.date_modified (varies by table)"
  encoding: webkit-microseconds
observations:
- proposition: USER_PROFILE_DATA_STORED
  ceiling: C3
  note: "Autofill + saved-payment data. Decryptable with profile DPAPI context. High-value for identity/financial fraud investigations."
  qualifier-map:
    actor.user: profile-dir owner
anti-forensic:
  write-privilege: user
provenance: [chromium-history-schema]
---

# Chrome-WebData

## Forensic value
Autofill form history + saved credit cards + saved addresses. Complements Chrome-LoginData (passwords); gives the NON-credential identity data the browser offers to fill. Useful for fraud/identity investigations and for establishing a user's real-world identity against a suspect profile.

## Cross-references
- **Chrome-LoginData** — paired credential store
- **Chrome-Cookies** — same DPAPI/AES-GCM key chain
