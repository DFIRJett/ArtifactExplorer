---
name: Firefox-Cookies
aliases: [Mozilla Firefox cookies]
link: application
tags: [per-user, credential-material]
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: Firefox-Cookies
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\cookies.sqlite"
  addressing: sqlite-table-row
fields:
- name: host
  kind: hostname
  location: moz_cookies → host
  references-data:
  - {concept: DomainName, role: httpRequestHost}
- name: name
  kind: label
  location: moz_cookies → name
- name: value
  kind: label
  location: moz_cookies → value
  note: "Firefox cookies are stored PLAINTEXT in moz_cookies.value — no per-cookie encryption (unlike Chromium)"
- name: creationTime
  kind: timestamp
  location: moz_cookies → creationTime
  encoding: webkit-microseconds (microseconds since 1970-01-01 UTC)
  clock: system
  resolution: 1us
- name: lastAccessed
  kind: timestamp
  location: moz_cookies → lastAccessed
  encoding: webkit-microseconds
- name: expiry
  kind: timestamp
  location: moz_cookies → expiry
  encoding: unix-epoch-seconds
observations:
- proposition: AUTHENTICATED_SESSION
  ceiling: C3
  note: "Firefox cookie store. Values are PLAINTEXT — no DPAPI dance required. Makes Firefox profiles the easier extraction target when both browsers are in scope."
  qualifier-map:
    object.domain: field:host
    time.last_access: field:lastAccessed
anti-forensic:
  write-privilege: unknown
provenance: [mozilla-places-schema]
---

# Firefox-Cookies

## Forensic value
Mozilla Firefox cookie store. Key difference from Chromium family: values are **plaintext** — directly readable without DPAPI key extraction. Makes Firefox the easier target when both browsers are in scope.

## Cross-references
- **Firefox-places** — paired visit history (places.sqlite)
- **Firefox-FormHistory** — autofill companion
- **Firefox-Downloads** — also in places.sqlite (consolidated in modern FF)
