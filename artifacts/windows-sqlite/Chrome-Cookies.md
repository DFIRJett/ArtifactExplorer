---
name: Chrome-Cookies
aliases:
- Chromium cookies
- Edge cookies
- browser session tokens
link: application
tags:
- per-user
- tamper-easy
- credential-material
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: Chrome-Cookies
platform:
  windows:
    min: '7'
    max: '11'
location:
  path: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"
  alternates:
    - "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies"
    - "%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies"
  addressing: sqlite-table-row
fields:
- name: host_key
  kind: hostname
  location: cookies table → host_key column
  note: cookie domain scope; leading dot means 'and subdomains'
  references-data:
  - concept: DomainName
    role: httpRequestHost
- name: name
  kind: label
  location: cookies table → name column
- name: value
  kind: ciphertext
  location: cookies table → encrypted_value column
  encoding: DPAPI (Chrome v80+) — key encrypted in Local State → os_crypt.encrypted_key
  note: plaintext 'value' column is empty in v80+; all tokens in encrypted_value
- name: path
  kind: path
  location: cookies table → path column
- name: creation_utc
  kind: timestamp
  location: cookies table → creation_utc
  encoding: webkit-microseconds (microseconds since 1601-01-01 UTC)
  clock: system
  resolution: 1us
- name: last_access_utc
  kind: timestamp
  location: cookies table → last_access_utc
  encoding: webkit-microseconds
- name: expires_utc
  kind: timestamp
  location: cookies table → expires_utc
  encoding: webkit-microseconds
  note: 0 = session cookie (deleted at browser close)
- name: is_secure
  kind: flag
  location: cookies table → is_secure
- name: is_httponly
  kind: flag
  location: cookies table → is_httponly
- name: samesite
  kind: flag
  location: cookies table → samesite
  note: -1 unspecified / 0 None / 1 Lax / 2 Strict
observations:
- proposition: AUTHENTICATED_SESSION
  ceiling: C3
  note: Session tokens valid at time of acquisition; cookie theft gives resumable auth to web services without password. Pair with browser Sync state for cross-device context.
  qualifier-map:
    object.domain: field:host_key
    actor.user: profile directory owner
    time.last_access: field:last_access_utc
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - tool: browser settings 'Clear cookies'
    typically-removes: full
  - tool: CCleaner
    typically-removes: full
  - tool: VACUUM via sqlite3
    typically-removes: deleted-row recovery
provenance: [chromium-history-schema]
---

# Chrome-Cookies

## Forensic value
The authenticated-session record for every website the user is logged into. A fresh cookie export yields resumable sessions to Gmail, Office365, GitHub, AWS console — anything the user has open.

Chrome encrypts `encrypted_value` with a DPAPI-wrapped AES-GCM key stored in `Local State` → `os_crypt.encrypted_key`. Decryption sequence:
1. Read `Local State` JSON, extract and base64-decode `os_crypt.encrypted_key`
2. Strip the `DPAPI` prefix (5 bytes)
3. Pass to `CryptUnprotectData` under the profile user's context — yields the AES key
4. For each encrypted_value: strip `v10`/`v11` prefix, split nonce (12 bytes) + ciphertext + tag (16 bytes), AES-GCM decrypt

Tools that automate this: Hindsight, DB Browser for SQLite + chrome_cookie decryption scripts, browser forensic suites (Belkasoft, Magnet).

## Live-file caveat
The Cookies file is locked while Chrome is running. Options:
- Shadow copy + offline
- Kill browser + copy
- Live triage with the Debug Protocol over `--remote-debugging-port=9222` (intrusive; changes state)

## Cross-references
- **Chrome-History** (History DB) — visits to the domains in host_key
- **Chrome-LoginData** — saved password for the same domains (complementary credential)
- **WebCache-V01** (ESE) — IE/Edge-legacy cookie store; separate artifact, different format

## Practice hint
```python
import sqlite3
conn = sqlite3.connect(r'...\Default\Network\Cookies')
for r in conn.execute("SELECT host_key, name, datetime((creation_utc-11644473600000000)/1000000, 'unixepoch') AS created FROM cookies ORDER BY creation_utc DESC LIMIT 20"):
    print(r)
```
Timestamp conversion: `(value - 11644473600000000) / 1000000` → Unix epoch seconds.
