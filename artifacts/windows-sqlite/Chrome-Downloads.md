---
name: Chrome-Downloads
aliases:
- Chromium downloads
- Edge downloads
- downloads table
link: file
link-secondary: application
tags:
- per-user
- tamper-easy
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: Chrome-History
platform:
  windows:
    min: '7'
    max: '11'
location:
  path: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History"
  alternates:
    - "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History"
  addressing: sqlite-table-row
fields:
- name: target_path
  kind: path
  location: downloads table → target_path
  note: final disk path of downloaded file
- name: current_path
  kind: path
  location: downloads table → current_path
  note: path during active download (.crdownload suffix); equals target_path when complete
- name: tab_url
  kind: url
  location: downloads table → tab_url
  note: URL of the page that INITIATED the download (not necessarily the download URL itself)
  references-data:
  - concept: URL
    role: referrerUrl
- name: tab_referrer_url
  kind: url
  location: downloads table → tab_referrer_url
  references-data:
  - concept: URL
    role: referrerUrl
- name: mime_type
  kind: label
  location: downloads table → mime_type
- name: original_mime_type
  kind: label
  location: downloads table → original_mime_type
  note: server-declared MIME — diverges from mime_type when Chrome reclassified; forensic anomaly signal
- name: total_bytes
  kind: size
  location: downloads table → total_bytes
- name: received_bytes
  kind: size
  location: downloads table → received_bytes
- name: state
  kind: flag
  location: downloads table → state
  note: 0 in-progress / 1 complete / 2 cancelled / 3 interrupted / 4 cancelled-by-tab-close
- name: danger_type
  kind: flag
  location: downloads table → danger_type
  note: SafeBrowsing verdict — 0 not-dangerous / 1 dangerous-file / 2 dangerous-url / others
- name: interrupt_reason
  kind: flag
  location: downloads table → interrupt_reason
- name: hash
  kind: hash
  location: downloads table → hash
  encoding: SHA256 raw bytes (32B)
  note: content SHA256 Chrome computed post-download — pivot against threat-intel directly
  references-data:
  - concept: ExecutableHash
    role: scannedHash
- name: start_time
  kind: timestamp
  location: downloads table → start_time
  encoding: webkit-microseconds
  clock: system
  resolution: 1us
- name: end_time
  kind: timestamp
  location: downloads table → end_time
  encoding: webkit-microseconds
- name: chain-url
  kind: url
  location: downloads_url_chains table → url (joined by id)
  note: redirect chain from initial URL to final bytes; multiple rows per download
  references-data:
  - concept: URL
    role: downloadedFromUrl
observations:
- proposition: DOWNLOADED
  ceiling: C3
  note: Chromium records every download with initiating tab URL, full redirect chain, content hash. High-value for phishing/supply-chain/C2-payload attribution.
  qualifier-map:
    object.file.path: field:target_path
    object.file.hash: field:hash
    object.source.url: field:tab_url
    time.start: field:start_time
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - tool: Clear browsing data → Downloads
    typically-removes: full (but VACUUM needed to defeat row-recovery)
  - tool: VACUUM via sqlite3
    typically-removes: deleted-row recovery
provenance: [chromium-history-schema]
---

# Chrome-Downloads

## Forensic value
Chromium's canonical download record. Per-download row in `downloads` with full metadata, plus the `downloads_url_chains` join table that preserves the redirect path — often multiple hops from the click target to the final byte source, revealing intermediate redirectors or CDN fronts.

The `hash` column is the forensic crown jewel: Chrome computes SHA256 during the download and stores the raw bytes. Convert to hex and pivot against VirusTotal / internal threat-intel immediately — no need to re-hash from disk.

## Redirect-chain analysis
```sql
SELECT d.target_path, d.start_time, c.chain_index, c.url
FROM downloads d
JOIN downloads_url_chains c ON c.id = d.id
ORDER BY d.start_time DESC, c.chain_index ASC;
```
Chains > 2 hops deserve scrutiny. Chains terminating at raw IP addresses or `.tk`/`.ru`/`.xyz` TLDs from casual user traffic are anomalies worth tracing.

## State + danger_type interpretation
- `state=1` AND `danger_type=0` — completed, SafeBrowsing cleared
- `state=1` AND `danger_type>0` — completed despite warning (user overrode)
- `state=3` (interrupted) — worth checking `interrupt_reason`; sometimes evidence of active defender response mid-download

## Cross-references
- **Zone-Identifier-ADS** on the target_path — Mark-of-the-Web attached by Chrome; survives browser uninstall
- **Defender-MPLog** — SmartScreen / Defender scan of the downloaded file
- **Sysmon-15** (FileCreateStreamHash) — captures the Zone-Identifier ADS creation moment + file hash independently

## Practice hint
Extract downloads with their chains in one go:
```python
import sqlite3
conn = sqlite3.connect(r'...\Default\History')
for tgt, url, start in conn.execute("""
    SELECT target_path, tab_url,
      datetime((start_time-11644473600000000)/1000000, 'unixepoch')
    FROM downloads ORDER BY start_time DESC LIMIT 20
"""):
    print(tgt, start, url)
```
