---
name: RDP-Bitmap-Cache
title-description: "Terminal Server Client bitmap cache — tiled RDP screen bitmaps reconstructable into screenshots"
aliases:
- RDP bitmap cache
- Terminal Services client cache
- mstsc bmc files
link: network
link-secondary: user
tags:
- per-user
- remote-session-reconstruction
- itm:ME
- itm:IF
volatility: persistent
interaction-required: user-action
substrate: windows-binary-cache
substrate-instance: RDP-Bitmap-Cache
platform:
  windows:
    min: '7'
    max: '11'
  windows-server:
    min: '2008R2'
    max: '2022'
location:
  path: "%LOCALAPPDATA%\\Microsoft\\Terminal Server Client\\Cache\\"
  addressing: file-path
  note: "mstsc.exe (Remote Desktop client) caches small bitmap tiles from each RDP session to reduce bandwidth on subsequent redraws. Default cache filenames: Cache0000.bin through CacheNNNN.bin (streaming binary) plus bcache*.bmc (per-bitmap format). Enabled by default when 'Persistent bitmap caching' checkbox is on in mstsc — it is."
fields:
- name: profile-sid
  kind: identifier
  location: derived from path segment `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\` — the owning user's SID resolves via ProfileList ProfileImagePath
  encoding: sid-string
  note: "Not stored in the cache file itself — derived from the per-user cache directory path. Required to attribute RDP-session bitmap evidence to a specific user account that ran mstsc.exe."
  references-data:
  - concept: UserSID
    role: profileOwner
- name: bitmap-tile
  kind: content
  location: "Cache\\bcache24.bmc (or Cache0000.bin) — 64x64 pixel tile records"
  encoding: "24bpp-RGB tile (per format: bcache24 / bcache2 / bcache5)"
  note: "Each tile is a small slice of the remote screen (typically 64x64 pixels). Thousands of tiles per file. Reassembled via shape-and-position matching to produce full screenshots — tools like bmc-tools (ANSSI) or BMC Viewer do this automatically."
- name: tile-key
  kind: identifier
  location: "per-tile header — bitmap cache key"
  encoding: uint64
  note: "Uniquely identifies a tile across the session for cache hit/miss tracking. Not directly forensic but used by reassembly tools for deduplication."
- name: cache-file-mtime
  kind: timestamp
  location: Cache\bcacheNN.bmc / Cache000N.bin file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime brackets the window of the most-recent RDP session that wrote to this cache file. Cross-reference with TS-Client-MRU and TerminalServerClient-Default registry keys to confirm WHICH server was connected to in that window."
- name: cache-version
  kind: label
  location: "bcacheNN.bmc header — cache-format version"
  encoding: varies (bcache2 = legacy; bcache24 = 24bpp color; bcache5 = newer)
  note: "Different file formats hold different bit depths. Modern Windows 10/11 primarily produces bcache24.bmc (24bpp) and Cache0000.bin (stream). Pick the parser based on filename."
- name: persistent-cache-flag
  kind: flags
  location: "Registry joined: HKCU\\Software\\Microsoft\\Terminal Server Client\\BitmapCacheSize + BitmapPersistCacheSize"
  type: REG_DWORD
  note: "Controls the on-disk cache allowance. Default is non-zero (cache enabled). An attacker-authored 0 here disables the cache to prevent later reconstruction. Worth checking alongside the cache files themselves."
observations:
- proposition: VIEWED_REMOTE
  ceiling: C4
  note: 'RDP bitmap cache is the single best source of "what the user
    actually saw on the remote server." Because the cache is tile-based
    and persisted to the client''s disk, a DFIR team months after the
    fact can reconstruct screen captures of exactly which server
    windows, applications, and data the user had open during an RDP
    session. No server-side logging can provide this. For insider-
    threat cases where a user used RDP to access sensitive systems
    (PII databases, trading terminals, source-code repos), the bitmap
    cache gives pixel-level evidence of the viewing session even if
    the user took no explicit screenshots.'
  qualifier-map:
    direction: outbound
    peer.address: artifact:TS-Client-MRU
    time.start: field:cache-file-mtime
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: clear cache via mstsc "Clear" button or delete Cache\ folder
    typically-removes: all .bmc / .bin files (tiles lost; registry mtimes and MRU entries remain)
  - tool: set HKCU\...\Terminal Server Client\BitmapPersistCacheSize = 0
    typically-removes: prospective caching (cache never written during subsequent sessions)
  survival-signals:
  - Cache\bcacheNN.bmc present with mtimes matching incident window = reconstructable RDP session screens
  - Cache folder empty but TS-Client-MRU shows recent connections = deliberate cache clear, investigate for cover-up
  - Large .bmc files (tens of MB) on a user who claims "I never RDP'd to that server" = direct contradiction
provenance:
  - anssi-fr-2016-bmc-tools-python-tool-to-recon
  - ms-remote-desktop-protocol-bitmap-cach
  - matrix-nd-dt061-detect-text-authored-in
exit-node:
  is-terminus: true
  primary-source: mitre-t1021-001
  attribution-sentence: 'Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP) (MITRE ATT&CK, n.d.).'
  terminates:
    - ACCESSED_REMOTELY
    - VIEWED_LOCATION
  sources:
    - anssi-fr-2016-bmc-tools-python-tool-to-recon
    - ms-remote-desktop-protocol-bitmap-cach
  reasoning: >-
    The per-session bitmap cache under %LOCALAPPDATA%\Microsoft\
    Terminal Server Client\Cache holds 64x64-pixel tiles of the
    remote desktop screen painted during the RDP session. Tile
    reconstruction (bmc-tools) yields a partial-to-substantial
    rendering of what the attacker SAW on the remote host. This
    is terminal visual evidence: there is no "upstream" — the
    tiles themselves ARE the recorded view. For ACCESSED_REMOTELY
    convergence, the cache provides the definitive what-did-they-
    see answer when connection-fact evidence establishes the
    session.
  implications: >-
    Reconstructed tiles showing remote desktops, file explorer
    windows, documents open on the remote host, or command-line
    tools in use constitute direct visual evidence of RDP-
    mediated activity. Cache survives session close and persists
    until overwritten by subsequent sessions (LRU eviction within
    the 8192-tile file capacity). Per-user and per-host scope —
    shows which specific user connected to which specific server,
    per the containing cache folder.
  preconditions: >-
    mstsc.exe (the Windows built-in RDP client) must have created
    the cache. UWP Remote Desktop / third-party clients don't
    populate it. Bitmap Caching must be enabled client-side
    (default-on but can be toggled in the client's experience
    settings). Cache file is binary .bmc format; bmc-tools.py or
    RegRipper plugin parses.
  identifier-terminals-referenced:
    - UserSID
    - IPAddress
---

# RDP Bitmap Cache

## Forensic value
mstsc.exe (Remote Desktop Connection) caches bitmap tiles of the remote screen to its local AppData. The cache is designed for bandwidth optimization but functions forensically as a client-side screen recording of every RDP session. Reassembled tiles produce near-complete screenshots of what the user saw.

Location: `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\`
- `bcache24.bmc` — 24bpp RGB tile format (modern)
- `Cache0000.bin` through `CacheNNNN.bin` — streaming variant
- `bcache2.bmc` / `bcache5.bmc` — legacy variants

Default RDP client settings have persistent bitmap caching enabled; opting out requires unchecking "Persistent bitmap caching" in mstsc's Experience tab before connecting. Most users never touch this setting.

## Why it's uniquely valuable
Nothing else in Windows forensics provides a visual reconstruction of a remote session. Server-side RDP event logs (Security-4624, TerminalServices-LocalSessionManager) tell you the session happened; UAL tells you which client IPs connected. Neither tells you what was on the screen. The bitmap cache does.

For insider-threat casework where a user RDP'd to a sensitive server and "just looked at" data (the classic "I didn't exfil, I only viewed" defense), bitmap cache reconstruction often produces pixel evidence of the specific records, screens, or applications the user actually viewed.

## Concept references
- IPAddress (via join to TS-Client-MRU / TerminalServerClient-Default for destination)

## Reconstruction workflow
```powershell
# Acquire the Cache folder for the user of interest
Copy-Item "C:\Users\<user>\AppData\Local\Microsoft\Terminal Server Client\Cache" -Destination .\evidence\rdp-cache\ -Recurse

# Reassemble with bmc-tools (Linux analyst box)
# git clone https://github.com/ANSSI-FR/bmc-tools.git
# python3 bmc-tools.py -s .\evidence\rdp-cache -d .\output -b
```

Output is a directory of per-tile PNGs. Manual reassembly (spatial arrangement) is required for full-screen reconstruction but individual tiles often carry enough context (visible text, UI widgets, visible data columns) to identify what was on screen without reassembly.

## Cross-reference
- `HKCU\Software\Microsoft\Terminal Server Client\Default\MRUn` — last N servers connected to
- `HKCU\Software\Microsoft\Terminal Server Client\Servers\<hostname>` — per-server persistent config
- Security-4624 type 10 on the target server = matching inbound logon

Chain: TS-Client-MRU → target server → bitmap cache acquired on the client = "what the user saw on that specific server in that specific session."

## Practice hint
On a lab setup: RDP from a test client to a test server. Open Notepad on the server, type identifiable text ("this is test content 12345"). Disconnect. On the client, locate `bcache24.bmc` in Cache folder, run bmc-tools, browse the output PNGs. You'll see tiles containing your typed text — proof that mstsc cached the visible pixels to the client's disk without any user action.
