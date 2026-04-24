---
name: windows-ess
kind: database-file
substrate-class: Database
aliases: [ESE, Jet Blue, Extensible Storage Engine, EDB]

format:
  storage: "Extensible Storage Engine (ESE / Jet Blue) — the same engine Exchange, Active Directory, and Windows Search use"
  file-extension: [.edb, .dat, .jdb]
  page-size: "typically 4096, 8192, or 32768 bytes per page"
  authoritative-spec:
    - title: "Extensible Storage Engine (ESE) database file format"
      author: Joachim Metz
      url: https://github.com/libyal/libesedb/blob/main/documentation/Extensible%20Storage%20Engine%20(ESE)%20Database%20File%20(EDB)%20format.asciidoc
    - title: "MS-ESE: Extensible Storage Engine Database (Microsoft)"
      publisher: Microsoft (partial public docs)

known-instances:
  "SRUDB.dat (System Resource Usage Monitor)":
    path: "%WINDIR%\\System32\\sru\\SRUDB.dat"
    tables: [NetworkConnectivity, NetworkUsage, AppResourceUsage, AppHistory, EnergyUsage, PushNotification]
  "Windows.edb (Windows Search)":
    path: "%ProgramData%\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb"
  "ntds.dit (Active Directory)":
    path: "%WINDIR%\\NTDS\\ntds.dit"
  "WebCache*.dat (IE/Edge WebCache)":
    path: "%LOCALAPPDATA%\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat"
  "DataStore.edb (Windows Update)":
    path: "%WINDIR%\\SoftwareDistribution\\DataStore\\DataStore.edb"

persistence:
  locked-on-live-system: yes
  acquisition: "raw-disk image, VSS snapshot, or service-stop + file copy"
  parsers:
    - { name: libesedb / esedbexport (Joachim Metz), strengths: [format-correct, research-grade] }
    - { name: SrumECmd (Eric Zimmerman), strengths: [SRUM-specialized, CSV export] }
    - { name: ESEDatabaseView (NirSoft), strengths: [GUI, quick browsing] }
    - { name: Python `pyesedb`, strengths: [scriptable] }

forensic-relevance:
  - dirty-state-recovery: "ESE files can be 'dirty' (uncommitted transactions). Some parsers require running `esentutl /r` to apply transaction logs before querying — forensically: do this on a copy, never on the original."
  - table-schema-discovery: "Each .edb has its own table set; schema must be discovered at parse time. GUIDs as table names are common (e.g., SRUM uses {d10ca2fe-6fcf-4f6d-848e-b2e99266fa89})."
  - deleted-row-recovery: "ESE supports soft-deletes; rows marked deleted persist until vacuum. Offline parsers can recover them."

integrity:
  signing: none
  transaction-log: "paired .log + .jrs files next to the .edb manage ACID; replay required for consistency"
  tamper-vectors:
    - "direct EDB manipulation via libesedb"
    - "ese table truncation via esentutl"
    - "selective row deletion (requires schema knowledge)"

known-artifacts:
  # ESE/Jet-Blue substrate. Artifacts are per-subsystem: SRUM (resource usage),
  # Windows Search (Windows.edb), IE/Edge WebCache (WebCacheV01.dat), Active
  # Directory (ntds.dit on DCs), Exchange (Mailbox.edb), and thumbnail cache.
  # Each table within a shared DB is a distinct forensic artifact.
  # Seed source: authored + Psmths/windows-forensic-artifacts + ForensicFocus
  # Windows Search, Magnet SRUM guide, ESE-analyst toolset.
  authored:
    - SRUM-Process             # SRUDB.dat → {AppResource}/{Process} table (existing)
  unwritten:
    # 
provenance:
  - libyal-libesedb
--- SRUM sibling tables (all within SRUDB.dat) ---
    - name: SRUM-NetworkUsage
      location: "%WINDIR%\\System32\\sru\\SRUDB.dat → {973F5D5C-1D90-4944-BE8E-24B94231A174} table"
      value: per-process bytes-sent/received per network interface per user
    - name: SRUM-NetworkConnections
      location: SRUDB.dat → {DD6636C4-8929-4683-974E-22C046A43763} table
      value: network-interface connection events (SSID/profile, connect/disconnect times)
    - name: SRUM-EnergyUsage
      location: SRUDB.dat → {FEE4E14F-02A9-4550-B5CE-5FA2DA202E37} table
      value: per-process energy/battery telemetry
    - name: SRUM-ApplicationResource
      location: SRUDB.dat → {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89} table
      value: per-app foreground/background time and CPU per user
    - name: SRUM-PushNotifications
      location: SRUDB.dat → {D10CA2FE-6FCF-4F6D-848E-B2E99266FA86} table
      value: notification delivery per app
    # --- Windows Search ---
    - name: Windows-Search-edb
      location: "%PROGRAMDATA%\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb"
      value: SystemIndex table — full-text content, file/email/IM/calendar indexing with path + summary
    # --- IE/Edge legacy caches ---
    - name: WebCache-V01
      location: "%LOCALAPPDATA%\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat"
      value: IE/Edge-Legacy history, cookies, download history, DOMStore — pre-Chromium Edge artifact
    # --- Thumbnail cache (ESE-format in Win7+) ---
    - name: Thumbcache-edb
      location: "%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\thumbcache_*.db"
      value: cross-references windows-thumbcache container; image thumbnails as proof-of-viewing
    # --- Domain controllers ---
    - name: NTDS-dit
      location: "%WINDIR%\\NTDS\\ntds.dit (DC-only)"
      value: Active Directory database — user accounts, password hashes, GPOs, domain structure
    # --- Exchange (server) ---
    - name: Exchange-Mailbox-edb
      location: Exchange Server data path (per mailbox DB)
      value: server-side mailbox store — messages, attachments, calendars
    # --- Offline Address Book ---
    - name: OAB-edb
      location: "%LOCALAPPDATA%\\Microsoft\\Outlook\\Offline Address Books\\"
      value: cached Exchange global address list — enumerates org users
---

# Windows Extensible Storage Engine (ESE / EDB)

## Forensic value
Microsoft's longstanding embedded database engine. Not forensically interesting in itself — the INTEREST is in which databases use it and what they record. SRUDB.dat (resource usage per app per user), WebCache (browser history + proxy), ntds.dit (AD objects) are all ESE files.

The pattern matters: ESE is a *substrate* used by many forensic artifacts. Each .edb/.dat/.jdb file is a substrate-instance of this class, with its own internal schema (table names, column definitions, row contents).

## Acquisition notes
Always copy all sibling files:
- `<name>.edb` — primary database
- `<name>.chk` — checkpoint file (pointer to last-replayed log)
- `*.log` — transaction logs (numbered, rolling)
- `*.jrs` — reserved log space
- `*.jtx` — transaction log files on some installations

If the database is "dirty" (checkpoint ≠ latest transaction), parsers may fail or produce stale data. Use `esentutl /r <base>` on a *copy* to recover before analysis.

## Practice hint
Acquire `%WINDIR%\System32\sru\SRUDB.dat` from a live Win10 system (requires service stop or VSS). Open with SrumECmd. Observe the AppResourceUsage table — one row per (app, user, hour-bucket) with disk/network byte counters.
