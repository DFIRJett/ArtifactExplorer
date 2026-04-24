---
name: windows-sqlite
kind: database-file
substrate-class: Database
aliases: [SQLite, application-database, SQLite3]

format:
  storage: SQLite3
  magic: "SQLite format 3\\0"
  endianness: big (header); per-type on page contents
  page-size: "typically 4096 (configurable 512–65536)"
  authoritative-spec:
    - title: "SQLite Database File Format"
      url: https://www.sqlite.org/fileformat.html

known-instances:
  "Chrome/Edge History":
    path: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History  (or  ...\\Microsoft\\Edge\\User Data\\Default\\History)"
    tables: [urls, visits, downloads, keyword_search_terms]
  "Firefox places.sqlite":
    path: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\places.sqlite"
  "Teams (new) storage.db":
    path: "%APPDATA%\\Microsoft\\Teams\\<version>\\Storage"
  "Slack IndexedDB leveldb-in-sqlite":
    path: "%APPDATA%\\Slack\\IndexedDB\\..."
  "Signal Desktop message-db":
    path: "%APPDATA%\\Signal\\sql\\db.sqlite (encrypted)"
  "iMessage chat.db (on macOS sync or iOS backup)":
    path: "~/Library/Messages/chat.db"
  "Windows 10 Activity History (ActivitiesCache.db)":
    path: "%LOCALAPPDATA%\\ConnectedDevicesPlatform\\<userid>\\ActivitiesCache.db"

persistence:
  locked-on-live-system: "usually yes — apps hold exclusive locks while running"
  acquisition:
    - "close the owning app, copy the .sqlite file + -journal / -wal / -shm sibling files"
    - "VSS snapshot for locked-file bypass"
    - "sqlite3_backup API (forensically preferred — read-only, no modifications)"
  parsers:
    - { name: "sqlite3 CLI", strengths: [universal, read-only with '-readonly' flag] }
    - { name: "DB Browser for SQLite", strengths: [GUI, free] }
    - { name: "commercial forensic suites", strengths: [auto-parse known schemas, deleted-row recovery] }
    - { name: "SQLECmd (Zimmerman)", strengths: [named schemas for common DFIR databases] }

forensic-relevance:
  - journal-and-wal-files: |
      SQLite write-ahead-log (.wal) and journal (.journal / -shm) files contain
      uncommitted or recently-committed transactions. On an app that's still
      running, rows may exist in WAL but not yet in the main DB. Acquire both.
  - deleted-row-recovery: |
      SQLite marks deleted rows as free but typically doesn't zero the content
      until VACUUM runs. Forensic tools can carve deleted rows from the DB
      file (undark, sqlparse) or from freelist pages.
  - schema-discovery: "sqlite_master table is canonical — query it to learn the schema before extracting data"

integrity:
  signing: none
  tamper-vectors:
    - "any SQL tool can modify rows"
    - "schema changes via ALTER TABLE leave no trace in default pragma"
    - "VACUUM destroys deleted-row recovery"

known-artifacts:
  # Per-application SQLite databases. Each artifact is a specific product's
  # .db/.sqlite file with its own schema. Ghost count is large because
  # nearly every modern app stores state in SQLite.
  # Seed source: authored + Hindsight browser artifacts +
  # Artifacts-KB ActivitiesCache reference + Group-IB Chromium Edge analysis.
  authored:
    - Chrome-History           # History DB — urls/visits/downloads
    - Firefox-places           # places.sqlite — moz_places/moz_historyvisits
  unwritten:
    - Chrome-Downloads             # downloads + downloads_url_chains tables on History DB
    - Edge-History                 # same schema as Chrome-History (Chromium family)
provenance:
  - chromium-history-schema
  - mozilla-places-schema
  - sqlite-org-fileformat
  - benson-hindsight
--- Chromium family (Chrome/Edge/Brave/Opera share schema) ---
    - name: Chrome-Cookies
      location: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"
      value: authenticated-session tokens; per-site cookie history with created/expires
    - name: Chrome-Downloads
      location: History DB → downloads + downloads_url_chains tables
      value: completed/paused/cancelled downloads with full redirect chain
    - name: Chrome-LoginData
      location: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data"
      value: saved credentials (usernames + DPAPI-encrypted passwords)
    - name: Chrome-WebData
      location: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Web Data"
      value: autofill forms, credit cards, saved payment methods
    - name: Chrome-TopSites
      location: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Top Sites"
      value: most-visited page thumbnails and rank data
    - name: Chrome-Bookmarks
      location: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Bookmarks (JSON, not SQLite — crossref)"
      value: JSON-serialized bookmark tree; timestamp per entry
    - name: Edge-History
      location: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History"
      value: Chromium-Edge history (same schema as Chrome)
    - name: Edge-Cookies
      location: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies"
      value: Edge cookie store
    - name: Firefox-Cookies
      location: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\cookies.sqlite"
      value: Firefox cookie store (moz_cookies)
    - name: Firefox-FormHistory
      location: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\formhistory.sqlite"
      value: autofill form-entry history
    - name: Firefox-Downloads
      location: Firefox places.sqlite → moz_annos + downloads metadata
      value: downloads history (consolidated into places.sqlite in modern Firefox)
    # --- Windows 10/11 Timeline + activity ---
    - name: ActivitiesCache
      location: "%LOCALAPPDATA%\\ConnectedDevicesPlatform\\L.<user>\\ActivitiesCache.db"
      value: Win10 Timeline activity feed — per-app focus time, content payload, clipboard cross-device
    # --- Messaging apps ---
    - name: Skype-main-db
      location: "%APPDATA%\\Skype\\<user>\\main.db (classic) or %LOCALAPPDATA%\\Packages\\Microsoft.SkypeApp_*\\"
      value: chat messages, calls, participants
    - name: Signal-DB
      location: "%APPDATA%\\Signal\\sql\\db.sqlite"
      value: SQLCipher-encrypted Signal conversations; key in config.json (DPAPI-wrapped on Win10+)
    - name: Telegram-DB
      location: "%APPDATA%\\Telegram Desktop\\tdata\\ (proprietary format — limited SQLite)"
      value: chats and media (mostly non-SQLite but often classed with SQLite artifacts)
    - name: WhatsApp-DB
      location: "%APPDATA%\\..\\Local\\Packages\\5319275A.WhatsAppDesktop_*\\LocalState\\\\* (newer UWP version)"
      value: WhatsApp Desktop chats + media
    # --- Notifications and system app state ---
    - name: Notifications-wpndatabase
      location: "%LOCALAPPDATA%\\Microsoft\\Windows\\Notifications\\wpndatabase.db"
      value: Windows Push Notifications — toast content, app handles, arrival timestamps
    # --- Cloud sync clients ---
    - name: OneDrive-SyncEngine
      location: "%LOCALAPPDATA%\\Microsoft\\OneDrive\\settings\\Personal\\*.dat (mixed formats incl. SQLite)"
      value: OneDrive sync state; files-on-demand placeholder info
    - name: Dropbox-filecache
      location: "%APPDATA%\\Dropbox\\instance1\\filecache.dbx (encrypted SQLite variant)"
      value: Dropbox file state (decryption often needs extracted key)
---

# SQLite database

## Forensic value
The most common application-database format on modern systems. Browsers, chat clients, note apps, email clients, Windows' own Activity History — all use SQLite. For any application-centric investigation, the corresponding SQLite database is typically the primary artifact.

## Acquisition checklist
- Primary: `<name>.sqlite` (or no extension: `History`, `places.sqlite`, etc.)
- WAL: `<name>.sqlite-wal`
- Shared-memory: `<name>.sqlite-shm`
- Journal: `<name>.sqlite-journal`

The WAL file is forensically critical — recent transactions live there first. Skipping WAL = missing recent activity.

## Practice hint
Acquire a live Chrome's History file via VSS (can't copy directly — it's locked). Open with `sqlite3 History .schema` to see tables. Query `SELECT url, visit_count, datetime(last_visit_time/1000000-11644473600, 'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 20`.

Note the Chrome-specific timestamp format: microseconds since 1601-01-01 — the conversion offset above is standard-FILETIME-to-unix-epoch.
