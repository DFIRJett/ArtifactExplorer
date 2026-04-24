# Nomenclature

Read-only reference for the naming axes in this project. Captures the conventions the data follows so contributors (human or AI) can match the existing style without reverse-engineering it.

**Scope:** names only. For the architectural model — tiers, observations, convergences, scenarios, exit-nodes, volatility axis — see `docs/architecture.md`.

---

## 1. Artifact names

**Rule:** `name:` in the frontmatter must match the filename stem. Validator enforces this — don't rename one side without the other.

Four naming patterns in active use, picked by evidence shape:

### 1.1 Event-ID style (Windows Event Log channels)

Used for single-event artifacts in `artifacts/windows-evtx/`.

**Format:** `<ProviderShort>-<EventID>`

- `ProviderShort` is the short channel / provider label (e.g., `Security`, `Sysmon`, `System`, `Firewall`, `PowerShell`, `BITS`, `Defender`, `KernelPnP`, `DeviceSetup`).
- `EventID` is the integer event ID.

Examples: `Security-4624`, `Sysmon-10`, `PowerShell-4104`, `System-41`, `Firewall-2004`, `BITS-60`.

**Exception:** for channels where we treat the whole channel as one artifact rather than per-event, use the channel name only: `DriverFrameworks-Operational`.

### 1.2 PascalCase (named artifacts in registry / filesystem / binary caches)

Used when the artifact already has a canonical community name from SANS, Eric Zimmerman tooling, libyal, 13Cubed, etc. Inherit the name verbatim in its community PascalCase form.

Examples: `USBSTOR`, `MountedDevices`, `ShellBags`, `Amcache`, `Prefetch`, `MFT`, `UsnJrnl`, `BAM`, `RecentDocs`, `ShimCache`, `UserAssist`.

### 1.3 PascalCase-subpart (registry subkeys meriting their own artifact)

Used when a single community-named artifact (e.g., Amcache) has multiple forensically distinct subkeys that each deserve independent modeling.

**Format:** `<ParentPascal>-<QualifierPascal>`

Examples: `Amcache-InventoryApplicationFile`, `Amcache-InventoryDriverBinary`, `Amcache-InventoryDevicePnp`, `Active-Setup`, `AppInit-DLLs`, `Winlogon-Userinit-Shell`.

### 1.4 Lowercase-kebab (plaintext log files)

Used for plaintext `.log` artifacts where the log filename on disk is itself the canonical identifier.

Examples: `firewall-log`, `proxy-log`, `setupapi-dev-log`, `Setupapi-Upgrade-Log` (capitalized variant — the file on disk is PascalCase).

### 1.5 When a new artifact doesn't fit cleanly

Pick in this priority order:
1. If it's an evtx event → Event-ID style (1.1).
2. If the DFIR field already has a name for it → inherit verbatim, PascalCase (1.2).
3. If it's a subkey of a named artifact → PascalCase-subpart (1.3).
4. If it's a plaintext log → use the log filename (1.4).
5. Otherwise, PascalCase with hyphens between conceptual parts.

---

## 2. Substrate names

> **Terminology note.** What was previously called "container" / "container-class" / "container-instance" is now **substrate** / **substrate-class** / **substrate-instance**. See `docs/architecture.md` §Substrate axis for the conceptual model. This section covers the naming conventions only.

**Rule:** Every artifact's `substrate:` field must match a file under `substrates/<value>.md`. Validator enforces this.

**Format:** `windows-<kind>` — lowercase kebab-case, uniform across all 15.

| Substrate                 | Format family                                          | Example artifacts |
|---------------------------|--------------------------------------------------------|-------------------|
| `windows-binary-cache`    | proprietary binary cache files                         | Prefetch, Thumbcache variants, Notifications-wpnidm |
| `windows-disk-metadata`   | disk-region structures                                 | MBR, GPT, EFI-System-Partition |
| `windows-ess`             | ESE (Extensible Storage Engine) databases              | NTDS-dit, Windows-Search-edb, Cortana-CoreDb |
| `windows-evtx`            | Event Log (.evtx) records                              | Security-4624, Sysmon-1, System-41 |
| `windows-fat-metadata`    | FAT / exFAT filesystem structures                      | FAT32-Boot, exFAT-Boot |
| `windows-jumplist`        | Jump List .automaticDestinations / .customDestinations | AutomaticDestinations, CustomDestinations |
| `windows-lnk`             | Shell Link (.lnk) files                                | ShellLNK, BrowserDownload-LNK |
| `windows-ntfs-metadata`   | NTFS metafile structures                               | MFT, UsnJrnl, LogFile, Zone-Identifier-ADS |
| `windows-prefetch`        | Prefetch (.pf) files                                   | Prefetch |
| `windows-pst`             | Outlook PST / OST mail stores                          | Outlook-PST, Outlook-OST |
| `windows-recyclebin`      | $Recycle.Bin metadata                                  | RecycleBin-I-Metadata |
| `windows-registry-hive`   | registry hive files                                    | USBSTOR, Amcache, Run-Keys, etc. |
| `windows-sqlite`          | SQLite databases                                       | Chrome-History, Firefox-places, ActivitiesCache |
| `windows-text-log`        | plaintext log files                                    | firewall-log, setupapi-dev-log, CBS-log |
| `windows-thumbcache`      | Thumbcache database                                    | Thumbcache-Entry |

**Substrate-file metadata** (inside `substrates/<name>.md`) declares:

- `substrate-class:` — one of the 8 values: `Registry`, `Event Log`, `Text Log`, `Database`, `Filesystem Metadata`, `Filesystem Artifact`, `Disk Metadata`, `Application Cache`. Drives substrate-view coloring + hull clustering in the viewer.
- `kind:` — technical format enum: `binary-structured-file`, `plaintext-log`, `sqlite-database`, `ese-database`, `database-file`, `filesystem-metadata`, `disk-region`, `disk-substrate`.

Each substrate maps to exactly one substrate-class. Each substrate-class rolls up multiple substrates (e.g., Database covers `windows-sqlite` + `windows-ess`).

### 2.1 Adding a new substrate

Rare. Only needed when a fundamentally new format family appears (e.g., if we ever add macOS, substrate names would become `macos-<kind>`). Requires:

1. New file at `substrates/<name>.md` with `name:`, `kind:`, `substrate-class:`, and a `known-artifacts:` roster.
2. Adding the value to the `substrate` enum in `schema/artifact.schema.json`.
3. At least one artifact in `artifacts/<substrate-name>/` using it.

---

## 3. Links

The `link:` field on every artifact classifies the primary "story" the artifact tells. `link-secondary:` optionally marks a dual-story artifact. Both draw from the same 11-value enum.

Drives node coloring in the graph view. A value's meaning is the *primary aspect* the artifact contributes to an investigation, not its technical substrate.

### 3.1 The 11 values and what each means

| Link value              | Meaning in this project                                                         |
|-------------------------|---------------------------------------------------------------------------------|
| `application`           | Executable / software behavior — what ran, loaded, was registered. Includes Amcache application-side records, Prefetch, AppCompat, AppPaths, UserAssist. |
| `device`                | Hardware / peripheral / removable media attached to the host. USB family, Bluetooth, PnP enumeration. |
| `evasion`               | Anti-forensic primary — tamper tools, cleaners, log-clear evidence, hide-tracks artifacts. Use sparingly — many artifacts *reveal* tampering but are classified by what they normally track (e.g., Security-1102 is `security`, not `evasion`). |
| `file`                  | Filesystem-level evidence of file existence / path / metadata. MFT, UsnJrnl, LNK, ShellBags, Jump Lists. |
| `memory`                | RAM / process memory / swap / crash dump. Rare in this corpus; reserved for memory-image artifacts. |
| `network`               | Remote communication — connections, DNS, firewall, proxy, network-profile history. |
| `persistence`           | Something configured to execute / load / reappear later. Run keys, Services, Scheduled Tasks, WMI subscriptions, autologger providers, shell extensions. |
| `security`              | Authentication, access control, audit. Security.evtx most events, LSA artifacts, SAM, credential stores, firewall rules (config-side), ACL-related. |
| `system`                | General OS configuration / state. Time zone, environment, policy, cached settings that aren't specifically about host identity. |
| `system-state-identity` | Host-identity specifically — ComputerName, OS version, hardware identifiers, boot/shutdown records, crash state. Narrower visual clustering than `system`. |
| `user`                  | User-identity, session, account activity, profile history. Logons, per-user SIDs, profile ownership, interactive actions. |

### 3.2 Primary vs secondary — when to use `link-secondary:`

Use `link-secondary:` when the artifact straddles two stories with roughly comparable forensic weight. Don't use it just because an artifact has a minor second aspect — pick one and commit.

Common pairings:

| Primary `link:` | Secondary `link-secondary:` | Typical artifact |
|-----------------|------------------------------|------------------|
| `user` | `persistence` | Group-add events (Security-4728/4732), SID-history add — the user got persistent elevation |
| `user` | `application` | UserAssist, RunMRU — user-initiated execution records |
| `security` | `persistence` | FirewallRules, AutoLogon — security-configured and sticky |
| `device` | `application` | DeviceSetup events — device drivers (applications) plus device identity |
| `file` | `persistence` | ShellExt, AppCertDlls file-based persistence |
| `persistence` | `evasion` | Tamper-capable persistence (rarely used — `evasion` is itself rare) |

### 3.3 Choosing between `system` and `system-state-identity`

- `system-state-identity` = "what machine is this?" — ComputerName, OS-Version, TimeZoneInformation, CrashDump-MEMDMP, WindowsUpdate-log, CBS-log.
- `system` = "how is this machine configured?" — policy settings, environment, generic configuration data that doesn't uniquely identify the host.

If in doubt, default to `system`. Promote to `system-state-identity` only when the artifact's primary forensic use is answering *which machine / boot / version this is*.

### 3.4 The `evasion` link

Used exactly once in the corpus today. Reserve for artifacts whose primary purpose is tamper / clean-up / obstruction evidence — not for artifacts that *reveal* tampering (those stay classified by their normal story, with tamper significance documented in `anti-forensic.survival-signals:`).

---

## 4. Concept names

**Rule:** Concept files live at `concepts/<Name>.md` (was `forensic-data/`). The registry `schema/concepts.yaml` declares the authoritative concept set and role vocabulary.

**Format:** `PascalCase`, no hyphens or spaces. Examples: `UserSID`, `DeviceSerial`, `LogonSessionId`, `MFTEntryReference`, `ExecutablePath`, `VolumeGUID`.

Concept files declare their kind: `identifier` (values resolve uniquely to real entities) or `value-type` (values are reusable labels). See `docs/architecture.md` §Concepts for the structural role this plays.

### 4.1 Role names (inside a concept file's `roles:` list)

**Format:** `camelCase`, no hyphens. Describes how a field on an artifact is using the concept.

Examples: `actingUser`, `authenticatingUser`, `profileOwner`, `mountedVolume`, `accessedVolume`, `usbDevice`, `deviceIdentity`, `persistedService`, `scheduledTask`, `installedService`.

Role names are concept-specific; one role belongs to exactly one concept. Two different concepts may share a role name coincidentally (e.g., both TaskName and UserSID have `identitySubject`), but the `references-data: [{concept, role}]` binding disambiguates them.

---

## 5. Consistency notes for future authoring

1. **Don't mix naming conventions within a family.** If adding a new Amcache subkey, follow `Amcache-<Pascal>`. If adding a new text log, use the log filename.
2. **`substrate:` is not a free-form field.** Only the 15 enumerated values are valid. A new artifact that doesn't fit any existing substrate is a signal to either (a) reconsider whether it really needs to be a separate artifact, or (b) author a new substrate first.
3. **`link:` is exactly one value.** Not a list. If two stories are truly co-equal, that's what `link-secondary:` is for.
4. **`link:` is not taxonomy of the substrate.** A registry key tracking USB devices is `link: device`, not `link: system`. The link describes the *investigative story*, not the data-format family.
5. **Concepts and substrates never mix.** Concepts are the join-key vocabulary; substrates are the format families. Don't put substrate-flavored names in the concept registry or vice versa.
