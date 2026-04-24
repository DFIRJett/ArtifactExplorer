---
name: color-classification
version: 0.2
purpose: |
  Three-dimensional visual encoding for the forensic artifact graph.
  Separates (1) where an artifact lives from (2) what it links together
  from (3) temporal context.

encoding-dimensions:
  - name: spatial-clustering
    drives: node position (force-layout attraction)
    encodes: substrate (registry, eventlog, sqlite, plist, filesystem, memory, cloud-api)
    rationale: Co-locates artifacts by where they physically live. All registry artifacts cluster; all EVTX cluster; etc. Produces legible "neighborhoods" at a glance and makes cross-container relationships visually obvious.
  - name: color
    drives: node color
    encodes: primary entity link (user / device / system / network / file / application / security)
    rationale: Encodes what the artifact most directly reveals about the investigation. Matches the investigator's mental model ("I need a user-scope artifact and a device-scope artifact to close this attribution").
  - name: timestamp-side-state
    drives: deferred rendering — NOT primary edges; available as overlay/query layer
    encodes: every artifact's timestamp fields are harvested into a corpus-wide temporal-index; any future time-scrub UI can light up artifacts within a user-specified window
    rationale: Timestamps are in virtually every artifact. Rendering time-correlation as primary edges produces a fully-connected mush with no information content. Keep them modeled, keep them queryable, keep them out of the default view.

primary-links:
  - id: user
    color: "#377EB8"
    name: User
    description: Identifies or is scoped to a user principal (SID, username, profile).
    examples: [SAM, ProfileList, NTUSER-artifacts-generally, jump-lists, UserAssist, Security-4624-target-user]
  - id: device
    color: "#984EA3"
    name: Device
    description: Identifies physical hardware — USB, peripherals, mobile, IoT endpoints.
    examples: [USBSTOR, MountedDevices, MountPoints2, WindowsPortableDevices, Bluetooth-Devices, Partition-Diagnostic-1006]
  - id: system
    color: "#4DAF4A"
    name: System
    description: Machine-level state, configuration, OS activity.
    examples: [Policy-registry, installed-software, services, scheduled-tasks, WMI-subscriptions, timezone-NTP-state, environment-variables]
  - id: network
    color: "#FF7F00"
    name: Network
    description: Network communication, connection state, remote endpoints.
    examples: [DNS-cache, netsh-state, proxy-logs, firewall-log, SRUM-network, NetworkList-profiles, browser-connection-history]
  - id: file
    color: "#E41A1C"
    name: File
    description: File or folder access, content, lifecycle on the filesystem.
    examples: [MFT, UsnJrnl, shellbags, LNK-Recent, thumbcache, RecentDocs, JumpLists, OfficeMRU, Zone-Identifier]
  - id: application
    color: "#F781BF"
    name: Application
    description: Application-level state — DBs, config, per-app artifacts.
    examples: [browser-SQLite, PST-OST, Teams-DB, Slack-DB, iMessage-DB, chat-databases, Amcache, BAM]
  - id: security
    color: "#8DD3C7"
    name: Security Tooling
    description: Security/detection/audit telemetry and verdicts.
    examples: [Defender-MPLog, Defender-quarantine, CrowdStrike-detections, YARA-hits, sandbox-reports, Sigma-matches]
  - id: persistence
    color: "#FFD700"
    name: Persistence
    description: Autorun / scheduled execution / installed-code persistence anchors.
    examples: [Run-keys, AutoLogon, Services, Scheduled-Tasks, AppInit-DLLs, AppCertDlls, ImageFileExecutionOptions, WMI-Subscriptions, COM-HijackKeys]
  - id: memory
    color: "#9B5DE5"
    name: Memory Capture
    description: Volatile-state captures — dump files and memory-capture stores.
    examples: [Hiberfil, Pagefile, Swapfile, CrashDump-MEMDMP]
  - id: evasion
    color: "#00F5D4"
    name: Anti-Forensic Evasion
    description: Artifacts whose authorship is primarily anti-forensic — log wipes, tamper state, coverage manipulation.
    examples: [Security-1102, System-104, Audit-Policy-tamper-events]
  - id: system-state-identity
    color: "#17A398"
    name: System Identity State
    description: Machine-level identity and configuration snapshots — what this host is, how it's named, what OS runs on it.
    examples: [ComputerName, OS-Version, Registered-Owner, TimeZoneInformation, BCD-Store]

spatial-clusters:
  description: |
    Container-class drives a mild clustering force. Same-class artifacts attract
    weakly; different-class artifacts don't. Produces visible neighborhoods
    without hard walls.
  classes:
    - id: windows-registry-hive
      label: Windows Registry
    - id: windows-evtx
      label: Windows Event Log
    - id: windows-filesystem
      label: Windows Filesystem Metadata
    - id: windows-prefetch
      label: Windows Prefetch
    - id: sqlite-database
      label: SQLite DB
    - id: plist-binary
      label: Binary plist
    - id: plist-xml
      label: XML plist
    - id: macos-filesystem-events
      label: macOS fseventsd
    - id: memory-structure
      label: Memory
    - id: cloud-api-response
      label: Cloud API
    - id: mobile-app-sandbox
      label: Mobile app container

timestamp-side-state:
  scope: |
    Every field with kind: timestamp is harvested into a corpus-wide
    temporal-index. This index is written to viewer/data.json as a separate
    top-level `temporal` block alongside the primary graph.
  rendering-policy:
    primary-graph: timestamp-to-timestamp correlations are NOT drawn as edges
    overlay-mode: reserved for future time-scrub UI (drop a time window, highlight co-occurring artifacts)
    query-access: available via viewer data; callable by any future tool

tags:
  - id: volatile
    meaning: memory-only; lost on reboot
  - id: tamper-hard
    meaning: kernel-signed, cryptographic, or covered by enabled audit policy
  - id: tamper-easy
    meaning: user-writable without elevation; no audit by default
  - id: per-user
    meaning: scoped to a single user profile
  - id: timestamp-carrying
    meaning: carries at least one explicit per-entry timestamp field
  - id: recency-ordered
    meaning: recency conveyed via MRU list ordering (position = rank) without per-entry timestamps; RunMRU, RecentDocs, TypedPaths are examples
  - id: recency-presence
    meaning: an entry's existence implies recent access; timestamps may be key-level only (no per-entry time); ShellBags is the canonical example
  - id: anti-forensic-resistant
    meaning: empirically survives common cleaner tooling
  - id: cross-platform
    meaning: same investigative concept applies across OSes

node-sizing:
  artifact-formula: "base + (arm_count * 2) + (outgoing_pivot_count * 3) + log2(1 + field_count)"
  rationale: External connectivity drives visual prominence — bridge artifacts dominate, leaf artifacts recede. Internal field count contributes logarithmically so dense artifacts don't swamp the graph.
  base: 4

edge-types:
  - id: arm-of
    visual: thin gray line
    directional: artifact-to-arm
    meaning: an arm (pivoting field) belongs to its parent artifact
  - id: pivot
    visual: medium line, colored by pivot semantic
    directional: undirected (arm to arm across artifacts)
    meaning: two fields on different artifacts reference the same forensic entity (same serial, same GUID, same label)
  - id: ghost-pivot
    visual: dashed line to a gray "ghost" node
    directional: arm to unwritten artifact
    meaning: field declares a pivot to an artifact not yet written in the repo — priority target for authoring
  - id: anti-forensic-survival
    visual: dashed coral line
    directional: undirected
    meaning: this artifact empirically survives cleaner tooling that removed that one
---

# Color Classification — v0.2

## What changed from v0.1

**v0.1** conflated "what investigative question this artifact answers" (execution / authentication / file-access / …) with one color dimension. That made color the only visual encoding and forced single-artifact-per-category reduction.

**v0.2** splits this into three orthogonal dimensions. Spatial clustering answers *where does this live*. Color answers *what entity does this link to*. Timestamp side-state answers *when did this happen* — without cluttering the primary graph.

## Why these specific dimensions

The artifact corpus naturally varies along exactly these three axes. Two artifacts can live in the same place but link to different entities (USBSTOR is device, SAM is user — both in registry). They can link to the same entity from different places (USBSTOR in registry, WPD in registry but SOFTWARE hive, Partition/Diagnostic in EVTX — all device-linked). Every artifact has timestamps, so time is the pervasive background signal.

Encoding each axis in a different visual dimension gives the graph three legible layers instead of one crowded one.

## Rules for classifying a new artifact

1. **Substrate (spatial):** pick from the `spatial-clusters.classes` list. If the artifact's container isn't listed, add a new substrate entry — don't stretch an existing one.
2. **Primary link (color):** answer the question *"what entity does this artifact most directly tell me about?"*. If the answer is "both user AND device equally" — pick whichever is the narrower scope (per-user artifacts are user-primary; machine-wide are device/system-primary). The non-primary entity becomes a tag.
3. **Tags:** add as many as apply. Tags are cross-cutting qualifiers (volatile, per-user, tamper-hard, etc.).
4. **Timestamp harvesting:** automatic — any field with `kind: timestamp` feeds the temporal-index. No manual curation.

## Known gaps and iteration plan

- **"Communication" dropped** as a primary link. Email, chat, SMS are all *application-scope* artifacts that happen to be about message exchange. Folded into `application`. Revisit if application becomes too crowded.
- **"Cloud" dropped** as a primary link. A cloud-sync artifact on the local device is a `file` or `application` artifact depending on what it stores; a cloud API response is its own substrate and primary-links to whatever entity the response describes.
- **"Malware-specific" narrowed to `security`** — covers detection telemetry generally.
- **`application` and `security` are the most likely to be trimmed** if the seven-color set feels busy. Revisit after the corpus grows past ~50 artifacts.
