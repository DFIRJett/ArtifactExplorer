# Candidate Source Repository Verification

Reconnaissance pass to verify accessibility, structure, and content for 10 candidate DFIR knowledge repositories before adding them to `schema/sources.yaml`.

Date: 2026-04-22. No project files were modified during this pass.

---

### 1. RegRipper plugin catalog

**Access:** public GitHub repo, clone or browse — `https://github.com/keydet89/RegRipper3.0` (698 stars, 148 forks, Apache-style license).
**Structure:** individual `.pl` files under `/plugins/<name>.pl`. Header comments in each plugin document the target hive, registry path, version, and forensic purpose. Many plugins have paired `_tln.pl` variants emitting timeline-normalized output.
**Spot-check:**
- `plugins/amcache.pl` — verified visible in directory listing.
- `plugins/usbstor.pl` — not seen in the truncated listing returned, but `bthport.pl`, `bam.pl`, `appcompatcache.pl`, `defender.pl`, `featureusage.pl` all confirmed present. Listing was truncated at ~100 of a larger set.
**Content fields available per plugin:** plugin name, target hive, registry path, version string, purpose text in header, category (e.g., USB, malware, software), output format (standard or _tln).
**Scope estimate:** 500+ plugins (search results and community forks consistently cite this range); the directory is truncated in web UI.
**Verdict:** usable. Broad coverage of registry artifacts. Cite by plugin filename + hive/key.

---

### 2. KAPE Targets/Modules

**Access:** public GitHub repo — `https://github.com/EricZimmerman/KapeFiles` (836 stars, 229 forks, 3,313 commits).
**Structure:** two top-level directories `/Targets/` (`.tkape`) and `/Modules/` (`.mkape`). Each file is a YAML-ish KAPE config specifying paths/globs to collect or a parser to run.
**Spot-check:** `Targets/` and `Modules/` subtree structure confirmed via repo browse; README describes format. Individual file contents not re-fetched but known structure (Description, Author, Version, Category, Paths/FileMasks).
**Content fields available per entry:** Description, Author, Version, Id, RecreateDirectories, Category, Targets/FileMasks (for targets) or BinaryName/CommandLine/ExportFormat (for modules).
**Scope estimate:** hundreds of .tkape and .mkape files each; categories include ApplicationLogs, Antivirus, BrowsingHistory, EvidenceOfExecution, RegistryHives, etc.
**Verdict:** usable. One entry per artifact-collection task — maps cleanly onto our artifact cards.

---

### 3. SANS FOR500 / FOR508 posters

**Access:** public, free after (sometimes) an email-gated download — `https://www.sans.org/posters/`. No paywall for the poster PDFs themselves.
**Structure:** each poster has its own landing page with title, date, and a PDF download link. No deep URL pattern exposed in listing; individual poster slugs are human-readable.
**Spot-check confirmed present in listing:**
- "Windows Forensic Analysis Playbook" (31 Mar 2026) — DFIR category.
- "Memory Forensics Cheat Sheet" (23 Oct 2025).
- "SIFT Cheat Sheet" (23 Oct 2025).
**Content fields available per poster:** title, category, publication date, download URL, short blurb. PDFs themselves have artifact tables (file path, parser tool, forensic value) — ideal for citation.
**Scope estimate:** ~5-10 DFIR-specific posters currently active; historical versions exist but SANS tends to retire older poster URLs when revised.
**Verdict:** usable but watch for URL rot. Prefer citing the current poster title; PDF is the load-bearing artifact, not the landing page.

---

### 4. Hexacorn persistence catalog — "Beyond good ol' Run key"

**Access:** public blog — `https://www.hexacorn.com/blog/`. No paywall.
**Structure:** URL pattern `https://www.hexacorn.com/blog/YYYY/MM/DD/beyond-good-ol-run-key-part-N/`. The publication date in the URL is unique per part and must be looked up (not derivable from N alone). A master index exists at `https://www.hexacorn.com/blog/2017/01/28/beyond-good-ol-run-key-all-parts/`.
**Spot-check:**
- Part 156 (2026/01/03) — confirmed recent; covers registry-based persistence via software purchase/download URLs.
- Part 2 (2012/09/16) — confirmed via search results; covers WinZip external-program paths as a persistence vector.
- Parts 62, 78, 86, 88, 101, 122, 125, 142, 155 all surfaced in search — URL pattern holds across the series.
**Content fields available per post:** title with part number, publication date, technical prose, registry paths / config locations, occasional PoC code, and back-references to earlier parts. Not highly structured but consistently formatted.
**Scope estimate:** 156+ parts as of January 2026. One of the single largest persistence-technique catalogs anywhere.
**Verdict:** highly usable. Recommend citing by part number + URL; use the "all parts" index page as discovery root.

---

### 5. 13Cubed YouTube channel

**Access:** public YouTube channel — `https://www.youtube.com/@13Cubed` (Richard Davis). Viewable without login. Channel ID `UCy8ntxFEudOCRZYT1f7ya9Q`. 37,500+ subscribers, 88+ videos at the time stats were last aggregated (third-party tracker; actual count now higher).
**Structure:** videos at `https://www.youtube.com/watch?v=<VIDEO_ID>`. No deep catalog schema; each video has a description (sometimes with linked references) and a transcript.
**Spot-check:** WebFetch returned only YouTube chrome — JS-rendered video list is not scrape-friendly via WebFetch. Channel existence confirmed via third-party stats (Social Blade, NoxInfluencer, SPEAKRJ) and DFIR Diva's curated list.
**Content fields available per video:** title, upload date, description text, transcript (if uploaded), video ID. No structured metadata useful for registry paths or event IDs.
**Scope estimate:** ~100 DFIR/IR tutorial videos covering Windows forensics, memory analysis, Volatility, KAPE, Velociraptor, etc.
**Verdict:** marginal for bibliographic citation. Use sparingly for specific episodes that cover a concrete artifact (e.g., "Prefetch Deep Dive"). Better treated as a companion resource in `training/resources.md` than as a bulk source in `schema/sources.yaml`.

---

### 6. ForensicArtifacts YAML repo

**Access:** public GitHub — `https://github.com/ForensicArtifacts/artifacts` (1.2k stars, 224 forks, Apache-2.0).
**Structure:** per-OS YAML files under `/artifacts/data/` (e.g., `windows.yaml`, `linux.yaml`, `macos.yaml`, `webbrowser.yaml`, etc.). Each file contains multiple artifact entries separated by `---`.
**Per-entry fields confirmed verbatim:** `name`, `doc`, `sources` (with nested `type` and `attributes` — e.g., REGISTRY_VALUE, REGISTRY_KEY, FILE, COMMAND, WMI), `supported_os`, `urls`, optional `aliases`, `conditions`, `labels`, `provides`.
**Spot-check — two entries confirmed verbatim:**
- `WindowsComputerName` — REGISTRY_VALUE `HKLM\System\CurrentControlSet\Control\ComputerName\ComputerName`, value `ComputerName`.
- `WindowsAutorun` — FILE type, path `%%environ_systemdrive%%\autorun.inf`.
**Scope estimate:** hundreds of artifacts across Windows/Linux/macOS plus browser and cloud subfiles. This is the canonical cross-tool schema (used by Plaso, Velociraptor, GRR).
**Verdict:** highly usable. Already referenced in user memory as a benchmark (though "not structured like ForensicArtifacts" is flagged — meaning our project's tier model is intentionally different). Cite per-artifact by `name:` field.

---

### 7. Harlan Carvey WindowsIR blog archive

**Access:** public Blogger site — `https://windowsir.blogspot.com/`. No login required.
**Structure:** URL pattern `https://windowsir.blogspot.com/YYYY/MM/<slug>.html`. Chronological archive with monthly pagination.
**Spot-check — post confirmed present and accessible:**
- "LNK Files" (2026-03-10) — discusses .lnk structure, Wietze's research, and metadata for threat intelligence / detection. Content rendered without login.
- "Devices" (2026-02), "Windows Defender Support Logs" (2026-01), "Questions I've Been Asked" (2026-01) — all visible in recent post list.
**Content fields available per post:** title, publication date, prose body, embedded links, comments. Not formally structured; citation requires reading the post for the specific registry path or tool recommendation.
**Scope estimate:** 15+ years, many hundreds of posts. Harlan still actively posting as of March 2026.
**Verdict:** usable for named-concept attribution (e.g., "Shellbags analysis — Carvey 2014"). High quality but inconsistent structure; best cited by specific URL rather than bulk-crawled.

---

### 8. Insider Threat Matrix articles + detections

**Access:** public — `https://insiderthreatmatrix.org/`. No login.
**Structure — CORRECTED from the candidate description:** the top-level taxonomy uses `AR1`-`AR5` for the five article categories (Motive, Means, Preparation, Infringement, Anti-Forensics). Sections use codes with letter-number form like `MT005`, `ME024`, `PR017`, `IF029`, `AF031`. URL patterns confirmed:
- Articles: `/articles/AR[1-5]`
- Sections: `/articles/AR[1-5]/sections/<CODE>`
- Detections: `/detections/DT<NNN>`
- Preventions: `/preventions/PV<NNN>` (inferred; not directly fetched, but DT/PV nav seen in page)
The "ART-N / DT-N / PV-N" pattern in the candidate brief is approximately right (section codes are prefixed by article-phase letters, not literally "ART-N"), and exists as hypothesized.
**Spot-check:**
- `/articles/AR3/sections/PR017` (Archive Data) — confirmed. Contains: ID, created/updated dates, applicable platforms (Windows/Linux/macOS), MITRE ATT&CK mapping (T1560 + sub-techniques), title, description, subsections list, Preventions section, Detections section.
- `/detections/DT001` (ConsoleHost_history.txt Created Timestamp Discrepancy) — confirmed.
- `/detections/DT055` (PowerShell Logging) — confirmed; includes registry paths and "three logging types" guidance.
- `/detections/DT128` (Microsoft Purview eDiscovery) — confirmed.
- Attempted `/articles/AR3/sections/PR017` direct WebFetch returned 404 on one form (`insiderthreatmatrix.org/articles/AR3/sections/PR017`) but resolved on another (same URL, slightly different trailing slug). Minor URL-shape ambiguity — worth confirming exact form before scripting.
**Content fields available per detection/section:** ID, title, description, applicable platforms, MITRE mapping, file/registry paths or log sources, example commands, cross-refs to related detections.
**Scope estimate:** ~150+ sections + ~130+ detections + preventions. Already referenced in user memory as a tier-3→tier-1 mapping source.
**Verdict:** highly usable. Confirmed structured, confirmed public. Good for behavior-anchor citations.

---

### 9. NIST NCP / StigViewer Windows STIG

**Access:** StigViewer.com is publicly accessible. NIST NCP (`https://ncp.nist.gov/`) wraps the same DoD STIG content with extra metadata. No login required for either.
**Structure:** Top-level list at `https://www.stigviewer.com/stigs` lists all STIGs. Individual STIG pages use dated slugs e.g., `/stig/microsoft_windows_11_security_technical_implementation_guide/2025-05-15/`. Individual controls *should* be at `.../finding/V-<NNNNNN>` but spot-check attempts returned 404 on both `/stig/microsoft_windows_11/2025-05-15/` and `/stig/microsoft_windows_11/` and `/stig/microsoft_windows_11_security_technical_implementation_guide/2025-05-15/finding/V-253257`.
**Spot-check — PARTIAL FAILURE:**
- STIG index page at `/stigs` loaded correctly and lists 7 Windows STIGs (Win10 v3, Win11 v2, Server 2019 v3, Server 2022 v2, DNS, Defender Firewall, PAW). Two distinct Win11 STIG entries appear: v2 Release 5 (2024-10-15, 5 findings — looks like an erratum release) and v2 full (2025-05-15, 258 findings).
- Individual per-STIG pages: WebFetch hit 404 on all tried URL forms. Either the slug pattern is different from the listing text or WebFetch is being blocked; manual browser check recommended.
**Content fields available (known from prior art, not re-verified today):** V-number, title, severity (Cat I/II/III), STIG ID, Rule ID, discussion, check text, fix text, CCI references, and (for applicable controls) registry path / key / value / expected data.
**Scope estimate:** ~250-300 findings per current Windows STIG; roughly 40-50% reference specific registry paths directly usable for artifact attribution.
**Verdict:** usable in principle; URL-routing requires manual confirmation before scripted citation. NIST NCP alternative should be tested if StigViewer URLs stay flaky. FLAG for follow-up.

---

### 10. Microsoft Security Auditing events umbrella

**Access:** public — `https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings`. No login required. Note: the canonical URL redirects into `/previous-versions/windows/it-pro/windows-10/...` — content is marked `is_archived: true` but remains live and authoritative for legacy/Win10 audit policies.
**Structure — CONFIRMED HUB PAGE:** This page IS the umbrella. It lists all advanced audit subcategories grouped by 10 top-level categories (Account Logon, Account Management, Detailed Tracking, DS Access, Logon/Logoff, Object Access, Policy Change, Privilege Use, System, Global Object Access Auditing). Each subcategory is a relative link to its own dedicated page.
**Spot-check — 5 example linked subcategory pages (relative links confirmed in hub):**
- `audit-process-creation` → Event IDs 4688/4689 (process creation/termination — load-bearing for execution-evidence artifacts)
- `audit-logon` → 4624/4625/4634 family
- `audit-registry` → 4657 (registry value modification) — directly relevant to artifact auditing
- `audit-file-system` → 4663 (object access)
- `audit-security-state-change` → 4608/4609
All ~60 subcategory child pages are linked from the hub.
**Content fields available per subcategory page:** subcategory name, default setting, recommended setting, generated event IDs with short descriptions, GPO path, and Group Policy reference. Each event-ID page itself then has deeper fields (XML template, field meanings).
**Scope estimate:** 10 categories × ~60 subcategories × multiple event IDs each → roughly 200+ distinct event IDs covered. Perfect 1:1 mapping for Windows event-log artifacts.
**Verdict:** highly usable. Structured, stable, and the authoritative source. Cite by subcategory slug + event ID.

---

## Summary Table

| # | Repo | Accessible? | Structure Known? | Spot-Check Passed? | Recommend-Add? |
|---|---|---|---|---|---|
| 1 | RegRipper plugins | Yes | Yes | Yes (~100 plugins visible) | Yes |
| 2 | KAPE Targets/Modules | Yes | Yes | Partial (structure confirmed, individual file content not re-fetched) | Yes |
| 3 | SANS posters | Yes | Partial (per-poster URLs not normalized) | Yes (3 posters confirmed listed) | Yes, with caveat |
| 4 | Hexacorn persistence series | Yes | Yes | Yes (parts 2, 62, 78, 86, 88, 101, 122, 125, 142, 155, 156 all surface) | Yes |
| 5 | 13Cubed YouTube | Yes (JS-rendered) | Partial (YouTube-native only) | Channel confirmed via third parties; WebFetch can't render video list | Marginal — keep in training/resources.md |
| 6 | ForensicArtifacts YAML | Yes | Yes | Yes (2 entries verbatim) | Yes |
| 7 | WindowsIR blog | Yes | Yes | Yes (LNK Files post confirmed) | Yes |
| 8 | Insider Threat Matrix | Yes | Yes (CORRECTED: AR1-5 + code-prefixed sections, not literal ART-N) | Yes (PR017 + DT001, DT055, DT128) | Yes |
| 9 | StigViewer / NIST NCP | Index page yes; per-control pages FAILED on WebFetch | Partial | FAILED — all per-finding URL attempts 404'd | Flag for manual URL confirmation before adding |
| 10 | Microsoft audit events hub | Yes | Yes | Yes — hub page lists all 10 categories and ~60 subcategory links | Yes |

## Recommended order for adding to registry (highest-payoff-first)

1. **Microsoft audit events hub** (#10) — structured, authoritative, one-citation-per-event-ID maps directly to Windows event-log artifacts. Biggest-payoff-per-unit-effort.
2. **ForensicArtifacts YAML repo** (#6) — schema-native; pre-normalized one-entry-per-artifact. Easiest mechanical ingest.
3. **RegRipper plugin catalog** (#1) — plugin-per-registry-artifact, stable naming; covers a huge registry swath.
4. **Hexacorn persistence series** (#4) — unique depth on persistence; use "all parts" index as discovery root.
5. **Insider Threat Matrix** (#8) — already called out in user memory as a canonical reference; tier-3 → tier-1 mapping is directly aligned with the project's tier model.
6. **KAPE Targets/Modules** (#2) — one target/module per artifact-collection task; good structure but overlaps heavily with ForensicArtifacts.
7. **SANS posters** (#3) — small N but high prestige; worth having for big-picture citation.
8. **WindowsIR blog** (#7) — high value but unstructured; cite per-post on demand, don't bulk-crawl.
9. **StigViewer / NIST NCP** (#9) — HOLD pending URL pattern clarification.
10. **13Cubed YouTube** (#5) — don't add to schema/sources.yaml; keep in training/resources.md.

## Flagged problems

- **StigViewer per-finding URLs (#9):** multiple URL-form attempts (`/stig/microsoft_windows_11/`, `/stig/microsoft_windows_11/2025-02-25/`, `/stig/microsoft_windows_11_security_technical_implementation_guide/2025-05-15/finding/V-253257`) all returned 404 on WebFetch. Either WebFetch is being rate-limited/blocked, or the actual slug differs from what the index page shows. A manual browser visit or direct NIST NCP checklist download is needed before bulk ingest.
- **ForensicArtifacts readthedocs (#6):** format-specification docs returned 403 on WebFetch — suspected UA/rate-limit on readthedocs. Schema fields ultimately confirmed by reading `windows.yaml` directly; not a blocker.
- **13Cubed (#5):** JS-rendered video lists are not WebFetch-friendly. Citations possible per-video-URL but not at bulk.
- **Hexacorn individual post URLs (#4):** the `YYYY/MM/DD` segment is unique per part and must be looked up, not guessed. The "all parts" master index at `/blog/2017/01/28/beyond-good-ol-run-key-all-parts/` is the only reliable discovery surface; several speculative date-guess URLs (parts 56, 63, early parts) 404'd. When ingesting, scrape the index page rather than constructing URLs.
- **SANS posters (#3):** poster URLs change when SANS revises a poster; prior-year URLs go dead. Citation should use the current poster title as the load-bearing identifier, with URL as a best-effort pointer.
- **Insider Threat Matrix URL form (#8):** one WebFetch of `/articles/AR3/sections/PR017` returned 404 while a very similar fetch resolved. The code-prefix format (PR/MT/ME/IF/AF) may or may not be uppercase-sensitive, and trailing-slash behavior is inconsistent. Minor — worth a quick URL-normalization check before scripting.
