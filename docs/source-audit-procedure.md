# Source audit procedure

A repeatable function for analyzing and validating a source entry in `schema/sources.yaml`. Establishes what a source actually covers, discovers related content on the same site, and produces a structured audit report.

**When to run:** when a source has `coverage.artifacts` populated but is cited by artifacts not in that list (validator warnings), OR when adding a new source, OR as part of the priority-driven crawl methodology documented in `tools/crawl_state.yaml`.

**Principle:** one audit pass per source should extract *everything* the site offers in relation to our corpus — focal page, navigation breadth, sitemap, cross-references — not just the one page that triggered the audit. Efficiency depends on leaving no structural context unused.

---

## Input contract

Given:
- `source-id` from `schema/sources.yaml`
- Its `url` field
- Its current `coverage.artifacts` list (may be empty)
- Optionally: a list of "flagged" artifacts — artifacts currently citing the source but not in its coverage list

---

## Output contract

Produce a per-source audit record conforming to this shape:

```yaml
source-id: <id>
url: <url>
fetch-status: ok | dead | paywalled | jsonly | redirected-to <url>
current-coverage-artifacts: [<from registry>]
citing-artifacts-flagged: [<from input>]           # optional

# Phase 1 — focal verification
content-analysis:
  genuinely-covers: [<subset of flagged/existing that page actually covers>]
  not-covered: [<subset that page does NOT cover>]
  reasoning: "<one-paragraph explanation>"

# Phase 2 — structural discovery
structural-elements:
  navigation-links: [<URLs found in nav / sidebar / menu>]
  related-content: [<"see also" / "related posts" URLs>]
  breadcrumbs: [<hierarchy from site root to this page>]
  external-references: [<off-site URLs cited by this page — candidate new sources>]

# Phase 3 — sitemap discovery
sitemap:
  url: <sitemap URL or null>
  discovery-method: /sitemap.xml | /robots.txt | head-link | manual | not-found
  entry-count: <integer or null>

# Phase 4 — site: search for major-category coverage
site-search-results:
  probes-run: <count>
  hits-by-probe:
    USBSTOR: [<URL1>, <URL2>] | []
    MountedDevices: [...]
    Amcache: [...]
    Prefetch: [...]
    ShimCache: [...]
    ShellBags: [...]
    Recent-LNK: [...]
    MFT: [...]
    UsnJrnl: [...]
    Security-4624: [...]
    Security-4688: [...]
    Sysmon: [...]
    DPAPI: [...]
    LSA-Secrets: [...]
    Chrome-History: [...]

# Synthesis
proposed-action: retract-citations | expand-coverage | mixed | no-change
expand-coverage-to: [<artifact names to add>]
retract-citations-from: [<artifact files whose provenance should strip this source-id>]
discovered-artifacts-not-in-coverage: [<our-corpus artifacts the site covers but we didn't list>]
new-source-leads: [<external URLs the page cited worth registering as sources>]
notes: |
  Freeform observations. Site-specific patterns. Pitfalls.
```

---

## Phase 1 — Focal verification (MANDATORY)

1. WebFetch the source URL.
2. If unreachable (404/dead/paywall/JS-only), record `fetch-status` and short-circuit: produce `proposed-action: retract-citations`, all flagged artifacts in `retract-citations-from`, empty structural elements. Move on.
3. Parse the page content. For every artifact in the corpus that appears on the page in any form, classify the mention into one of three tiers:
   - **`dedicated-coverage`** — the page is *about* this artifact. A dedicated section / chapter / per-event page / byte-layout spec. The artifact is the focal subject.
   - **`substantive-mention`** — the artifact is discussed in depth as a subsection or as part of a multi-artifact umbrella (example: aboutdfir USB-devices page with a multi-paragraph MountedDevices section among its USB-family coverage).
   - **`passing-mention`** — the artifact is name-dropped, alluded to, cross-referenced, or mentioned in a single sentence. Not substantively documented by this page.

   Detection heuristics (in order of strength):
   - Artifact name appears in a section heading → likely dedicated/substantive
   - Registry path / file path / event ID matching the artifact appears with field-level detail → dedicated/substantive
   - Artifact name mentioned in prose only, without field detail → passing
   - Artifact name appears in a "see also" / "related" list → passing

4. Record `content-analysis`:
   ```yaml
   content-analysis:
     dedicated-coverage: [<artifacts the page is focal on>]
     substantive-mention: [<artifacts discussed as subsection>]
     passing-mention: [<artifacts name-dropped only>]
     not-covered: [<artifacts claimed-citing but NOT in page at all>]
     reasoning: "<one paragraph>"
   ```

**Why tier-split matters:**
- `dedicated-coverage` + `substantive-mention` → `coverage.artifacts` (authoritative attribution)
- `passing-mention` → `coverage.mentions` (forensic-linkage signal only, NOT attribution)
- `not-covered` → retract the citation

### Phase 1 supplement — Body-content cross-check (BEST-EFFORT)

For any source classified as `dedicated-coverage` or `substantive-mention` on an artifact, opportunistically cross-check the corpus entry's body fields against what the source actually says. No validator rule is enforced from this — the only field-specific source requirement remains `artifact.exit-node.sources` (per M-2 design). This is **advisory** cross-checking, to catch drift between corpus content and the literature we're auditing against.

**Skip when:**
- Source is narrow-scope (single event-ID page / single CVE) — low yield
- Page content doesn't cover structural detail (index-catalog umbrella with no fielded data)
- Source is not `dedicated-coverage` or `substantive-mention`

**What to cross-check (when signal is available on the page):**

| Datatype | Fields worth cross-checking |
|---|---|
| **artifact** | `location` (path / hive / key) · `fields[].location` · `fields[].encoding` · `fields[].type` · `substrate` · `substrate-instance` |
| **substrate** (when auditing a format-spec) | `format.magic` · `format.endianness` · `format.version` · `structure.*` · declared `parsers[]` |
| **concept** (when auditing a spec that defines it) | `canonical-format` · declared `roles[]` |
| **convergence** | per-artifact `notes[]` — does the source's description support the claim? |

**Viewer-critical fields (authored, reshape the graph if changed):**

These fields drive D3 rendering in `viewer/index.html` — color cluster, hull grouping, filter state, node kind, search. Any divergence touching these is **automatically MAJOR** regardless of other context, because a silent update would visibly alter the graph without the user seeing it.

| Entity | Viewer-critical authored fields |
|---|---|
| artifact | `kind` · `link` · `link-secondary` · `substrate` · `substrate-class` · `substrate-instance` · `tags` · `volatility` · `interaction-required` · `exit-node.is-terminus` · `aliases` |
| substrate | `kind` · `substrate-class` · `name` (cascades — filename rename) |
| concept | `kind` (identifier vs value-type changes rendering) · `link-affinity` · `aliases` |
| convergence | `exit-node` (drives the exit-node hull/marker) |

**Computed fields** (not editable — derived by `tools/build-graph.py` and emitted to `data.json`): `ceiling-max`, `color`/`color-secondary`, `concept-ref-count`, `edge-weights`, `source-count`, `field-count`, `is-exit-node`, `verified`, `mid-verified`, `size`, `cross-verifies-with`, `resolves-identity-via`, `is-bridge`. Audits never touch these directly; they re-derive on next build.

**Divergence classification — MAJOR vs minor:**

| Tier | Examples | Action |
|------|----------|--------|
| **major** | Any disagreement on a **viewer-critical field** above · different registry path / file path · different encoding (UTF-16LE vs ASCII) · different magic bytes / format version · different event-ID meaning | **Do not accept any auto-apply for this artifact/substrate.** Seed completes but the entity does NOT advance to audit-verified. Enter into `back_propagation.artifact_manual_review_queue` (or `substrate_manual_review_queue`) with structured divergence record. Human triage required. |
| **minor** | Source uses different phrasing for same concept · Source omits a field we have (or vice versa) · Source orders fields differently · Prose wording variance without meaning change · Body-content field (location-path / fields[].note / observations[].note) differs in non-structural ways | Log in `back_propagation.body_content_divergences` as informational. Audit proceeds normally — auto-apply still happens for source-side field-updates and coverage changes. Editorial pass later. |

**Rule of thumb:** if a change would make the viewer render the graph differently without the user pressing rebuild, it's MAJOR. If the change only affects prose inside the inspector/detail panel, it's minor.

**Output — Phase 5 appends a `body-content-checks` block per source:**

```yaml
body-content-checks:
  artifacts:
    <artifact-name>:
      location:         { corpus: "...", source: "...", status: match | minor-diff | MAJOR-CONFLICT, note: "..." }
      fields-reviewed:  [<field-name>, ...]
      divergences:
        - field: <field-name>
          claim-in-corpus: "..."
          claim-in-source: "..."
          severity: minor | major
          note: "..."
  substrates:
    <substrate-name>:
      format-checked:   [magic, endianness, version, ...]
      divergences:      [...]
  # "unverifiable" = page didn't carry the structural detail to cross-check
  unverifiable-fields:  [<field-name>, ...]
```

**Manual-review queue records (on MAJOR conflict):**

```yaml
artifact_manual_review_queue:
  - artifact: <name>
    source-triggering: <source-id>
    conflict-field: <field-name>
    corpus-claim: "..."
    source-claim: "..."
    audit-note: "..."
    surfaced-by: "seed-NN"
    status: pending-manual-review
```

**Guard-rail:** the audit does NOT rewrite artifact body fields from source content, ever. Even on a minor divergence where the source seems authoritative, the corpus entry stays as-is until editorial review. Body-content verification is a *surface-mismatch detector*, not an auto-correction mechanism.

**Budget:** typically +3–5 min per dedicated-coverage source; 0 for narrow or non-structural sources. Agents cap at ~5 divergences per seed and queue the rest to avoid rabbit-holing.

---

## Phase 2 — Structural discovery (MANDATORY)

From the same page fetch:

1. **Navigation**: extract every link visible in site navigation (top nav, sidebar menu, hamburger menu, dropdown).
2. **Related content**: extract every link in "Related posts", "See also", "Further reading", "Up next" sections.
3. **Breadcrumbs**: extract the hierarchical path from site root to this page.
4. **External references**: extract every off-site link the page content cites (but not every incidental link — focus on citations, footnotes, "references" section, inline source-links).

Record all under `structural-elements`.

**Why this matters:** navigation reveals what else this site offers. If the focal page covers USBSTOR but the sidebar lists 10 other registry forensics pages, those 10 pages probably cover artifacts we should register.

---

## Phase 3 — Sitemap discovery (MANDATORY, best-effort)

Attempt the following in order; record the first that succeeds:

1. `curl -sI <domain>/sitemap.xml` — check HTTP 200
2. `curl -s <domain>/robots.txt` — grep for `Sitemap:` line
3. Scan the focal page's `<head>` for `<link rel="sitemap">`
4. Try common alternatives: `/sitemap_index.xml`, `/archive`, `/all-posts`, `/index`, `/contents`
5. If all fail, record `not-found`.

If found, fetch it and record the entry count (number of URLs listed).

**Why this matters:** a sitemap is a definitive enumeration of the site's offerings. Replaces speculative "maybe this site has more content" with "here are all 85 posts/pages."

---

## Phase 4 — Site: search for major-category coverage (MANDATORY when WebSearch available)

For each probe term in the canonical list below, run `site:<domain> <probe-term>` via WebSearch. Record hit URLs per probe.

**Canonical probe list (15 terms across 9 DFIR categories):**

| Category | Probes |
|---|---|
| USB / removable media | `USBSTOR`, `MountedDevices` |
| Registry persistence | `Run-Keys` (also try "Run key") |
| Execution evidence | `Amcache`, `Prefetch`, `ShimCache` |
| Shell / user activity | `ShellBags`, `Recent-LNK` (also try "LNK files") |
| Filesystem metadata | `MFT`, `UsnJrnl` (also try "$MFT", "UsnJrnl") |
| Event log (Security) | `Security 4624`, `Security 4688` |
| Event log (other) | `Sysmon` |
| Credentials | `DPAPI`, `LSA-Secrets` (also try "LSA Secrets") |
| Browser | `Chrome-History` (also try "Chrome history SQLite") |

**Stopping rule:** per category, stop probing if 2+ hits found. A probe that returns 0 hits for all terms in its category means the site doesn't cover that category.

**Purpose:** discovery, not verification. Site: search reveals categories of artifacts the site covers that we might miss by reading only the focal page.

---

## Phase 5 — Synthesis + full field updates

Phase 5 emits TWO blocks: actions to apply, and source-entry field updates.

### Actions

- **`proposed-action`**:
  - `retract-citations` — focal verification confirmed the citing-flagged artifacts are NOT covered
  - `expand-coverage` — focal verification OR Phase 4 confirmed the page covers artifacts we didn't list
  - `mixed` — some of both
  - `no-change` — current coverage is correct; all citations valid

- **`expand-coverage-to`**: union of (Phase 1 dedicated-coverage ∪ substantive-mention) ∪ (Phase 4 hits mapped to our artifact names)
- **`retract-citations-from`**: Phase 1 not-covered
- **`discovered-artifacts-not-in-coverage`**: artifacts appearing in Phase 2 or Phase 4 that ARE in our corpus but AREN'T in the source's current or proposed coverage list.
- **`new-source-leads`**: external-reference URLs from Phase 2 that look like new sources worth registering.

### Field updates (applied to the source entry)

Every audit emits a `field-updates` block, regardless of whether any values actually change. Missing-from-block = no update. Explicit-in-block = apply.

```yaml
field-updates:
  url: <corrected URL if redirect, dead, or umbrella→specific found; otherwise omit>
  title: <if audit found canonical title differs; otherwise omit>
  author: <corrections>
  year: <corrections from site's publish date>
  publisher: <corrections>
  note: "<verification findings — what the audit learned about this source>"
  access-guide: |
    <populated/refined from Phase 2 structural observations; especially
    for kind: index-catalog sources. Should include navigation recipe,
    per-page fields, pitfalls.>
  kind: <reconsidered if evidence suggests different classification>
  authority: <reconsidered>
  sitemap-url: <from Phase 3 discovery>
  coverage.mentions: [<artifacts from Phase 1 passing-mention tier>]
  coverage.substrates: [<reconsidered if audit reveals different scope>]
  apa: <regenerated when any of author/year/title/publisher/url changes>
```

**Rule:** every field the audit has information about SHOULD produce a field-updates entry, even if the update is "unchanged — re-verified." This forces explicit verification rather than silent omission.

### Reclassifying non-focal sources encountered mid-audit

The `audits:` array is NOT restricted to the focal source's current citation set. When an audit encounters evidence about **any other source already in `schema/sources.yaml`** that would change that source's classification — `kind` was wrong, `authority` needs promotion/demotion, `coverage.substrates` / `coverage.artifacts` should expand/contract, note field needs update — the agent should emit an **additional `audits:` entry** for that non-focal source with a complete Phase 5 `field-updates` block. The apply-step applies every entry in the array identically regardless of whether it was the focal source.

**Examples triggering a secondary audit entry:**
- Current audit reads source X which discusses source Y's scope with greater authority than the corpus currently records → emit Y reclassification entry.
- Focal audit reveals source Z (already registered) covers artifacts beyond its declared `coverage.artifacts` → emit Z coverage-expansion entry.
- Agent reads a methodology source during Phase 2 structural-discovery and finds it references existing registry source W with context implying W's kind is mis-classified → emit W kind-reconsideration entry.

**Do NOT emit reclassification entries for sources not yet in the registry** — those go through Phase 6 `related-sources` as new-source-leads. This rule specifically handles the gap between "new source discovered" (Phase 6) and "focal source re-classified" (Phase 5 field-updates on the focal) — *existing non-focal sources whose classifications need updating*.

**Cap:** one or two secondary reclassification entries per seed is reasonable. More than that and the audit has drifted from its focal subject; queue the rest to `back_propagation` for a dedicated re-audit pass later.

### Back-propagation (discoveries that should update other data types)

Audit findings often surface facts that belong on data types the audit isn't directly editing — a new concept needed, a convergence participant to add, an unwritten sibling artifact, a field discrepancy on the focal artifact, a substrate-level cross-cutting issue. Without a structured capture mechanism, these decay.

Every audit emits a `back-propagation` block:

```yaml
back-propagation:
  concept-candidates:
    - {name: <Concept>, kind: identifier|value-type, rationale: "..."}
  convergence-participant-additions:
    - {convergence: <NAME>, artifact: <artifact>, proposition: <PROP>, rationale: "..."}
  substrate-unwritten-additions:
    - {substrate: <name>, artifacts: [<name>...], rationale: "..."}
  cross-artifact-references:
    - {from: <artifact>, to: <artifact>, kind: alternative-to|alias|version-of, rationale: "..."}
  field-discrepancy-flags:
    - {artifact: <name>, field: <field>, issue: "...", status: pending-verify}
  artifact-refactor-items:
    - {target: <path>, issue: "...", priority: low|normal|high}
```

The apply-script accumulates each category into `crawl_state.yaml` under `back_propagation.*` queues. These queues drive subsequent **editorial authorship passes** — body-content changes are high-judgment and NOT auto-applied.

### Tier-applicability (substrate + tier 2/3 reach)

Sources aren't only applicable to the tier-1 artifacts they cite. An audit must also capture whether the source belongs on:
- the **substrate** provenance (format spec, parser catalog, umbrella guide across a substrate family), and
- the **tier 2/3** database (information the source contains about convergences or scenarios that the artifact-level coverage doesn't capture).

Every audit emits a `tier-applicability` block:

```yaml
tier-applicability:
  substrate-level:
    applies: <true|false>
    substrates: [<substrate names, if applies>]
    rationale: "<why this is substrate-level — e.g. format spec, parser docs, multi-artifact umbrella>"
  tier-2-applies-to:
    - <convergence name>    # e.g. DEVICE_CONNECTED, USED, EXECUTED
  tier-2-broadly: <true|false>   # true if applies across many convergences generically (textbook / methodology)
  tier-3-applies-to:
    - <scenario slug>              # e.g. departing-employee-usb-exfil
  tier-3-broadly: <true|false>   # true for foundational sources that apply to every scenario (e.g. Casey C-scale)
  note: "<short rationale>"
```

The apply-script accumulates these into `crawl_state.yaml` under `tier_23_source_database` — NOT auto-applied to convergence/scenario provenance, because attribution at those tiers requires a dedicated editorial pass once the database has grown enough to be representative.

Classification heuristics:
- **format-spec / standards-doc / textbook** covering a substrate → `substrate-level.applies: true`
- **index-catalog / tool-docs** with >5 artifacts in a single substrate → `substrate-level.applies: true` (umbrella)
- **scenario case-study** (e.g. TheDFIRReport, Mandiant scenario posts) → `tier-3-applies-to` the matching scenario slug
- **foundational methodology** (Casey, Carvey, Carrier) → `tier-3-broadly: true`
- **convergence-cross-referencing** (source that explicitly reasons about the convergence — e.g. USB-chain artifact that cites 5 siblings) → `tier-2-applies-to: [<convergence names>]`

---

## Phase 6 — Discovery extraction (BEST-EFFORT, mandatory on dedicated-coverage)

Phase 5 writes what the audit DECIDES. Phase 6 captures what the audit DISCOVERS — value the source carries about the corpus beyond the focal artifact. Skipping this throws away most of the per-audit information yield.

Mandatory when any source in the audit is `dedicated-coverage` or `substantive-mention`. Optional otherwise.

```yaml
discovery-extraction:
  # 1. Related-source leads classified by kind (Phase 2 external-references promoted
  #    with classification, not just URL). Each entry drains to new_source_leads with
  #    shape {lead, url?, seen-in, kind?, authority-inferred?, relevance, status: candidate}.
  related-sources:
    - lead: "..."
      url: "..."
      seen-in: "<section or URL fragment>"
      kind: format-spec | analyst-writeup | textbook | case-study | standards-doc | tool-docs | peer-reviewed-paper | index-catalog
      authority-inferred: primary | secondary | tertiary
      relevance: "why this source would be worth auditing"

  # 2. Repository candidates — sites/indices/journals the source hints at that would
  #    justify a DEDICATED multi-artifact crawl, not just per-page registration.
  #    Examples: a new ITM site, a university course archive, a tool family's docs tree.
  repository-candidates:
    - name: "<short identifier>"
      url: "..."
      evidence: "<how the focal source revealed this repo>"
      estimated-artifact-coverage: "<rough count or list of implied artifacts>"

  # 3. Substrate field-enrichment candidates (when the source is a format-spec).
  #    Captures structural details the corpus substrate entry doesn't yet carry.
  substrate-field-enrichment:
    - substrate: <name>
      field: format.magic | format.endianness | format.version | structure.* | parsers[]
      source-says: "..."
      corpus-currently: "<missing | different | partial>"

  # 4. Artifact field-enrichment candidates (new field, new encoding detail, new
  #    anti-forensic pattern, new cross-artifact-reference implied by the source).
  artifact-field-enrichment:
    - artifact: <name>
      kind: new-field | observation-enrichment | anti-forensic-pattern | cross-artifact-ref
      source-says: "..."
      proposed-entry: "..."

  # 5. New concept candidates (value-types or identifiers the source references
  #    that don't exist in concepts/). Feeds concept_authorship_queue.
  concept-candidates:
    - name: <Proposed>
      kind: identifier | value-type
      evidence-in-source: "..."

  # 6. New convergence proposals (reasoning patterns spanning multiple artifacts
  #    that the source describes, which we haven't modeled as T2 entities).
  #    HARD RULE: a convergence is by definition a T2 link across ≥2 tier-1
  #    artifacts. Single-artifact "convergences" collapse to tier-1 observations
  #    and should be routed to artifact_field_enrichment_queue
  #    (kind: observation-enrichment / anti-forensic-pattern) instead of here.
  convergence-proposals:
    - proposition: <PROPOSED_NAME>
      contributing-artifacts: [<artifact-A>, <artifact-B>, ...]  # ≥2 required
      rationale: "..."

  # 7. New scenario proposals (case-study patterns / workflows the source describes
  #    that would be worth authoring as T3 entities).
  scenario-proposals:
    - slug: <proposed>
      narrative-summary: "..."
      involved-artifacts: [...]
```

**Drain destinations** (apply-script routes each category to its queue):

| Phase 6 category | Queue |
|---|---|
| related-sources | `new_source_leads` (shape enriched with `kind` / `authority-inferred` / `relevance`) |
| repository-candidates | `repository_candidates_queue` (new, top-level in crawl_state) |
| substrate-field-enrichment | `back_propagation.substrate_field_enrichment_queue` |
| artifact-field-enrichment | `back_propagation.artifact_field_enrichment_queue` |
| concept-candidates | `back_propagation.concept_authorship_queue` |
| convergence-proposals | `back_propagation.convergence_proposal_queue` |
| scenario-proposals | `back_propagation.scenario_proposal_queue` |

**Apply policy:** NONE of these queues auto-apply. All are editorial-review only. Same invariant as the viewer-critical-fields rule — authored datatypes (artifacts / substrates / concepts / convergences / scenarios) are never mutated by an apply script beyond provenance additions/retractions.

**Budget:** Phase 6 typically adds 2-4 minutes to an audit of a rich source. For narrow sources (single event-ID, single CVE, single blog post with no external references), Phase 6 produces empty arrays across the board and finishes in seconds.

**Rationale:** Each audit is an expensive opportunity to harvest *everything* a source carries about the corpus — sister sources it cites, format details it documents, reasoning patterns it describes, case studies it reconstructs, repositories it belongs to. Without Phase 6, most of that information is read by the agent and discarded. With Phase 6, it accumulates into queues that drive future authoring passes (new concepts, new convergences, new scenarios) and future audit prioritization (new repositories to crawl).

---

## Mapping Phase 4 hit URLs to our artifact names

Phase 4's probes are *category names*, not artifact names. When a probe like `USBSTOR` hits a URL, we need to determine which of our 292 artifacts the URL actually covers.

Heuristic:
1. Fetch the hit URL (light WebFetch — just enough to identify topic)
2. Match against our artifact filenames by registry-path / file-path / event-ID when possible
3. If the URL is a single-artifact focus page (common in blog posts), resolve to the artifact
4. If the URL is a hub / umbrella page, it may resolve to multiple artifacts

Record the mapping in `expand-coverage-to` using our canonical artifact names (i.e., the filename stem under `artifacts/`).

---

## Fallback behaviors

| Situation | Default |
|---|---|
| Focal URL 404 / dead | `retract-citations` all flagged; no further phases |
| Source marked `UNVERIFIED` in note | Default to `retract-citations` unless focal fetch succeeds |
| WebSearch rate-limited | Skip Phase 4; note in `notes:` |
| Phase 2 returns empty (single-article page with no nav) | Acceptable; record empty and move on |
| Phase 3 all attempts 404 | Record `not-found`; don't block output |

---

## Output target

Write each audit record into `tools/_coverage_audit.yaml` under the `audits:` list. When batch-running across many sources, group records in the same file.

## Applying audit output

Separate from producing the audit. Apply via a script that:
1. Reads `tools/_coverage_audit.yaml`
2. For each `retract-citations-from`: strips the source-id from those artifacts' provenance
3. For each `expand-coverage-to`: adds those artifact names to the source's `coverage.artifacts`
4. For each `new-source-leads`: queues into `tools/crawl_state.yaml` under `new_source_leads` (does NOT auto-add — human confirms)
5. Runs validator + build; commits

---

## Success criteria

Per source audited:
- [ ] `fetch-status` recorded
- [ ] `content-analysis` reasoning captures the per-artifact verdict
- [ ] `structural-elements.navigation-links` non-empty OR noted as "no nav present"
- [ ] `sitemap.discovery-method` records at least 2 attempts
- [ ] `site-search-results.probes-run` ≥ 9 (one per category) unless WebSearch unavailable
- [ ] `proposed-action` is one of the 4 allowed values

---

## Appendix: when to skip phases

The procedure above runs at full rigor. For known narrow-scope sources (single event-ID page, single CVE advisory), abbreviated audit is acceptable:

- Single MS-event-NNNN page: Phase 1 only. Phase 2-4 rarely yield. Document abbreviated.
- Single CVE advisory: Phase 1 only.
- Single academic paper DOI: Phase 1 + Phase 2 (paper references count as external sources).

Full rigor required for: repository / index-catalog kinds, blog archives, umbrella guides, reference sites, publisher hubs.
