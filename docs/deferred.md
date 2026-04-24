# Deferred work

Items that were considered during the tier-model restructure (commits A-J, April 2026) and deliberately left for future passes. Each is schema-extensible — adding any of them does not require another structural migration.

Grouped roughly by size and by what kind of commit would land them.

---

## Frontend / viewer work (delegated track)

All items in this section are `viewer/index.html` work — rendering, interactions, UI chrome. Consolidated here for delegation to the secondary Claude instance (which owns viewer/frontend work per the HANDOFF boundary). See `memory/INBOX/primary-20260422-frontend-deferred-consolidation.md` for the handoff notification.

Primary continues to own the data layer, schema, tooling, and corpus content; the frontend track can run in parallel.

### F1 — Consume new data-layer fields (source-count, edge-weights, verification status)

Data-layer work already emitted three per-artifact fields into `viewer/data.json`; the d3 rendering does not yet read them.

- `source-count: <int>` — forensic-relevance signal (count of sources whose `coverage.artifacts` includes this artifact)
- `edge-weights: { sister-artifact: fraction, ... }` — per-edge co-occurrence weight
- Verification status — derived from `tools/crawl_state.yaml` `verification_log`

**Viewer work:**
- Edge rendering: scale link stroke-width / opacity by `edge-weights`
- Node sizing: incorporate `source-count` into `artifact_size()`
- Config pane: "Relevance floor" slider filter
- Inspector: show source-count + top-N sister edges per selected node
- Verification-status badge: visually distinguish verified / unverified / verified-dead / verified-substrate-level nodes

**Note on edge-weight noise:** low-weight edges (~0.25) include umbrella-source artifacts (RegRipper covers 14 unrelated registry artifacts, so USBSTOR gets 0.25-edges to ShimCache/BAM/etc. via the shared umbrella). Recommend a viewer-side threshold (render only edges ≥ 0.5) rather than a build-time weight correction. Threshold could be user-configurable.

### F2 — H-002: Walkthrough UI overhaul (notification popup + walkthrough canvas fix + right sidebar)

Three-component integrated plan. Flagship USB-convergence-chain walkthrough is currently broken on canvas highlighting.

- **Notification popup system** — ephemeral visual cues for state changes; matches existing panel aesthetic (var(--panel), var(--stroke), 8px radius, severity-colored left border)
- **Walkthrough canvas-highlight fix** — `state.activeStepN` / `state.revealedSteps` update correctly but canvas doesn't respond; diagnose graph-side subscription gap
- **Right context sidebar** — progressive-disclosure overflow; tabs for Detail / Sources / Anti-forensic / Related / Timestamps / Practice; collapsed icon strip by default

~10-14 hours focused work. Full details in `memory/HANDOFF.md` H-002.

### F3 — Edge styling by volatility tier

Graph edges rendered with line style + opacity encoding derived from `min(endpoint volatility)` — a USBSTOR↔UserSID edge (both permanent/persistent) renders solid and bright; a ProcessId-mediated edge (runtime) renders dashed and faint. Companion to the Volatility slider already in place.

Viewer-only. Edge rendering in each view's `init()` consults endpoint volatility to pick stroke style.

### F4 — Tier-2-as-edges graph topology

Currently graph edges are concept-reference containment (`artifact → concept`). A tier-2 view would draw direct edges between artifacts that share an identifier concept, with the concept + roles as edge attributes — so every edge IS a tier-2 join. Dual-mode-yield convergences populate a second edge layer for corroboration.

Most aggressive viewer change available. Consider offering as a separate view-tab alongside the current graph, not a replacement.

### F5 — Radial-exploration interaction

"Focus on this node: dim everything not connected to it" interaction. Distinct from scenarios (which require 2+ anchors) — this is single-node exploration.

Bind to click-and-drag or double-click on any node.

### F6 — Scope labels on identifier concepts

Inspector text + legend block explaining that inferences drawn from an identifier concept are scoped to one specific real-world entity (e.g., "This UserSID concept aggregates identity — every specific value you see refers to one real user").

Orthogonal to what's already rendered; no schema change; viewer-only.

### F7 — Bridge-artifact rendering (companion to data-layer change)

The data-layer "bridge-artifact property" (see `Small / incremental schema extensions` below) adds a derived `is-bridge: true` flag at build time. Viewer side: render bridges with a distinct badge or halo. Pairs with F1's verification-status rendering.

---

## HANDOFF-deferred (from secondary instance)

### H-001 — Forensic-utility population priorities (schema additions + population passes)

Secondary instance's proposed roadmap for post-attribution-pass schema enrichment. Tier 1 (rigor): per-claim source linking, confidence backfill, temporal-precision, structured anti-forensic patterns. Tier 2 (workflow): acquisition metadata block, sister-artifact links. Tier 3 (training): structured common-errors, hunt-query library, MITRE as structured field. Tier 4 (niche): timezone-per-timestamp, tier/difficulty ratings. Full details in `memory/HANDOFF.md` H-001. Runs AFTER corpus-wide source review completes.

---

## Small / incremental schema extensions

### Bridge-artifact property (derived at build time)

An artifact is a *bridge* when its `fields:` bind two or more distinct identifier-kind concepts in the same record. USBSTOR carries both DeviceSerial and ContainerID. Partition/Diagnostic 1006 carries DeviceSerial and (via raw VBR bytes) material that resolves to FilesystemVolumeSerial. These artifacts disproportionately anchor convergence chains because losing them collapses two identifier spaces at once.

**Shape:** a derived `is-bridge: true` property computed in `tools/build-graph.py`. No schema change — the property is populated per-artifact based on field-level concept-reference bindings. Companion viewer rendering is F7 above.

### Structured common-errors frontmatter

Currently common-error tables live as prose in artifact bodies. Structured frontmatter (`common-errors:` list of `{error, consequence, correction}` objects) would make them filterable, queryable, and renderable in the Inspector.

**Shape:** add `common-errors:` as an optional top-level array on `schema/artifact.schema.json`. Author entries manually per artifact.

### Per-timestamp-field temporal-precision

Our `fields[*]` entries with `kind: timestamp` all look the same in the schema, but MountPoints2's `LastWriteTime` and USBSTOR's `LastArrivalDate` carry very different forensic weight. A `temporal-precision:` field on timestamp fields would encode this: `event-precise` / `approximate` / `debated`.

**Shape:** add an optional `temporal-precision:` key on the field schema inside `artifact.schema.json`. Populate mechanically where the existing `note:` already hedges the timestamp; otherwise manual.

### Rich exit-node entity-kind typing

An `exit-entity-kind:` property on concept files (and on artifacts flagged `exit-node: true`) declaring what real-world entity class the exit-node resolves to: `human`, `machine`, `device`, `volume`, `file`, `session`, `config-entity`, `namespace`.

**Shape:** optional top-level field on the concept + artifact schemas. Enumerated.

---

## Content / authorship passes

These aren't schema work — they're knowledge-curation work that the existing schema can already accept.

### Fill in convergence join-chain + exit-node

The 33 convergence files extracted in commit D have empty `join-chain:` and empty `exit-node:` — both left as authorship TODO. Each convergence needs a manual pass to specify which identifier concepts thread its input artifacts and what exit-node the chain terminates at.

Each file is ~50 lines of YAML; most would take 5–15 minutes to author properly. Total effort: 3–8 hours spread across 33 files.

### Scenario step-level convergence references

The `convergence:` field on `scenarios/*/steps[*]` was added to the schema in commit E but not populated. Each scenario's step can name a convergence file that implements it. Seven of the 11 scenarios have explicit steps (`steps: 6` typically); others are overlay-only and don't need per-step convergence refs.

Effort: ~2 hours.

### Observation confidence audit

Every observation defaults to `confidence: established`. The corpus almost certainly contains some claims that should be flagged `debated` (e.g., MountPoints2's LastWriteTime semantics, per the terminology-controversy conversation) or `preliminary`. A pass through the observations picking out the non-established ones with `debate-note:` citations of the disagreeing sources.

Effort: ongoing — probably a few hours for an initial pass, then incremental.

### Write-privilege audit — resolve the 87 "unknown"

Commit C2's distribution showed 87 artifacts with `write-privilege: unknown` because the old `mutability:` text didn't match any mapping pattern. These need individual review: is it admin, user, service, or kernel-only? The answer is almost always derivable from the artifact's substrate + path + existing prose, but needs human judgment.

Effort: ~2 hours.

### Node description view refactor

User-flagged 2026-04-22 during baton-protocol adoption cycle. Scope TBD — needs follow-up with user to specify what the refactor covers. Candidate interpretations:

- Restructure artifact-body prose sections (`## Forensic value` / `## Concept references` / `## Known quirks` / `## Anti-forensic caveats` / `## Practice hint`) into a more consistent template across the 292 artifacts
- Split free-form description prose into structured frontmatter fields that the viewer can render systematically (instead of body markdown the viewer currently embeds as prose block)
- Data-layer refactor of what `data.json` emits for node descriptions so the viewer's Inspector can show structured sections rather than a single prose blob
- Some combination of the above

Owned by primary (this model) per user direction. Effort: unknown until scope is pinned — ranges from a small schema-additive pass (~1-2 hours) to a corpus-wide authorship pass (~6-10 hours) depending on which interpretation lands.

---

## How to tackle these

Order suggestion, roughly by ROI × effort. Frontend items (F1–F7) run on the secondary-instance track, parallel to the data-layer items below.

**Data-layer / authorship (primary-instance track):**

1. Convergence join-chain authorship (highest ROI — unlocks tier-2 visualization meaningfully).
2. Write-privilege audit (mechanical cleanup; restores forensic-posture info).
3. Scenario step convergence references (wires the two tiers together explicitly).
4. Observation confidence audit (pedagogical value; paces well with normal authoring).
5. Bridge-artifact derived property.
6. Rich exit-node entity-kind typing.
7. Structured common-errors frontmatter.
8. Per-timestamp-field temporal-precision.
9. H-001 schema additions (per-claim source linking, confidence backfill, acquisition metadata, sister-artifact links, etc.).

**Frontend (secondary-instance track, F1–F7 above):**

- F1 (new-data-layer consumption) unblocks immediate visual payoff from data work already in viewer/data.json
- F2 (walkthrough overhaul) restores the flagship demo
- F3–F6 are independent enrichment
- F7 pairs with data-layer item #5 (bridge-artifact)
