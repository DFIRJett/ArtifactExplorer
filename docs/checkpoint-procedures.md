# Checkpoint procedures

Three cadences for verifying corpus health during the priority-driven source-crawl. Each has a specific scope and cost — don't run the heavy ones at every pause.

---

## Restart check (~30 seconds, every session start)

Goal: confirm environment is clean; identify next seed.

```
python tools/validate.py                # expect 0 errors, ~13 warnings (pre-existing)
python tools/verification_report.py     # progress counts
python tools/pending_decisions.py       # queue summary
```

Then peek at `tools/crawl_state.yaml` to identify the next frontier head (highest-count unprocessed artifact with highest-mention-type).

**What this catches:** broken state from uncommitted work, schema drift, unexpected artifact additions, pending items forgotten across sessions.

**Expected outcome:** "Ready to go — next seed is X — Y pending decisions from last session."

**Actions:** none unless warnings count increased or validator errors appeared.

---

## Pause check (~5 minutes, every ~5 seeds)

Goal: triage accumulating pending decisions; catch drift early.

### Steps

1. **Validator delta** — run `tools/validate.py`. Warnings should only decrease across crawl progression. If they increased, diagnose before continuing.

2. **Progress snapshot** — run `tools/verification_report.py`. Note:
   - Count of verified artifacts (should climb with each seed processed)
   - Per-substrate distribution (flag substrates that haven't been touched)
   - Count of verified sources

3. **Pending decisions triage** — run `tools/pending_decisions.py`. Expect accumulation in:
   - `new_source_leads` — candidate sources discovered during recent crawls. Per batch, decide: register (add to sources.yaml) / skip (out of scope) / defer (insufficient info to decide)
   - `fa_citation_audit_queue` — 44 FA citations that may be spurious; chip away in small batches
   - `tier23_review_queue` — methodology-source references noted during artifact crawls; escalate to convergence/scenario attribution passes
   - `discovered_artifacts_not_in_corpus` — artifact names seen in repos we don't have; decide whether to add to corpus
   - `verified-dead` sources — propose registry removal or keep-with-note
   - `verified-substrate-level` sources — check other artifacts citing them; retract where appropriate
   - `back_propagation.artifact_manual_review_queue` — **blocking**: artifacts where Phase 1 body-content cross-check surfaced a MAJOR conflict (path / encoding / format differs between corpus and source). Human triage required before the artifact can be marked audit-verified. Decide: update corpus to match source, update source understanding, or mark conflict unresolvable and note.
   - `back_propagation.substrate_manual_review_queue` — same but at substrate level (format spec disagreement)
   - `back_propagation.body_content_divergences` — informational: minor divergences that don't block audit-verification but merit editorial review
   - `back_propagation.substrate_field_enrichment_queue` — Phase 6 proposes adding substrate-body fields (format.magic, structure, parsers) from format-spec sources
   - `back_propagation.artifact_field_enrichment_queue` — Phase 6 proposes adding artifact-body fields, observation enrichment, or anti-forensic patterns from deep source reading
   - `back_propagation.concept_authorship_queue` — new-concept candidates surfaced by audits; author when source material supports
   - `back_propagation.convergence_proposal_queue` — new T2 reasoning-pattern candidates; require editorial authorship
   - `back_propagation.scenario_proposal_queue` — new T3 case-study candidates; require editorial authorship
   - `repository_candidates_queue` — sites/indices/journals worth dedicated multi-artifact crawls (distinct from per-page new_source_leads)

4. **Light duplicate check** — quick grep for same URL in multiple registry entries.

### Actions

Batch-triage the queues. Each queue item: register / skip / defer / retract. Apply approved actions in a small commit before continuing.

---

## Milestone review (~30 minutes, every ~20 seeds or before version tags)

Goal: the full R1-R13 review from 2026-04-22. Run rarely, at inflection points.

### Steps

1. **Validator health**:
   - `python tools/validate.py` — full pass including schema, provenance, coverage, concepts
   - Expect errors = 0; warnings stable or decreasing
2. **Data preservation survey**:
   - Count artifacts with non-empty provenance
   - Count sources with populated fields (field-by-field completeness %)
   - Verify schema-corpus consistency (substrates, concepts, scenarios, convergences)
3. **Forensic sensibility spot checks**:
   - Pick 3-5 verified artifacts; inspect their top edge-weights; verify they match forensic intuition (USBSTOR → MountedDevices should be high-weight; USBSTOR → ShimCache should be low or filtered)
   - Inspect coverage reports for sample artifacts
4. **Edge-weight distribution analysis**:
   - Median weight across corpus
   - Count of low-weight umbrella-noise edges (weight ≤ 0.3)
   - If noise count climbs, revisit the umbrella-contribution weighting formula
5. **Schema field completeness survey**:
   - Per-field population percentage across sources
   - Flag any regression in `coverage.artifacts` / `coverage.mentions` populations
6. **Registry reconciliation**:
   - Detect duplicate URLs across sources
   - Detect near-duplicate entries (same author + title + year across IDs)
   - Detect umbrella-vs-per-item redundancy (artifact cites both umbrella-repo and per-item from same family)
7. **Verification progress check**:
   - `verification_report.py --stale` — surface artifacts/sources never audited despite multiple seeds

### Actions

Major cleanup if needed. Output a "milestone N cleanup" commit if retracts / expansions / schema updates accumulate.

---

## What NOT to do at each checkpoint

- **Restart** should not trigger new audits, schema changes, or major reorganization. It's read-only verification.
- **Pause** should not attempt comprehensive corpus review. Triage only what's in the queues.
- **Milestone** should not be run per-seed. It's a quarterly-style ceremony for major inflections.

---

## Cadence summary

| Cadence | Frequency | Cost | Outputs |
|---|---|---|---|
| Restart | Every session start | 30 sec | "Ready to go" or flagged issue |
| Pause | Every ~5 seeds | 5 min | Pending-decision triage |
| Milestone | Every ~20 seeds | 30 min | Full review + major cleanup commit |

---

## Dead-source verification policy

Dead URLs surfaced by crawl agents (Phase 1 `fetch-status: dead`) are treated as **`verified-dead-pending`** initially, not immediately removed. Removal requires confirmation via `tools/verify_dead_sources.py`:

```
python tools/verify_dead_sources.py <source-id>
```

The tool runs four checks per URL:
1. HEAD request via curl with standard user-agent (`curl -sI -L`)
2. URL-variant attempts (trailing slash, www / no-www prefix, http→https)
3. Wayback Machine snapshot lookup via `archive.org/wayback/available?url=<url>`
4. Verdict: `alive` / `moved` / `bot-blocked` / `dead-with-wayback` / `dead-confirmed`

**Action by verdict:**

| Verdict | Action |
|---|---|
| `alive` | No change — Phase 1 agent was wrong (transient / rate-limit / bot-block). Restore citations if already retracted. |
| `moved` with `new-url` | Update URL on the source entry; re-verify; re-audit if content changed significantly. |
| `bot-blocked` (403/429) | Leave source alive; note in `note` field that WebFetch is blocked. |
| `dead-with-wayback` | Dead URL but Wayback snapshot available. Preserve entry; add `wayback-url` to note or as a proposed schema field. |
| `dead-confirmed` | Page 404 + no Wayback. Safe to remove registry entry. |

**Historical lesson (2026-04-22):** five MS channel-ref sources (ms-scm-events, ms-powershell-operational, ms-tsv-lsm-operational, ms-dns-client-operational, ms-defender-events) were incorrectly reported as dead-confirmed by an early (buggy) version of the tool — they are all alive. The fix was to stop checking curl's returncode (which can be non-zero on Windows due to /dev/null write failures even when the HTTP response succeeded) and parse the stdout verdict line directly. No citations were removed because we caught the bug before acting on the false positives.

---

## Apply policy — auto-apply vs stage for pause

Every seed's audit produces two kinds of output. The split by compute-impact decides which apply timing:

### Auto-apply immediately (affects crawl behavior; saves future compute)

Applies in the seed's apply-script, committed with the seed. Downstream benefits land immediately — attribution filter gets tighter, edge-weights update, next agent run doesn't re-discover.

- **New source entries** (all fields including `kind`, `authority`, `coverage`, `apa`, `access-guide` for new entries)
- **Retractions** from provenance (dead URL, substrate-only confirmed, spurious)
- **coverage.artifacts expansions** (up to 5 per seed per source)
- **coverage.mentions additions**
- **sitemap-url discovery**
- **URL corrections** (umbrella→specific, dead→replacement)
- **APA regeneration** (mechanical from other fields)
- **Verification-log status + dates**
- **Frontier count bumps**
- **seed_change_log entry** for the just-completed seed
- **Substrate-level provenance additions** (when Phase 5 `tier-applicability.substrate-level.applies: true`)
- **`tier_23_source_database` accumulation** — Phase 5 `tier-applicability.tier-2-applies-to` / `tier-3-applies-to` entries are written to `crawl_state.yaml` under `tier_23_source_database`. NOT auto-applied to convergence/scenario provenance — accumulates into an advisory catalog for later editorial pass.

### NEVER auto-apply — viewer-critical fields (always manual-review)

Regardless of how strong the signal is, apply scripts MUST NOT auto-modify these authored fields on existing entries. They drive D3 rendering in `viewer/index.html`; silent change reshapes the graph without the user seeing it. Any candidate change to one of these fields routes to `back_propagation.artifact_manual_review_queue` (or the substrate/concept/convergence equivalent), never to the entry directly.

| Entity | Fields that MUST NOT auto-update |
|---|---|
| artifact | `kind` · `link` · `link-secondary` · `substrate` · `substrate-class` · `substrate-instance` · `tags` · `volatility` · `interaction-required` · `exit-node.is-terminus` · `aliases` |
| substrate | `kind` · `substrate-class` · `name` |
| concept | `kind` · `link-affinity` · `aliases` |
| convergence | `exit-node` (terminus assignment) |

This rule is cross-cutting — it applies to every apply script, current and future (including H-006 M-4 artifact-wiring sweep when it lands). Provenance additions/retractions are NOT on this list because they don't reshape graph rendering; they update the verified-filter dimension which the viewer already treats as audit-state, not structural identity.

See `docs/source-audit-procedure.md` § Phase 1 supplement for the Phase 1 MAJOR/minor classification that feeds these queues.

### Stage for pause-point review (editorial / judgment; zero compute impact)

Writes to `tools/_pending_field_updates.yaml`. Pause-point triage reviews and either approves (apply) or rejects.

- **Access-guide prose updates on existing entries** — cosmetic; readers use it; no agent-behavior impact
- **Note-field rewrites on existing entries**
- **kind / authority reconsiderations** on existing entries
- **Author / title cosmetic corrections** when not bundled with URL correction
- **Bulk coverage.artifacts additions** (>5 items in a single seed — warrants spot-check)

### Rationale

Structured data changes propagate through the pipeline — apply immediately so downstream benefits land. Prose/editorial content doesn't affect agent behavior — safe to defer; human reviews at pause.

Risk of auto-applying structured changes is bounded by:
- Next seed's audit re-verifies sources (divergence detectable)
- Validator treats non-empty `coverage.artifacts` as authoritative (over-claims surface as warnings)
- Milestone review (every 20 seeds) re-audits top sources

Net effect: crawl speed ~= full auto-apply; prose quality gated by human review; errors in structured data surface naturally in next seed's divergence from expectations.
