# Changelog

Notable changes to DFIRCLI. Tagged versions only; untagged commits advance the `latest-stable` rolling pointer between releases.

Format follows [Keep a Changelog](https://keepachangelog.com/). Versioning is pre-1.0 and uses the pattern `vN-descriptor` — see `docs/architecture.md` for the scheme.

---

## [v5-attribution] — 2026-04-22

Source registry expanded and the 146 unattributed artifacts attributed. Coverage goes from 50% to 95.5%.

### Registry (303 entries, was 273)

- **Added 30 gap-filler entries**: 8 libyal format specs (libregf, liblnk, libfwsi, libscca, libesedb, libpff, libolecf, libevtx), 3 Microsoft Open Specifications (MS-SHLLINK, MS-PST, MS-CFB), 9 MITRE ATT&CK sub-techniques (T1003.002/004, T1059/001, T1543/003, T1546.009/010, T1547.001), 6 Microsoft channel/provider reference pages (Defender, SCM, PowerShell/Operational, TerminalServices-LSM, DNS-Client, DriverFrameworks-UM), Carrier FSFA textbook, Chromium + Firefox schema refs, Khatri srum-dump.
- **Cleaned 32 existing entries**: 13 URL strengthens (umbrella → specific), 8 metadata fixes (year/title corrections, MITRE parent-vs-sub title mismatches), 4 reattributions (unlocatable original → canonical alternative, ID preserved), 7 unverified markers (entry kept, note flags source cannot be located).

### Attribution (292 artifacts)

- **133 previously-unattributed artifacts** populated with provenance IDs from the expanded registry.
- **13 artifacts remain `provenance: []`** — gap-only. Needed sources (browser JSON formats, CBS/DISM/WU/IIS/DHCP/HTTPERR log specs, ActivityCache schema, OAB/.lzx format, YARA docs) aren't in scope for this pass.
- **Top source IDs applied**: libyal-libregf (53×), libyal-libevtx (23×), carrier-2005-FSFA (14×), libyal-liblnk + ms-shllink paired (11× each), chromium-history-schema (8×), libyal-libesedb (7×).

### Documentation

- `tools/_source_review.md` — full source-applicability audit report (273 entries classified into KEEP / STRENGTHEN-URL / FIX-METADATA / REMOVE).

---

## [v4-provenance] — 2026-04-22

Bibliographic attribution restructured. Per-artifact `sources:` blocks replaced with a centralized source registry referenced by a `provenance:` field on all entity types. Five commits on `refactor/provenance` merged to master.

### Added

- `schema/sources.yaml` — canonical source registry. 273 entries deduplicated from legacy data, each with `{id, apa, author, year, title, publisher, url, note?}`. APA 7 pre-formatted strings for display.
- `provenance:` field on artifact, concept, convergence, and scenario schemas. Each entry is either a bare source-ID string or `{source, section?, note?}` for citing a specific part of a source.
- Validator resolves every `provenance:` ID against the registry; unknowns are build errors.
- `tools/extract_sources.py` — one-shot registry extraction from legacy `sources:` blocks (kept for reproducibility).

### Removed

- `sources:` field on artifact schema (data migrated into registry).
- `$defs/source` in artifact schema → replaced with `$defs/provenanceRef`.

### Migrated

- 146 artifacts had their `sources:` blocks rewritten as `provenance:` arrays of source IDs.
- 146 unsourced artifacts received empty `provenance: []`, pending the attribution audit (next milestone).

### Viewer

- Inspector Sources block resolves provenance IDs against `data.sources` at render time. Unknown IDs render a visible audit warning rather than failing silently.

### Known gaps

- 50% of the corpus (146 artifacts) carries empty provenance. A manual attribution pass against source-fingerprint heuristics is the next piece of work.

---

## [v3-schema-cleanup] — 2026-04-22

Schema audit pass on `refactor/schema-cleanup`. Four commits merged to master.

### Removed (verified unused)

- `concept.exit-node` field — contradicted the exit-node taxonomy (exit-nodes are identifier-kind concepts automatically + manually-flagged artifacts).
- `artifact.fields[*].references-data[*].rationale` — zero usage across corpus.
- `substrate.volatility` enum — tautology; all 15 substrates were `on-disk`.

### Added

- `convergence.yields.casey-rationale` (both modes) — one-line justification for ceiling assignments.
- `convergence.join-chain[*].join-strength` — optional enum (strong / moderate / weak) for grading pivot tightness. Will populate inline during the imminent join-chain authorship pass.

### Changed

- `scenario.severity` tightened to enum `reference | playbook | case-study`. The one `high` outlier (`departing-employee-usb-exfil`) reclassified to `case-study`.
- Six fields sunset-marked with DEPRECATED descriptions, scheduled for removal once authorship passes complete: `convergence.via-artifacts`, `convergence.notes`, `scenario.artifacts`, `scenario.join-keys`, `scenario.steps[*].artifacts`, `scenario.steps[*].join-key`.

### Deliberately skipped

- Formalizing substrate bucket keys (`format`, `structure`, `persistence`, etc.) — low ROI for solo-author corpus; free-form is fine.
- `entity-kind` on exit-nodes and structured `common-errors` — premature; revisit when data patterns emerge.

---

## [v2-tier-model] — 2026-04-22

Major restructure: two-axis schema (substrate + tier). Ten commits on `refactor/tier-model` merged to master.

### Vocabulary changes

| Before | After |
|---|---|
| `containers/` directory | `substrates/` |
| `forensic-data/` directory | `concepts/` |
| `container-class:` field on artifacts | `substrate:` |
| `container-instance:` | `substrate-instance:` |
| `source-class:` field on containers | `substrate-class:` |
| `supports:` block on artifacts | `observations:` |
| `extends-to:` on artifacts | extracted to `convergences/*.md` files |
| `anti-forensic.mutability:` free-text | split into top-level `volatility:` + `anti-forensic.write-privilege:` |

### New schema

- `docs/architecture.md` — lock-in spec for the two-axis model.
- **Tier 2 first-class:** `convergences/` directory with `schema/convergence.schema.json`. 33 files extracted from the old `extends-to:` rules. Dual-mode `yields:` (new-proposition OR ceiling-elevation + corroboration-strength). Optional `join-chain:`, `exit-node:`, `degradation-paths:`.
- **New top-level fields on artifacts:** `volatility:` (permanent / persistent / session-scoped / runtime), `interaction-required:` (none / user-session / user-action).
- **New top-level field on concepts:** `lifetime:` (same enum as volatility).
- **New field on observations:** `confidence:` (established / debated / preliminary / unverified) + optional `debate-note:`.
- **New required block on scenarios:** `anchors:` with `entry:` (single exit-node) + `conclusions:` (list of 1+). Minimum 2 anchors total.
- **New optional field on scenario steps:** `convergence:` reference.

### Viewer

- Inspector: "Evidence axes" chip row (volatility / interaction-required / write-privilege) on artifact nodes; "Lifetime" field on concept nodes.
- Config tool pane: new Volatility floor slider (4 tiers: all / persistent+ / session+ / permanent).
- All field-rename wiring caught up.

### Docs

- `docs/architecture.md` — the spec.
- `docs/deferred.md` — 12 items deliberately left for future passes (bridge-artifact property, edge styling by volatility, tier-2-as-edges topology, convergence join-chain authorship, write-privilege audit, etc.).
- `docs/nomenclature.md` — updated for the new vocabulary.

### Stats

- 292 artifacts · 25 concepts · 33 convergences · 11 scenarios
- 578 concept references
- Validator 0/0 across 336 files
- Build 0 warnings

---

## [v1-phase2-clean] — 2026-04-20

Phase 2 schema formalization baseline. Pre-tier-model vocabulary.

### Added

- JSON Schema Draft 2020-12 for artifacts, containers, concepts, scenarios.
- `schema/concepts.yaml` as the canonical concept-role registry.
- `tools/validate.py` with jsonschema primary path + minimal fallback.
- 340 corpus files validate clean.

### Notes

Schema and vocabulary were substantially reworked in v2-tier-model. `v1-phase2-clean` is preserved as a historical pre-restructure restore point; `git checkout v1-phase2-clean` lands here.
