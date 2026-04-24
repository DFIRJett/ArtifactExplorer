# ArtifactExplorer

Interactive DFIR knowledge graph for Windows forensic artifacts. Browse 292
artifacts across 15 substrates, see how they corroborate each other through
34 Tier-2 convergences, and walk 11 Tier-3 case-study scenarios end-to-end.

**Live site:** https://dfirjett.github.io/ArtifactExplorer/

## What it is

A structured DFIR corpus + interactive viewer built around a three-tier
evidentiary model:

- **Tier 1 — Artifacts.** One entry per forensic container (registry key,
  event-log record, SQLite database, etc.). Documents fields, locations,
  encodings, observations, anti-forensic surface, and bibliographic provenance.
- **Tier 2 — Convergences.** Multi-artifact inferences joined on a shared
  pivot identifier (a SID, LUID, GUID, serial). Encodes how independent
  artifacts corroborate the same forensic claim.
- **Tier 3 — Scenarios.** Case-study walkthroughs with stepwise investigative
  questions, each step naming the artifacts that answer it, the join key
  threading the steps together, and a Casey C-scale strength rating.

The schema is documented field-by-field with academic reasoning + sourced
citations in **[01-SCHEMA.md](01-SCHEMA.md)**.

## Run the viewer locally

```
python tools/serve.py
```

Then open http://localhost:8100/viewer/index.html

## Rebuild the graph from source

```
python tools/build-graph.py
```

Walks `artifacts/`, `convergences/`, `scenarios/`, `concepts/`, `substrates/`
and the `schema/sources.yaml` registry. Emits `viewer/data.json` (~2.6MB
minified) which the viewer loads.

## Layout

```
ArtifactExplorer/
├── 01-SCHEMA.md            # Schema reference + academic reasoning + citations
├── README.md
├── CHANGELOG.md
├── artifacts/              # 292 Tier-1 artifact files, by substrate
├── convergences/           # 34 Tier-2 join-chain definitions
├── scenarios/              # 11 Tier-3 case-study walkthroughs
├── concepts/               # Concept (join-key) definitions
├── substrates/             # Substrate-class definitions
├── schema/                 # JSON schemas + sources.yaml (470 entries)
├── docs/
│   ├── architecture.md     # System architecture overview
│   └── nomenclature.md     # Naming conventions
├── topics/                 # Forensic methodology references
├── tools/                  # Build pipeline + analytic scripts
└── viewer/                 # Interactive d3-based force-graph viewer
    ├── index.html
    └── data.json           # Compiled graph data
```

## Citing

Citation guidance — including APA / MLA / IEEE forms for the schema doc and
the AI-assistance disclosure — is at the bottom of [01-SCHEMA.md](01-SCHEMA.md).
