# ArtifactExplorer Schema Reference

A complete field-by-field reference for the four schemas this project authors,
organized around the three-tier evidentiary model the corpus is built on.
Every field carries a **plain-English description**, an **academic / forensic
reasoning** note explaining why the field exists at all, and one or more
**authoritative sources** backing the datatype it carries.

> Status: First pass. Tier 1 (Artifact) is complete. Tier 2 (Convergence),
> Tier 3 (Scenario), Source schema, Cross-references, Datatype catalog, and
> Reconciliation report are scaffolded with TODO markers and will land in
> subsequent passes during the cleanup process.

---

## The three-tier model

The corpus is structured around three discrete tiers of evidentiary work,
mirroring the standard tier-1/tier-2/tier-3 analyst progression in mature
DFIR programs and the layered-inference framing used in Casey
(2002), *Error, Uncertainty and Loss in Digital Evidence,* and Casey
(2020), *Standardization of forming and expressing preliminary evaluative
opinions on digital evidence.*

| Tier | What it answers | Schema | Lives in |
|---|---|---|---|
| **Tier 1** | "What container holds this evidence and what does it record?" | Artifact schema | `artifacts/<substrate>/<name>.md` |
| **Tier 2** | "Which artifacts corroborate the same forensic claim, joined on which pivot?" | Convergence schema | `convergences/<RELATION>.md` |
| **Tier 3** | "How does an analyst walk a case end-to-end, and what's the cumulative certainty at each step?" | Scenario schema | `scenarios/<chain>.md` |

The fourth schema (`schema/sources.yaml`) is the **bibliographic registry**
that every tier references via `provenance:` (Tier 1) or `primary-source:`
(Tier 2 + 3) — it does not itself sit in the tier hierarchy; it underwrites it.

**Why three tiers, not one?** The Tier-1 / Tier-2 / Tier-3 split mirrors how
Casey distinguishes (a) the *raw artifact* (a registry hive entry, an event
record), (b) the *inferential proposition* it supports (an "AUTHENTICATED" event,
a "DEVICE_CONNECTED" event), and (c) the *narrative reconstruction* that
chains propositions into a case story. Mixing the three at one schema
level is what produces the sprawling "everything is an artifact" knowledge
bases this project explicitly avoids — Casey-Layer-1 atoms get authored
separately from Casey-Layer-2 inferences, which get authored separately
from Casey-Layer-3 narratives.

> **Sources** (full APA, drawn from `schema/sources.yaml` registry):
>
> Casey, E. (2002). Error, Uncertainty and Loss in Digital Evidence. *International Journal of Digital Evidence (IJDE).* https://www.utica.edu/academic/institutes/ecii/publications/articles/A0472DF7-ADC9-7FDE-C80B5E5B306A85C4.pdf
>
> Casey, E. (2020). Standardization of forming and expressing preliminary evaluative opinions on digital evidence. *Forensic Science International: Digital Investigation.* https://doi.org/10.1016/j.fsidi.2019.200888

---

## Tier 1 — Artifact schema

**File pattern:** `artifacts/<substrate>/<artifact-name>.md`
**Purpose:** Document one forensic *container* — a registry key, an event-log
record, a SQLite database, a binary cache file. An artifact entry lists what
fields the container holds, where each field is located inside the container,
how each field encodes its data, and which higher-tier concepts those fields
reference.

### Frontmatter — top-level fields

| Field | Type | Req | Allowed values / format | Description |
|---|---|---|---|---|
| `name` | string | yes | slug-form (`Security-4624`, `USBSTOR`) | Canonical artifact identifier. Must equal the filename minus `.md`. Becomes `artifact::<name>` in the graph. |
| `title-description` | string | yes | one short sentence | Human-readable purpose summary, surfaced in the inspector card hero. |
| `aliases` | string[] | no | array of strings | Alternate names the artifact may be known by — used by the search index and inspector "Also known as" block. |
| `link` | string | yes | one of: `system`, `user`, `network`, `security`, `application`, `forensic`, … | Mechanism / purpose grouping. Drives `link-affinity` color in the graph view and mechanism-hull membership when hulls are enabled. |
| `tags` | string[] | no | enum (see below) | Cross-cutting attributes (e.g. `tamper-hard`, `timestamp-carrying`, `per-user`, `rotation-fast`). Used as legend filters. |
| `volatility` | string | yes | one of: `runtime`, `session-scoped`, `persistent`, `permanent` | Evidence lifetime tier. Drives the volatility-floor slider in the legend. |
| `interaction-required` | string | yes | one of: `none`, `user`, `admin`, `system` | What privilege or user action is required to *create* this artifact (not to read it). |
| `substrate` | string | yes | one of: `windows-evtx`, `windows-registry`, `windows-sqlite`, `windows-text-log`, `windows-binary-cache`, `windows-ess`, `windows-jumplist`, `windows-lnk`, `windows-prefetch`, `windows-thumbcache`, `windows-pst`, `windows-ntfs-metadata`, `windows-recyclebin`, `windows-disk-metadata`, `windows-fat-metadata` | Technical substrate the artifact lives in. Drives the substrate-class color and substrate-view mother grouping. |
| `substrate-instance` | string | no | path-like | Specific instance within the substrate (e.g. `Security` for the EVTX channel, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` for a specific registry key). |
| `platform` | object | no | `{windows: {min, max}, windows-server: {min, max}, linux: {min, max}, macos: {min, max}}` | Platform-version applicability matrix. |
| `location` | object | yes | per-substrate (see below) | Where to find the artifact on disk + within its substrate. |
| `fields` | object[] | yes | array of field objects | The data fields this artifact holds. |
| `observations` | object[] | yes | array of observation objects | Forensic propositions the artifact supports + the Casey-scale ceiling for each. |
| `anti-forensic` | object | no | `{write-privilege, integrity-mechanism, known-cleaners[], survival-signals[]}` | Tampering surface analysis. |
| `provenance` | string[] | yes | array of source-ids from `sources.yaml` | Bibliographic backing for every claim in the file. |
| `cross-verifies-with` | object[] | no | array of `{artifact, pairs[]}` | Auto-emitted by the build: peers that share a `concept:role` pair. |
| `resolves-identity-via` | object[] | no | array of `{definer-artifact, concept, user-role}` | Auto-emitted by the build: peers that translate one of this artifact's identifier fields into a human-readable subject. |
| `is-exit-node` | bool | no | `true` / omitted | Marks the artifact as a "terminator" of investigative chains — typically attribution endpoints (SAM, ProfileList) or hash registries. Manually flagged. |

#### Reasoning — why this set of top-level fields?

The frontmatter answers the five questions a forensic examiner asks of any
piece of evidence:

1. **What is it?** (`name`, `title-description`, `aliases`, `link`)
2. **Where do I find it?** (`substrate`, `substrate-instance`, `location`, `platform`)
3. **How long does it last and how easily is it tampered?** (`volatility`, `interaction-required`, `anti-forensic`)
4. **What can I conclude from it, and how confident?** (`observations` with Casey ceilings)
5. **Who says so?** (`provenance`)

The split-out `cross-verifies-with` and `resolves-identity-via` blocks are
*derived*, not authored — they're computed by the build pipeline by walking
every other artifact's `fields[].references-data` entries and matching on
shared concepts. They're materialized into the file so the inspector can
render corroboration tables without having to run a graph query at view
time. Casey's principle of corroborating evidence (2002, ch. 3) is the
forensic justification — a single artifact bearing a single identifier
field is a thin claim; the same identifier appearing in N other artifacts'
fields is N independent corroborations of that claim.

> **Sources backing this design** (full APA):
>
> Casey, E. (2002). Error, Uncertainty and Loss in Digital Evidence. *International Journal of Digital Evidence (IJDE).* https://www.utica.edu/academic/institutes/ecii/publications/articles/A0472DF7-ADC9-7FDE-C80B5E5B306A85C4.pdf
>
> Casey, E. (2020). Standardization of forming and expressing preliminary evaluative opinions on digital evidence. *Forensic Science International: Digital Investigation.* https://doi.org/10.1016/j.fsidi.2019.200888
>
> Carrier, B. (2003). Defining Digital Forensic Examination and Analysis Tools Using Abstraction Layers. *International Journal of Digital Evidence, 1*(4). [⚠ NOT YET REGISTERED in `schema/sources.yaml` — candidate for addition.]

---

### `fields[]` — the field schema

Each entry in the `fields` array describes one data column / value the
artifact holds.

| Sub-field | Type | Req | Allowed values / format | Description |
|---|---|---|---|---|
| `name` | string | yes | kebab-case slug | Field identifier within the artifact. |
| `kind` | string | yes | one of: `timestamp`, `identifier`, `path`, `counter`, `hash`, `bool`, `enum`, `binary`, `freetext`, `object` | The *forensic kind* of the field — drives downstream coloring + filtering. |
| `location` | string | yes | substrate-relative path | Where in the container the field lives (e.g. `EventData\TargetUserSid` for an EVTX field, `\HKLM\...\Value` for a registry value). |
| `encoding` | string | yes | datatype (see Datatype catalog below) | How the bytes are encoded (`sid-string`, `iso8601-utc`, `utf-16le`, `hex-uint64`, etc.). |
| `clock` | string | conditional | `system`, `monotonic`, `external`, `unknown` | Required for `kind: timestamp`. Which clock generated the timestamp. |
| `resolution` | string | conditional | `1us`, `1ms`, `1s`, `1d`, … | Required for `kind: timestamp`. Granularity. |
| `references-data` | object[] | no | array of `{concept, role}` | The concept this field's value resolves to + the role it plays in that concept's reference graph. This is the JOIN-KEY emission — every entry here adds one edge in the graph. |
| `note` | string | no | free text | Analyst-facing prose explaining quirks, non-obvious values, common mistakes. |

#### Reasoning — why `kind` is separate from `encoding`

`kind` is the *forensic role* (is this a timestamp, an identifier, a
counter?), `encoding` is the *bit-level representation* (UTF-16LE,
hex-uint64, ISO-8601-UTC, etc.). The same kind can appear in many
encodings (a SID can be `sid-string` or `sid-binary`; a timestamp can be
`iso8601-utc` or `windows-filetime` or `unix-epoch-ms`). Splitting them
lets parsers route on `kind` (decide which presenter to use) and validate
on `encoding` (check the byte format). This mirrors the
abstraction-layer separation Carrier (2003) calls out — physical encoding
is a different abstraction layer than logical kind.

#### Reasoning — `references-data` as the join-key emission point

Every Tier-2 convergence in this project is built by *unioning* every
artifact's `references-data` entries that name the same `concept:role` pair.
That's the formal definition of a join key in the relational sense — a
field whose value, when shared across two records, identifies them as
referring to the same real-world entity. Authoring at the field level
(rather than the artifact level) means the join machinery is composable:
a new artifact contributing the same `(concept, role)` pair automatically
joins every existing convergence that uses it, without re-authoring the
convergence file. This is the same principle Cohen (2012) calls out for
his "AFF4" object-relational evidence model — pivot identity lives at the
field, not the container.

> **Sources backing this design** (full APA):
>
> Carrier, B. (2003). Defining Digital Forensic Examination and Analysis Tools Using Abstraction Layers. *International Journal of Digital Evidence, 1*(4). [⚠ NOT YET REGISTERED in `schema/sources.yaml`.]
>
> Cohen, M. (2012). Building a Forensic Tool with the AFF4 Object Model. *Digital Investigation, 9*, 117–127. https://doi.org/10.1016/j.diin.2012.05.014 [⚠ NOT YET REGISTERED in `schema/sources.yaml`.]

---

### `observations[]` — the proposition schema

Each observation declares one forensic claim the artifact supports, with
the Casey C-scale ceiling for the strength of that claim.

| Sub-field | Type | Req | Allowed values / format | Description |
|---|---|---|---|---|
| `proposition` | string | yes | UPPER_SNAKE | The forensic claim (e.g. `AUTHENTICATED`, `EXECUTED`, `FILE_ACCESSED`). Must match a Tier-2 convergence name OR be an extension of one. |
| `ceiling` | string | yes | `C1` … `C6` | Casey-scale ceiling of certainty this artifact alone can support. |
| `note` | string | no | free text | Why the ceiling is what it is — e.g. "C4 because event is signed but timestamps can be backdated by SYSTEM-level cleaners." |
| `qualifier-map` | object | no | `{principal, target, result, method, source, time.start, time.end}` with values like `field:<field-name>` or `this-system` | Maps proposition qualifiers to the artifact field that supplies each, so the build can synthesize the proposition's structured form (who, what, how, when) from the artifact's parsed fields. |
| `exit-node` | bool | no | `true` / omitted | Marks this observation as a terminator of inference chains. |

#### Reasoning — Casey ceilings, not Casey scores

The schema records the *ceiling* (the strongest claim the artifact alone
can support), not a final score. The actual case score is a function of
how many other artifacts corroborate the same proposition — that's the
Tier-2 work. Recording the ceiling at Tier-1 keeps the artifact entry
self-contained and forces the analyst to do the corroboration work
explicitly (via a Tier-2 convergence + Tier-3 walkthrough) rather than
inheriting unjustified confidence from an "evidence" label.

> **Source** (full APA):
>
> Casey, E. (2002). Error, Uncertainty and Loss in Digital Evidence. *International Journal of Digital Evidence (IJDE).* https://www.utica.edu/academic/institutes/ecii/publications/articles/A0472DF7-ADC9-7FDE-C80B5E5B306A85C4.pdf — Table 5, *Certainty scale*.
>
> The C1–C6 ladder (per Casey, 2002, Table 5) is reproduced verbatim here:
> - **C1** Erroneous / incorrect
> - **C2** Highly uncertain
> - **C3** Somewhat uncertain
> - **C4** Probable
> - **C5** Almost certain
> - **C6** Certain (rare; reserved for cryptographically-signed evidence + corroborated chain of custody)

---

### `anti-forensic` — tampering surface

| Sub-field | Type | Req | Allowed values / format | Description |
|---|---|---|---|---|
| `write-privilege` | string | no | `user`, `admin`, `service`, `system`, `kernel` | Privilege required to modify or delete the artifact. |
| `integrity-mechanism` | string | no | free text | Built-in integrity protection (e.g. "EVTX checksums", "transactional NTFS journal"). |
| `known-cleaners[]` | object[] | no | `{tool, typically-removes, note}` | Specific tooling known to wipe / tamper this artifact. |
| `survival-signals[]` | string[] | no | array | Patterns to look for when this artifact has been tampered (e.g. "sequence-id gap", "log-clear event preserved by Sysmon"). |

#### Reasoning — anti-forensic as first-class

Casey (2002, §4 *Loss*) frames evidence loss as a primary uncertainty
contributor. Treating tampering surface as authored frontmatter (rather
than prose buried in a body section) means the inspector can render it
in a structured, scannable block — and the volatility-floor / verification
slider in the legend can act on it directly.

---

### Body section (Markdown after the `---` close)

After the YAML frontmatter, the body is free-form Markdown for analyst-
facing prose. By convention the body uses the following H2 sections (none
strictly required by the schema):

- **Forensic value** — what this artifact tells you in one paragraph
- **Concept references** — bullet list mirroring the field-level `references-data`
- **Practice hint** — one hands-on exercise the analyst can run

These sections are surfaced in the inspector when the user expands the
artifact's "Details" disclosure. They're prose-grade documentation and
not consumed structurally by the build.

---

## Tier 2 — Convergence schema

**File pattern:** `convergences/<RELATION_NAME>.md`
**Purpose:** Document one Tier-2 inferential convergence — a relation
(`AUTHENTICATED_AS`, `DEVICE_CONNECTED`, `EXFILTRATED`, etc.) supported by
TWO OR MORE artifacts that share at least one join-key concept. The
convergence file declares which artifacts contribute, which concepts pivot
between them, and how strong each pivot is.

### Frontmatter — top-level fields

| Field | Type | Req | Allowed values / format | Description |
|---|---|---|---|---|
| `name` | string | yes | `UPPER_SNAKE` | Convergence relation identifier. Becomes the proposition emitted (e.g. `AUTHENTICATED_AS`). |
| `summary` | string | yes | one-line description | Human-readable summary surfaced in the inspector. |
| `yields` | object | yes | `{mode, proposition, ceiling}` | What this convergence *produces* when its inputs are corroborated. `mode` is `new-proposition` (synthesizes a new claim) or `strengthens-existing` (raises certainty on an existing one). `proposition` is the relation name (often equal to `name`). `ceiling` is the max Casey C-scale this convergence can support. |
| `inputs` | string[] | yes | array of proposition names | The Tier-1 propositions that, when present together, fire this convergence. Must reference observation propositions defined on at least one artifact. |
| `input-sources` | object[] | yes | array of `{proposition, artifacts[]}` | For each input proposition, the specific artifacts known to emit it. Used by the build to materialize the convergence's artifact set. |
| `join-chain` | object[] | yes | array of join-chain entries (see below) | The pivot concepts that thread the input artifacts together — the *substance* of the convergence. |
| `exit-node` | string[] | no | array of artifact names | Artifacts that act as terminators of inference chains starting at this convergence (e.g. `SAM`, `ProfileList`, `NTDS-dit` for identity-resolution termini). |
| `notes` | string[] | no | array of free-text notes | Per-artifact analyst notes (often "this artifact's contribution: ..."). |
| `provenance` | string[] | yes | array of source-ids from `sources.yaml` | Bibliographic backing for every claim. Should include sources for each input proposition + sources for the join-chain pivots. |

### `join-chain[]` — the convergence's substance

Each entry describes one pivot concept that links the convergence's artifacts.

| Sub-field | Type | Req | Allowed values / format | Description |
|---|---|---|---|---|
| `concept` | string | yes | concept node name | The pivot identifier (e.g. `LogonSessionId`, `UserSID`, `DeviceSerial`). |
| `concept-id` | string | no | `concept::<name>` | Pre-resolved graph id (auto-emitted by build if omitted). |
| `join-strength` | string | yes | `strong`, `weak`, `time-window` | The strength of the join. `strong` = unique deterministic identifier (LUID, SID, GUID). `weak` = name-based or context-shared (username, hostname) — needs corroboration. `time-window` = matched only by temporal proximity within bounded interval. |
| `sources` | string[] | yes | array of source-ids | The sources backing THIS specific join (not the whole convergence). |
| `primary-source` | string | yes | source-id | The single most-relevant citation for this pivot — used by the viewer's notification source-picker to render the APA citation in walkthrough steps. |
| `attribution-sentence` | string | yes | one prose sentence | The "say it in one sentence" forensic justification for *why* this concept is a valid pivot. Should explain the concept's origin (which container/field generates it), its uniqueness guarantees, and any caveats. |
| `description` | string | no | multi-paragraph free text | Extended forensic prose explaining the pivot's role across the artifacts it bridges. |
| `artifacts-and-roles` | object[] | yes | array of `{artifact, role}` | Which artifacts carry this pivot, and what role each plays (`sessionContext`, `identitySubject`, `usbDevice`, etc.). |

#### Reasoning — why convergences are derived from artifact join-key emissions

Tier-2 convergences are *not* hand-authored from scratch; their inputs are
derived by walking every Tier-1 artifact's `fields[].references-data` and
unioning the matches. The convergence file's role is to *name the pattern*
and provide forensic prose, not to enumerate the underlying artifacts —
those are computed. This separation is the formal expression of Cohen's
(2012) AFF4 object-relational pattern: relations live as their own
entities, distinct from the records they connect, so that adding a new
record automatically extends every relation it qualifies for.

#### Reasoning — `join-strength` gradations

The three-level gradation (`strong` / `weak` / `time-window`) tracks the
forensic concept of join *uniqueness*. A `strong` join (LUID, SID, GUID)
deterministically identifies the same real-world entity across records;
a `weak` join (username, hostname) may collide and requires additional
corroboration; a `time-window` join (events within ε of each other) is
the weakest — temporal proximity is necessary but not sufficient. This
gradation matches the typology in Garfinkel's *cross-drive analysis*
work, where pivot identity is rated by collision rate.

> **Sources backing this design** (full APA):
>
> Cohen, M. (2012). Building a Forensic Tool with the AFF4 Object Model. *Digital Investigation, 9*, 117–127. https://doi.org/10.1016/j.diin.2012.05.014 [⚠ NOT YET REGISTERED in `schema/sources.yaml`.]
>
> Garfinkel, S. L. (2010). Digital forensics research: The next 10 years. *Digital Investigation, 7*, S64–S73. https://doi.org/10.1016/j.diin.2010.05.009 [⚠ NOT YET REGISTERED in `schema/sources.yaml`.]
>
> Casey, E. (2002). Error, Uncertainty and Loss in Digital Evidence. *International Journal of Digital Evidence (IJDE).* https://www.utica.edu/academic/institutes/ecii/publications/articles/A0472DF7-ADC9-7FDE-C80B5E5B306A85C4.pdf — Chapter 3, on corroboration.

---

## Tier 3 — Scenario schema

> **TBD next pass.** Will document the top-level scenario fields
> (`name`, `severity`, `narrative`, `summary`, `anchors`, `join-keys`,
> `primary-artifact-ids`, `corroborating-artifact-ids`, `artifacts.primary`,
> `artifacts.corroborating`) plus the `steps[]` sub-schema (`n`, `question`,
> `artifact-ids`, `artifact-names`, `join-key`, `conclusion`, `attribution`,
> `casey`, `primary-source`, `attribution-sentence`). Reasoning section
> will cover why scenarios separate "step anchor" from "step participants"
> and the academic basis for stepwise inferential walkthroughs (drawing
> on the Toulmin argument structure as adapted by Bex & Verheij for
> evidential reasoning).

---

## Source schema (`schema/sources.yaml`)

> **TBD next pass.** Will document `id`, `author`, `year`, `title`,
> `publisher`, `url`, `apa`, `note`, `kind` (with full enum: `academic-paper`,
> `format-spec`, `standards-doc`, `event-definition`, `textbook`,
> `tool-docs`, `analyst-writeup`, `vendor-advisory`, `behavior`, `index-catalog`),
> `authority` (`primary` / `secondary`), `coverage.{substrates, artifacts,
> convergences, tier-3-applies-to}`. Reasoning section will explain why
> sources are first-class entities with their own coverage map (it lets
> the viewer pick the most-relevant citation per step automatically) and
> the kind-weighting rationale (academic > format-spec > tool-docs >
> index-catalog).

---

## Cross-references

> **TBD next pass.** Will diagram (Mermaid) and table-out:
> - Artifact `provenance[]` → Source `id`
> - Artifact `fields[].references-data[].concept` → Concept node
> - Convergence `input-sources[].artifacts[]` → Artifact `name`
> - Convergence `join-chain[].artifacts-and-roles[].artifact` → Artifact `name`
> - Convergence `join-chain[].primary-source` → Source `id`
> - Scenario `steps[].artifact-ids[]` → Artifact `name`
> - Scenario `steps[].join-key.concept-id` → Concept node
> - Scenario `steps[].primary-source` → Source `id`

---

## Datatype catalog

> **TBD next pass.** Will alphabetize every distinct datatype that
> appears in `fields[].encoding`, `fields[].kind`, `qualifier-map.*`,
> `clock`, `resolution`, etc. For each: definition, example, authoritative
> source. Initial list (to be expanded):
>
> | Datatype | Used in | Source |
> |---|---|---|
> | `sid-string` | identifier fields (UserSID, GroupSID) | MS-DTYP §2.4.2.3 |
> | `sid-binary` | binary identifier fields | MS-DTYP §2.4.2.2 |
> | `iso8601-utc` | timestamp fields | RFC 3339 / ISO 8601 |
> | `windows-filetime` | timestamp fields (FILETIME 100-ns ticks) | MS-DTYP §2.3.3 |
> | `unix-epoch-ms` | SQLite timestamp fields | POSIX.1 |
> | `hex-uint64` | LogonId, ProcessId, HandleId | (numeric, no spec) |
> | `utf-16le` | most string fields in Windows containers | Unicode 15.0 |
> | `mft-entry-reference` | NTFS join-key | Carrier, *File System Forensic Analysis* §13 |
> | `pidl` | shellbag / LNK target binary | Microsoft IShellFolder reference |
> | `casey-c-scale` | observation ceilings | Casey (2002) Table 5 |
> | `mitre-technique-id` | attribution mappings | MITRE ATT&CK Framework |

---

## Reconciliation report

> **TBD next pass.** Auto-generated from a survey pass over the corpus +
> grep over `viewer/index.html` consumption sites. Will list:
>
> - **Authored-but-never-consumed**: fields appearing in artifact
>   frontmatter but never read by the viewer (likely typos or stale
>   schema; cleanup candidates).
> - **Consumed-but-never-authored**: fields the viewer reads via
>   `node["..."]` but no artifact actually authors (likely stale code;
>   cleanup candidates).
> - **Documented-but-not-in-corpus**: fields documented in this reference
>   but not yet present in any authored artifact (forward-looking, or
>   vestigial from earlier schema).

---

## Versioning + change protocol

This document is the **single source of truth** for the schema. The
authoring workflow is:

1. Propose a schema change in this document first.
2. Update the JSON-Schema files under `schema/*.schema.json`.
3. Update the build pipeline (`tools/build_graph.py`).
4. Author or migrate any affected `.md` files.
5. Verify the viewer still consumes the updated structure.

Changes to this document should preserve the academic-reasoning + source-
support pattern: every new field gets both a "what" and a "why," with a
citation backing the design choice. Fields without academic backing are
acceptable but should be flagged (`*reasoning: pragmatic / convention*`) so
the gap is visible.

---

*Document maintained as part of the 2026-04-24 cleanup process. Tier 1
section authored from a survey of `artifacts/windows-evtx/Security-4625.md`
+ frontmatter conventions across `artifacts/**/*.md`. Subsequent passes will
expand Tiers 2 + 3, the source schema, the datatype catalog, and the
reconciliation report.*

---

## AI assistance disclosure

This document and the broader ArtifactExplorer viewer codebase were developed in
collaboration with **Claude Opus 4.7 (1M context)**, an Anthropic large
language model. The collaboration pattern was as follows:

- **Human (project owner)** specified every design decision, schema choice,
  forensic framing, and acceptance criterion. The Casey C-scale adoption,
  the three-tier model, the join-key emission pattern at the field level,
  and every authoring policy in the corpus are human-originated decisions.
- **AI (Claude)** assisted with code generation (viewer JavaScript, CSS,
  HTML), draft text for documentation including this schema reference,
  candidate APA citation formatting, and exploratory implementation
  proposals. All AI-generated code was reviewed and accepted by the human
  before integration. All AI-suggested citations must be independently
  verified by the human against the underlying primary sources before
  use in any external publication.
- **Verification responsibility** lies with the human. AI-generated
  citations to academic sources (Casey 2002, Casey 2020, Carrier 2003,
  Cohen 2012, etc.) are starting points; readers and downstream authors
  must check each citation against the original publication. The
  registered sources in `schema/sources.yaml` are the verified subset.

### Citing this document or the viewer

If you cite SCHEMA.md, the ArtifactExplorer viewer, or any AI-collaborated component
of this project in academic work, the recommended pattern is:

**APA 7th edition — reference list entry:**

> Anthropic. (2026). *Claude Opus 4.7 (1M context)* [Large language model]. https://claude.ai/

**APA 7th edition — in-text citation:**

> (Anthropic, 2026)

**Methods / acknowledgements paragraph (template):**

> The schema documentation and viewer implementation were authored in
> collaboration with Claude Opus 4.7 (Anthropic, 2026). The author
> specified all design decisions, independently verified all source
> citations against their primary publications (Casey, 2002; Casey,
> 2020; etc.), and reviewed all generated code before integration. AI
> assistance is acknowledged per the journal's AI-use policy.

### Journal-specific notes

- Most digital-forensics journals (FSI:DI, *Digital Investigation*, JoDI,
  DFRWS proceedings) updated their editorial policies in 2023–2024 to
  **require an AI-use disclosure** in the methods or acknowledgements
  section. AI is not an author under any of these policies (consistent
  with ICMJE, APA, Nature, Science, and IEEE policies as of 2026).
- For Casey-style certainty assertions specifically: treat AI-generated
  forensic reasoning as Casey C2–C3 by default until corroborated
  against primary sources. The schema reasoning notes in this document
  cite primary sources as starting points — independent verification
  is required before they support any C4+ claim downstream.

---
