# ArtifactExplorer Architecture

Lock-in spec for the project's data model. The restructure commits (B through J) implement against this document; if there is a conflict between this doc and later implementation, the doc wins and the implementation is wrong.

Subsequent rounds of refinement update this doc first, then the code.

---

## Purpose

ArtifactExplorer is a **training corpus** for tier-3 DFIR analysts. Its job is to encode forensic knowledge as structured, cross-referenced data that a viewer can render as an interactive graph and that an analyst can use to reason about investigative chains.

The data model separates two concerns that DFIR community vocabulary conflates:

1. **Where evidence lives and what format it takes** (the substrate axis).
2. **What forensic knowledge is asserted and at what abstraction level** (the tier axis).

These two axes are orthogonal. An artifact lives somewhere on the substrate axis; its forensic claims live on the tier axis; the same substrate artifact participates at multiple tiers.

---

## The two orthogonal axes

```
                         TIER AXIS
                            ↑
                  ┌─────────────────────┐
          Tier 3  │      SCENARIO       │  reusable story of a forensic
                  │                     │  relationship between 2+ exit-nodes
                  ├─────────────────────┤
          Tier 2  │    CONVERGENCE      │  multi-artifact join via shared
                  │                     │  identifier-concept values
                  ├─────────────────────┤
          Tier 1  │    OBSERVATION      │  single-artifact claim:
                  │                     │  one proposition + one ceiling
                  └─────────────────────┘
                            │
                            │  observations attach to artifacts
                            │
                  ┌─────────────────────┐
                  │      ARTIFACT       │  the compound forensic knowledge
                  │                     │  unit (fields + substrate binding)
                  ├─────────────────────┤
                  │  SUBSTRATE-INSTANCE │  specific named instance (e.g.,
                  │                     │  'Security', 'NTUSER.DAT')
                  ├─────────────────────┤
                  │      SUBSTRATE      │  format family (e.g.,
                  │                     │  windows-evtx, windows-registry-hive)
                  ├─────────────────────┤
                  │   SUBSTRATE-CLASS   │  access-method category (e.g.,
                  │                     │  Registry, Event Log, Database)
                  └─────────────────────┘
                         SUBSTRATE AXIS →
```

Read the axes independently. Artifacts + substrate describe *what* and *where*. Tiers describe *what you can conclude*.

---

## The substrate axis

Three levels, each a generalization of the one below. Each artifact binds itself to a specific point in this axis.

### Substrate-class

The broadest access-method category. Eight values:

`Registry`, `Event Log`, `Text Log`, `Database`, `Filesystem Metadata`, `Filesystem Artifact`, `Disk Metadata`, `Application Cache`.

A substrate-class determines the **parsing approach**. Registry artifacts are parsed by hive parsers; Event Log artifacts by EVTX parsers; Database artifacts by the appropriate database engine.

Declared on substrate files as `substrate-class:`.

### Substrate

A specific substrate family. Fifteen values, all prefixed `windows-`:

```
windows-binary-cache        windows-ntfs-metadata    windows-recyclebin
windows-disk-metadata       windows-prefetch         windows-registry-hive
windows-ess                 windows-pst              windows-sqlite
windows-evtx                windows-jumplist         windows-text-log
windows-fat-metadata        windows-lnk              windows-thumbcache
```

A substrate determines the **exact format and parsers**. windows-evtx and windows-registry-hive are both under Registry-ish / Event-Log-ish substrate-classes, but have completely different binary formats and different parsers.

Declared on artifact files as `substrate:`. Each value must resolve to a file under `substrates/<value>.md`.

### Substrate-instance

A specific named instance of a substrate. Examples: the `Security` channel of windows-evtx, the `NTUSER.DAT` hive of windows-registry-hive, the `History` database of windows-sqlite.

Declared on artifact files as `substrate-instance:`. Free-form — naming is validated informally against the substrate file's known-instances list if present.

### Substrate files

Each substrate has a file at `substrates/<substrate>.md` declaring:

- `name:` (must match filename stem)
- `substrate-class:` (one of the 8 values above)
- `kind:` (technical format enum: `binary-structured-file`, `plaintext-log`, `sqlite-database`, `ese-database`, `database-file`, `filesystem-metadata`, `disk-region`, `disk-substrate`)
- `format:`, `structure:`, `parsers:`, `persistence:`, `retention:`, `known-instances:`, etc. (descriptive metadata)

The substrate file is substrate-about — it doesn't make forensic claims. Forensic claims live on artifacts.

---

## The tier axis: Tier 1 — Observations

### Definition

An **observation** is a single-artifact forensic claim: *this artifact, on its own, using these specific fields, can defend this one proposition at this one Casey-ceiling level, assuming these preconditions hold.*

Observations are **atomic**. A multi-artifact claim is a tier-2 convergence, not an observation.

### Schema shape

`observations:` is a top-level list on every artifact file. Each entry:

```yaml
observations:
- proposition: AUTHENTICATED            # UPPER_SNAKE verb-past-participle
  ceiling: C4                            # Casey C-scale; patterns: C1..C5, C3-C4, "C3 (with corroboration)"
  confidence: established                # NEW: established | debated | preliminary | unverified
  debate-note: "..."                     # optional; present when confidence == debated
  note: "..."                            # narrative justification / caveats
  qualifier-map:                         # binds proposition slots to artifact field values
    principal: field:target-user-sid
    target: this-system                  # literal value; no field: prefix
    method: field:authentication-package
    time.start: field:time-created
  preconditions:                         # assumptions required for the claim to hold
  - "Security.evtx retained (no 1102)"
  - "Logon success auditing enabled"
```

### Proposition

A named type. UPPER_SNAKE verb-past-participle (`AUTHENTICATED`, `CONFIGURED`, `EXISTS`, `CREATED`, `EXECUTED`, `PERSISTED`, `CONNECTED`). Multiple artifacts may claim the same proposition; that's what makes tier-2 convergence possible.

The proposition's **slots** (e.g., AUTHENTICATED has `principal`, `target`, `method`, `time.start`) are implicitly declared by usage and filled via `qualifier-map:`.

### Ceiling (Casey C-scale)

Pattern: `^C[1-5](?:[–-]C[1-5])?(?:\s*\(.+\))?$`. Allows `C1`–`C5`, ranges (`C3–C4`), optional parenthetical qualifiers. In practice the corpus uses C2 through C4.

| Level | Meaning |
|---|---|
| C2 | Plausible; single-data-point; can't exclude benign explanation |
| C3 | Probable; this combined with context establishes the claim |
| C4 | Near-certain from this artifact alone (kernel-logged, integrity-backed, cryptographically bound) |

C1 (trace) and C5 (courtroom-direct) are defined by the schema but unused by convention. Claims at C5 require tier-2 convergence rather than single-artifact assertion.

### Confidence

Added in this restructure. Orthogonal to ceiling. Answers: *what is the epistemological status of the source knowledge supporting this claim?*

| Value | Meaning |
|---|---|
| `established` | strong consensus among forensic literature / practitioners |
| `debated` | supported but contested; cite specific disagreements in `debate-note:` |
| `preliminary` | limited or emerging evidence; may change as the field matures |
| `unverified` | no strong backing found; included for completeness, treat carefully |

Default is `established`. A `C4, established` claim is canonical. A `C3, debated` claim signals the practitioner community doesn't uniformly agree on how to read this evidence.

### Qualifier-map

Binds each slot of the proposition to either:

- **A field reference**: `field:<field-name>` — looks up the named entry in the same artifact's `fields:` list. The slot value is whatever runtime value that field carries on any given record.
- **A literal**: any non-`field:`-prefixed string. Used when the slot value is fixed by the artifact's context of acquisition (e.g., `target: this-system` on a logon event — the target is always the host that produced the evtx).

### Preconditions

Narrative assumptions required for the claim to hold. Free-text list. The build tool doesn't interpret preconditions; they exist for the analyst to verify before trusting the claim.

---

## The tier axis: Tier 2 — Convergences

### Definition

A **convergence** is a multi-artifact join: *when these artifacts all carry the same identifier-concept value in their fields, joined through this chain of concept-role pivots, they jointly yield a higher-order forensic claim.*

Tier 2 is where forensic chains live. The shared identifier-concept value is the join key; the resulting claim is stronger than any individual artifact's tier-1 observation.

### Schema shape

One file per convergence at `convergences/<name>.md`:

```yaml
name: usb-user-attribution
summary: "From a recovered USB device identity to the specific user account that mounted it."

join-chain:                                   # ordered list of concept-role pivots
  - concept: DeviceSerial                     # must be identifier-kind
    artifacts-and-roles:
      - artifact: USBSTOR
        role: usbDevice
      - artifact: MountedDevices
        role: usbDevice
  - concept: VolumeGUID
    artifacts-and-roles:
      - artifact: MountedDevices
        role: mountedVolume
      - artifact: MountPoints2
        role: accessedVolume
  - concept: UserSID
    artifacts-and-roles:
      - artifact: MountPoints2
        role: profileOwner

exit-node: UserSID                            # terminal of the chain; must be identifier concept OR flagged exit-node artifact

yields:                                       # dual-mode: new-proposition OR ceiling-elevation
  mode: new-proposition                       # 'new-proposition' | 'ceiling-elevation'
  proposition: USED                           # required when mode == new-proposition
  ceiling: C3 (with corroboration)
  # OR, for ceiling-elevation mode:
  # mode: ceiling-elevation
  # elevates-proposition: CONNECTED
  # ceiling: C3 (with corroboration)
  # corroboration-strength: independent-subsystem     # 'independent-subsystem' | 'same-subsystem'

degradation-paths:
  - if-missing: MountPoints2
    fallback-artifact: EMDMgmt
    ceiling-drop: "C3 → C2"
    note: "..."
```

### Join-chain

Ordered list. Each step names a concept (which must be identifier-kind per the registry) and the artifacts + roles that bind it.

Walking the chain resolves a forensic pivot: from the first artifact's binding through the shared concept values to the last artifact's binding. The chain terminates at the `exit-node:`.

### Dual-mode yields

Convergences produce either:

- **A new higher-level proposition.** The convergence asserts something that no individual input artifact asserted (`USED`, `PERSISTED`, `EXFILTRATED`, `ACCESSED_REMOTELY`). Mode: `new-proposition`.
- **Ceiling elevation on an existing proposition with corroboration.** Two or more artifacts independently assert the SAME proposition; their agreement raises confidence without creating a new claim. Mode: `ceiling-elevation`. Requires `corroboration-strength:` — `independent-subsystem` (different OS component produced each observation) carries more weight than `same-subsystem`.

Both modes are first-class. A convergence declares which mode it operates in.

### Exit-node

The concept or artifact at which the join-chain terminates and attribution lands. Must be one of:

- an identifier-kind concept (by definition, identifier values resolve to real-world entities), OR
- an artifact whose frontmatter flags `exit-node: true` (manual curatorial judgment that the artifact directly terminates attribution without needing a further concept hop).

The exit-node is the forensic endpoint of the convergence — where an analyst's pivot lands.

### Degradation-paths

Explicit fallbacks when intermediate artifacts are missing (cleaner was run, acquisition incomplete, etc.). Each path declares what artifact is missing, what fallback to use, and what ceiling drop to expect.

Degradation paths encode the forensic reality that partial chains still yield partial attribution, at reduced confidence.

---

## The tier axis: Tier 3 — Scenarios

### Definition

A **scenario** is a reusable forensic story: *a pattern of 2+ exit-node anchors connected by a sequence of convergences, that can be instantiated against any investigation matching the pattern.*

Scenarios are templates. A specific case is an instance of a scenario pattern; the scenario itself describes the reusable shape.

Every scenario has **at least two exit-node anchors** — one entry, one or more conclusions. A single-anchor "scenario" is actually a query, not a story; queries are handled by separate graph-interaction features, not by the scenarios schema.

### Schema shape

One file per scenario at `scenarios/<name>.md`:

```yaml
name: Departing employee — USB exfiltration with cleanup
severity: playbook
summary: "..."
narrative: |
  ...multi-paragraph framing of the story pattern...

anchors:
  entry: MFTEntryReference                   # where the investigation starts; must be exit-node
  conclusions:                               # one or more conclusion-anchors; each must be exit-node
    - UserSID                                # primary attribution
    - ServiceName                            # optional secondary conclusion (branching scenarios)

steps:
  - n: 1
    question: "Was the session authenticated during the exfil window?"
    convergence: auth-session-window          # references convergences/auth-session-window.md
    conclusion: "LogonSessionId anchors the acting window."
    casey: C4
  - n: 2
    question: "Was a USB device connected?"
    convergence: usb-user-attribution
    conclusion: "Device identity tied to user's session."
    casey: C3
  # ...more steps...
```

### Anchors

Required. Minimum total of 2 anchor references (1 entry + ≥1 conclusion). Each reference must name an exit-node (identifier concept or flagged artifact).

- `entry:` is singular — one investigative starting point.
- `conclusions:` is a list of one or more — accommodates both linear (one conclusion) and branching (multiple conclusions) scenarios.

### Steps

Ordered list. Each step:

- Poses a forensic question (`question:`).
- References a convergence (`convergence:`) that answers it.
- Declares the conclusion reached at that step (`conclusion:`).
- Carries a Casey ceiling for the step (`casey:`).

The step's convergence brings its own inputs, join-chain, and exit-node. The scenario chains steps into a walk across the graph.

---

## Cross-cutting elements

These apply across tiers or across substrate/tier axes.

### Concepts — the join-key vocabulary

A **concept** is a named typed data-class that artifacts reference from their fields via `references-data: [{concept, role}]`.

Concept files live in `concepts/<Name>.md`. The registry at `schema/concepts.yaml` declares the authoritative set of concepts and their valid roles.

Every concept has a `kind:`:

- **`identifier`** — values are forensically unique per real-world entity. A specific SID resolves to exactly one user. A specific VolumeGUID to exactly one mounted volume. Identifier concepts anchor tier-2 convergences; their values **are** the join keys.
- **`value-type`** — values are reusable labels or types without unique real-world identity. ExecutablePath values vary per-executable; URL values per-URL; ExecutableHash values per-content. Value-types can be referenced for categorical filtering and context but cannot anchor convergences.

The identifier vs value-type distinction is load-bearing. Convergence `join-chain` is mechanically restricted to identifier concepts by the validator.

### Concept lifetime

Added in this restructure. Declares how long instances of a concept persist. Four values matching the volatility axis:

- `permanent` — survives reboot and device lifetime (UserSID, DeviceSerial, VolumeGUID, MFTEntryReference, GPTPartitionGUID)
- `persistent` — survives reboot but admin-mutable (ServiceName, TaskName, MachineNetBIOS)
- `session-scoped` — lifetime bounded by a boot / login session (LogonSessionId)
- `runtime` — lifetime bounded by a process or handle (reserved for value-type concepts like the former ProcessId/HandleId)

Declared as top-level `lifetime:` on concept files.

### Exit-nodes

An exit-node is a graph node where a forensic chain terminates because it has resolved to a specific real-world entity. Two sources:

- **Derived:** every identifier-kind concept is automatically an exit-node. By definition, an identifier value resolves to one entity.
- **Manual:** artifacts may self-flag `exit-node: true` in frontmatter for curatorial cases where the artifact itself terminates attribution without a concept hop.

Exit-nodes are the **attribution terminals** of the tier model. Convergences terminate at exit-nodes; scenarios walk from one exit-node to another (or to several in branching scenarios).

### Volatility

Added in this restructure. Declares how long evidence naturally persists, independent of adversarial behavior. Top-level `volatility:` on artifacts; four values:

- `permanent` — evidence survives reboot, reformat, typical deletion — requires destructive action to remove (cryptographic wipe, hardware replacement)
- `persistent` — survives reboot and normal use but is mutable by admin or removable by cleaners / reformat
- `session-scoped` — lifetime bounded by a logon session or boot; lost on logoff/reboot
- `runtime` — lifetime bounded by a process or handle; lost on process exit

Volatility differs from adversarial tamper. A volatile artifact is easy to lose even without an adversary. The anti-forensic axis covers tamper behavior separately.

### Interaction-required

Added in this restructure. Declares whether an artifact's creation requires user involvement. Top-level `interaction-required:` on artifacts; three values:

- `none` — written by kernel or system service without any user being logged in or active (USBSTOR, PartitionDiagnostic-1006)
- `user-session` — requires a logged-in user session but no specific user action (System events with SubjectLogonId)
- `user-action` — requires the user to actively interact (MountPoints2 requires Explorer interaction; RecentDocs requires opening a file)

This is orthogonal to `link:` (investigative story). Two artifacts with `link: device` can differ sharply in `interaction-required:` — USBSTOR is `none`, MountPoints2 is `user-action`. The distinction matters for ordering a forensic chain: chains start at `interaction-required: none` artifacts (system-level anchors) and progress to `user-action` artifacts (user-attribution).

### Anti-forensic metadata

Unchanged in intent; clarified in structure. Per-artifact `anti-forensic:` block:

- `integrity-mechanism:` — how the substrate defends its records (append-only, kernel-mediated, none)
- `write-privilege:` — what privilege is required to modify (admin, user, service, kernel-only). Renamed from the old free-text `mutability:` field, which conflated lifetime and write-privilege.
- `known-cleaners:` — list of tools that target this artifact
- `survival-signals:` — patterns that reveal tamper even after cleanup

The former `mutability:` field is removed; its lifetime content moves to top-level `volatility:` and its privilege content moves to `write-privilege:`.

### Links (investigative story)

Unchanged. The `link:` and optional `link-secondary:` fields classify each artifact's primary investigative story. Eleven values: `user`, `device`, `system`, `system-state-identity`, `network`, `security`, `persistence`, `application`, `file`, `memory`, `evasion`. See `docs/nomenclature.md` for detailed per-value semantics.

---

## Field reference — top-level artifact frontmatter

Consolidated list after the restructure:

```yaml
# Identity
name: <string>
title-description: <string>
aliases: [<string | integer>, ...]

# Investigative story axis
link: <enum>
link-secondary: <enum>
tags: [<string>, ...]

# Substrate axis
substrate: <enum-of-15>                      # was container-class
substrate-instance: <string>                 # was container-instance
platform: { ... }
location: { ... }

# Data
fields: [ { name, kind, location, encoding, references-data: [{concept, role}], ... }, ... ]

# Tier-1 claims
observations:                                # was supports
- proposition: <UPPER_SNAKE>
  ceiling: <C-scale>
  confidence: <established|debated|preliminary|unverified>
  debate-note: <string>                      # optional
  note: <string>
  qualifier-map: { <slot>: field:<name> | <literal> }
  preconditions: [<string>, ...]

# Cross-cutting lifetime + interaction axes
volatility: <permanent|persistent|session-scoped|runtime>
interaction-required: <none|user-session|user-action>

# Tamper / anti-forensic
anti-forensic:
  integrity-mechanism: <string>
  write-privilege: <admin|user|service|kernel-only>
  known-cleaners: [ { tool, typically-removes, ... }, ... ]
  survival-signals: [<string | object>, ...]

# Exit-node flag (manual)
exit-node: <boolean>                         # default false; identifier concepts don't need this flag

# Bibliography
sources: [ { author, year, title, url, note }, ... ]
```

Top-level on **substrate** files:

```yaml
name: <string>
substrate-class: <enum-of-8>                 # was source-class
kind: <technical-format-enum>
format: { ... }
structure: { ... }
parsers: [ ... ]
persistence: { ... }
retention: { ... }
known-instances: [ ... ]
anti-forensic-concerns: [ ... ]
```

Top-level on **concept** files:

```yaml
name: <string>
kind: <identifier|value-type>
lifetime: <permanent|persistent|session-scoped|runtime>
link-affinity: <enum>
description: <string>
canonical-format: <string>
aliases: [<string>, ...]
roles: [ { id, description } ]
known-containers: [ <artifact-name>, ... ]
```

Top-level on **convergence** files (new):

```yaml
name: <string>
summary: <string>
join-chain: [ { concept, artifacts-and-roles: [{artifact, role}] }, ... ]
exit-node: <concept-name | artifact-name>
yields:
  mode: <new-proposition|ceiling-elevation>
  # new-proposition mode:
  proposition: <UPPER_SNAKE>
  ceiling: <C-scale>
  # ceiling-elevation mode:
  elevates-proposition: <UPPER_SNAKE>
  corroboration-strength: <independent-subsystem|same-subsystem>
degradation-paths: [ { if-missing, fallback-artifact, ceiling-drop, note }, ... ]
```

Top-level on **scenario** files:

```yaml
name: <string>
severity: <reference|playbook|case-study>
summary: <string>
narrative: <string>
anchors:
  entry: <concept-name | artifact-name>      # must be exit-node
  conclusions: [<exit-node-name>, ...]       # one or more; total anchors (entry + conclusions) >= 2
steps:
- n: <int>
  question: <string>
  convergence: <convergence-name>
  conclusion: <string>
  casey: <C-scale>
```

---

## Directory and file layout (after restructure)

```
ArtifactExplorer/
├── artifacts/
│   └── <substrate>/<artifact-name>.md
├── substrates/                              # was containers/
│   └── <substrate>.md
├── concepts/                                # was forensic-data/
│   └── <concept>.md
├── convergences/                            # NEW
│   └── <convergence>.md
├── scenarios/
│   └── <scenario>.md
├── schema/
│   ├── artifact.schema.json
│   ├── substrate.schema.json                # was container.schema.json
│   ├── concept.schema.json
│   ├── convergence.schema.json              # NEW
│   ├── scenario.schema.json
│   └── concepts.yaml
├── tools/                                   # build, validate, serve
├── viewer/                                  # index.html + data.json
└── docs/
    ├── architecture.md                      # this file
    └── nomenclature.md                      # detailed naming conventions
```

---

## Deferred for future rounds

The following are acknowledged design concerns not included in this restructure. They are schema-extensible — future commits can add them without breaking the model described here.

1. **Bridge-artifact property.** Derived-at-build property flagging artifacts whose fields bind two or more distinct identifier concepts in one record (Partition/Diagnostic 1006 binds DeviceSerial + Volume-related identity simultaneously). No schema change, just a derived field for query/rendering.

2. **Structured common-errors frontmatter.** Currently common errors live in artifact prose bodies. A structured `common-errors:` list would make them filterable / queryable / renderable in the viewer.

3. **Per-timestamp-field temporal-precision.** Some timestamp fields are kernel-event-precise; others reflect "some Explorer shell write" with imprecise semantics. A `temporal-precision:` field on timestamp `fields[*]` would encode this.

4. **Scope labels on identifier concepts.** Visual / Inspector communication that inferences from an identifier concept are scoped to one specific entity. Deferred per explicit user decision.

5. **Edge styling by volatility tier.** Line style + opacity encoding on graph edges derived from min-endpoint volatility. Companion to the volatility slider.

6. **Tier-2-as-edges graph topology.** Rendering artifact↔artifact edges directly for identifier-concept joins, with concepts as edge attributes rather than concept-hub nodes. Fundamental graph-view redesign.

7. **Rich exit-node entity-kind typing.** Declaring what kind of real-world entity an exit-node resolves to (human, device, volume, session, file, config-entity, namespace). A new enum field on exit-node declarations.

8. **Radial-exploration as a separate graph feature.** Single-node-focus exploration ("show me everything connected to this node, dim everything else") is a graph-interaction feature, not a scenario. Deferred to viewer work.

---

## Vocabulary lock-in

After this document, the following terms have fixed meanings:

| Term | Fixed meaning |
|---|---|
| artifact | compound forensic knowledge unit at `artifacts/<substrate>/<name>.md`; carries fields + observations |
| substrate | format family (one of 15 values); declared via artifact `substrate:` field; defined at `substrates/<name>.md` |
| substrate-class | access-method category (one of 8 values); declared on substrate files |
| substrate-instance | named instance of a substrate (free-form, usually acquisition-target name) |
| concept | named join-key-vocabulary entry at `concepts/<Name>.md` |
| identifier concept | concept with `kind: identifier`; values uniquely resolve to real-world entities |
| value-type concept | concept with `kind: value-type`; values are reusable labels |
| join key | an identifier-concept value (runtime instance). Informal term; not a schema field. |
| observation | tier-1 single-artifact claim; a `supports:` entry renamed to `observations:` |
| convergence | tier-2 multi-artifact join, first-class file at `convergences/<name>.md` |
| scenario | tier-3 reusable forensic story, first-class file at `scenarios/<name>.md` |
| exit-node | graph node where a forensic chain terminates; identifier concept OR flagged artifact |
| anchor (scenario) | exit-node serving as entry or conclusion of a scenario; minimum 2 per scenario |
| volatility | natural evidence-lifetime tier; axis independent of tamper-posture |
| interaction-required | axis declaring whether artifact creation needs user involvement |
| confidence | epistemic status of an observation's source knowledge; orthogonal to Casey ceiling |
| ceiling | Casey C-scale certainty level for an observation's claim |
| write-privilege | on anti-forensic: what privilege is needed to modify the evidence |

Terms deliberately NOT used in the schema:

- **container, container-class, container-instance** — deprecated; renamed to substrate / substrate-class / substrate-instance.
- **source-class** — deprecated; renamed to substrate-class.
- **supports** — deprecated; renamed to observations.
- **mutability** — deprecated; split into top-level `volatility:` and anti-forensic `write-privilege:`.
- **terminus** — briefly considered; rejected in favor of `exit-node:` for vocabulary consistency.

---

## Versioning

Pre-1.0. Versioning uses fixed annotated tags at structural inflection points, plus a rolling `latest-stable` tag that moves forward with any clean-state commit.

### Tag scheme

- **Fixed tags**: `vN-descriptor` (e.g., `v1-phase2-clean`, `v2-tier-model`). Each N bumps at a structural inflection — vocabulary rename, schema shape change, new file type. Each tag is annotated with a message describing what the inflection was. Tags never move.
- **Rolling tag**: `latest-stable`. Points at the most recent clean state (validator 0/0, build 0 warnings, no open regressions). Moves forward with each clean commit.
- **Post-1.0** (when the corpus is ready to be referenced externally): switch to standard semver. `v1.0.0` is the first stable release; breaking schema changes earn a major bump; content additions earn a minor bump.

### When to branch vs. commit-direct

The project is solo and pre-1.0. Two workflow patterns:

- **Branch-per-version** — use when the change touches schema shape, directory structure, vocabulary, or spans multiple commits whose intermediate states aren't self-consistent. Branch name follows `refactor/<descriptor>`. Merge to master with `--no-ff` so the branch topology is preserved. Merge commit earns a new fixed tag. Examples: the tier-model restructure (commits A-J on `refactor/tier-model`), the sidebar refactor (`refactor/sidebar`).
- **Commit directly to master + advance `latest-stable`** — use for data-only or self-contained work: authoring a new artifact, filling in a convergence's `join-chain:`, marking an observation as `debated`, resolving a `write-privilege: unknown`. No branch ceremony; validator + build must be clean after each commit.

The discriminator: does the change require me to think about schema/structure, or just to type forensic knowledge into existing slots? First → branch. Second → direct.

Most items in `docs/deferred.md` are direct-commit work against the v2-tier-model schema; a handful (tier-2-as-edges graph topology, structured common-errors frontmatter, rich exit-node entity-kind typing) are branch-per-version work that would earn a new fixed tag on merge.
