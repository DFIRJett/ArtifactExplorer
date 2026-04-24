"""
Shared parsing layer for ArtifactExplorer graph tools.

Model (v0.3):
  - Artifact = a registry key / file / log / etc. that carries forensic data
  - Concept  = a shared forensic data type (VolumeGUID, DeviceSerial, UserSID, ...)
               referenced by multiple artifacts
  - An artifact's field declares `references-data: [ConceptName, ...]`
  - Each concept's file declares `known-containers: [ArtifactName, ...]`
  - Graph edges: artifact → concept (one per reference)
  - Ghost artifact: a concept's known-container that isn't yet written as an artifact file

Requires: pip install pyyaml
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required. Install with: pip install pyyaml")


ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = ROOT / "artifacts"
SUBSTRATES_DIR = ROOT / "substrates"
CONCEPTS_DIR = ROOT / "concepts"
SCHEMA_DIR = ROOT / "schema"
SCENARIOS_DIR = ROOT / "scenarios"
CONVERGENCES_DIR = ROOT / "convergences"
VIEWER_DIR = ROOT / "viewer"

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---", re.DOTALL)


def _resolve_exit_node(raw) -> bool:
    """Exit-node frontmatter accepts boolean (legacy) OR structured dict.
    For dicts, truthiness comes from `is-terminus`, not the dict's non-emptiness."""
    if isinstance(raw, dict):
        return bool(raw.get("is-terminus", False))
    return bool(raw)


def _exit_node_field(raw, key: str) -> str:
    """Pull a named string field out of the structured exit-node dict
    (e.g. `attribution-sentence`, `primary-source`). Returns "" if the
    frontmatter uses the legacy boolean form or the key is absent."""
    if isinstance(raw, dict):
        v = raw.get(key)
        return "" if v is None else str(v)
    return ""


def _read_frontmatter(path: Path) -> dict | None:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="utf-8-sig")
    m = FRONTMATTER_RE.match(text)
    if not m:
        return None
    return yaml.safe_load(m.group(1)) or {}


@dataclass
class ConceptRef:
    """An artifact field's reference to a shared concept."""
    artifact: str
    field: str
    concept: str
    role: str = "unspecified"  # semantic role this instance of the concept plays
    match_note: str = ""      # optional note (e.g., "USB-case encoding only")


@dataclass
class Concept:
    name: str
    kind: str = "identifier"
    link_affinity: str = ""
    link_affinity_secondary: str = ""  # optional — enables bi-color rendering
    description: str = ""
    canonical_format: str = ""
    aliases: list[str] = field(default_factory=list)
    known_containers: list[str] = field(default_factory=list)
    roles: list[dict] = field(default_factory=list)   # [{id, description}, ...]
    lifetime: str = ""   # permanent | persistent | session-scoped | runtime
    source_path: Path | None = None

    def role_ids(self) -> set[str]:
        return {r.get("id", "") for r in self.roles if r.get("id")}


@dataclass
class Artifact:
    name: str
    link: str = ""
    link_secondary: str = ""   # optional — enables bi-color rendering (same scheme as concepts)
    tags: list[str] = field(default_factory=list)
    container_class: str = ""
    container_instance: str = ""
    substrate_hub: str = ""  # H-018 Item 2 — curated forensic grouping label (User scope / NTFS Core / etc.)
    location_path: str = ""
    aliases: list[str] = field(default_factory=list)
    platform: dict = field(default_factory=dict)
    fields: list[dict] = field(default_factory=list)
    observations: list[dict] = field(default_factory=list)
    anti_forensic: dict = field(default_factory=dict)
    survival_edges: list[dict] = field(default_factory=list)
    exit_node: bool = False    # explicit forensic judgment — not derived from ceiling
    exit_attribution_sentence: str = ""  # verbatim sentence from primary-source justifying the terminus claim (audit artifact)
    exit_primary_source: str = ""        # single source id identified during exit-node audit as strongest attribution
    volatility: str = ""            # permanent | persistent | session-scoped | runtime
    interaction_required: str = ""  # none | user-session | user-action
    title_description: str = ""  # human-readable event title (e.g. "An account was successfully logged on")
    # Provenance IDs referencing schema/sources.yaml. Each entry is either
    # a bare ID string or an object {source, section?, note?}. The viewer
    # resolves IDs against the sources registry at render time.
    provenance: list = field(default_factory=list)
    source_path: Path | None = None

    def timestamp_fields(self) -> list[dict]:
        return [f for f in self.fields if f.get("kind") == "timestamp"]

    def concept_refs(self) -> list[tuple[str, str, str]]:
        """Return (field-name, concept-name, role) tuples from references-data declarations.

        Accepts two formats for backward compatibility:
          - list of strings: references-data: [ConceptA, ConceptB]   → role="unspecified"
          - list of dicts:   references-data:
                               - concept: ConceptA
                                 role: roleId
        """
        out: list[tuple[str, str, str]] = []
        for fld in self.fields:
            refs = fld.get("references-data") or []
            if isinstance(refs, str):
                refs = [refs]
            for c in refs:
                if isinstance(c, dict):
                    concept = c.get("concept", "")
                    role = c.get("role", "unspecified")
                    if concept:
                        out.append((fld.get("name", ""), concept, role))
                elif isinstance(c, str):
                    out.append((fld.get("name", ""), c, "unspecified"))
        return out


@dataclass
class Container:
    """A substrate/format definition (registry hive, EVTX file, SQLite db, ...)
    that hosts artifacts. Container files live in substrates/*.md and declare
    their own roster of authored + unwritten child artifacts via
    `known-artifacts:` frontmatter."""
    name: str
    source_class: str = ""
    known_artifacts: list[str] = field(default_factory=list)   # combined authored + unwritten names
    unwritten_details: list[dict] = field(default_factory=list)  # unwritten entries with per-item metadata
    # instance_implications[container_instance] = list of {concept, role, rationale}
    # Concepts that the substrate imposes on every artifact with this substrate-instance,
    # independent of per-artifact declarations. E.g., NTUSER.DAT → UserSID:profileOwner.
    instance_implications: dict = field(default_factory=dict)
    source_path: Path | None = None


@dataclass
class Scenario:
    """A real-world forensic use-case that exercises multiple join keys across
    multiple artifacts. Visual overlay surfaces: highlights the participating
    artifact nodes + the concept nodes acting as join keys; dims the rest.

    A scenario may OPTIONALLY declare a stepwise progression via `steps`
    (see xlsx-derived convergence chains). Each step names the artifacts
    that answer one investigative question plus the single join key that
    threads that step to the prior conclusion. The viewer renders steps
    as a scrollable list with per-artifact hover-highlight back onto the
    main graph."""
    name: str
    severity: str = ""
    summary: str = ""
    narrative: str = ""
    # Ordered list of {concept: name, role: role} — the join keys that thread
    # this scenario's artifacts together.
    join_keys: list[dict] = field(default_factory=list)
    primary_artifacts: list[str] = field(default_factory=list)
    corroborating_artifacts: list[str] = field(default_factory=list)
    # Optional stepwise structure. Each entry carries:
    #   n (int), question (str), artifacts (list[str]),
    #   join-key ({concept, role}), conclusion (str),
    #   attribution (str), casey (str)
    steps: list[dict] = field(default_factory=list)
    # Anchors — {entry: <exit-node>, conclusions: [<exit-node>, ...]}. Minimum
    # 2 anchors total (entry + ≥1 conclusion). Every anchor must be an exit-node
    # (identifier-kind concept or flagged exit-node artifact).
    anchors: dict = field(default_factory=dict)
    source_path: Path | None = None


@dataclass
class Corpus:
    artifacts: dict[str, Artifact]
    concepts: dict[str, Concept]
    containers: dict[str, Container]
    concept_refs: list[ConceptRef]
    links: list[dict]
    spatial_clusters: list[dict]
    tag_defs: list[dict]
    source_class_by_container: dict[str, str]   # substrate-name → substrate-class
    scenarios: list[Scenario] = field(default_factory=list)
    convergences: list[dict] = field(default_factory=list)

    def artifact_names(self) -> set[str]:
        return set(self.artifacts.keys())

    def concept_names(self) -> set[str]:
        return set(self.concepts.keys())

    def ghost_artifacts(self) -> dict[str, list[str]]:
        """Map of unwritten-artifact-name → list of concepts declaring it as a known-container."""
        existing = self.artifact_names()
        ghosts: dict[str, list[str]] = {}
        for c in self.concepts.values():
            for container in c.known_containers:
                if container not in existing:
                    ghosts.setdefault(container, []).append(c.name)
        return ghosts

    def container_ghost_artifacts(self) -> dict[str, list[str]]:
        """Map of unwritten-artifact-name → list of containers declaring it in known-artifacts."""
        existing = self.artifact_names()
        ghosts: dict[str, list[str]] = {}
        for c in self.containers.values():
            for name in c.known_artifacts:
                if name not in existing:
                    ghosts.setdefault(name, []).append(c.name)
        return ghosts

    def all_ghost_artifacts(self) -> dict[str, dict]:
        """Unified ghost index combining concept-declared and container-declared sources.
        Returns: artifact-name → {"concepts": [...], "containers": [...], "score": int}."""
        result: dict[str, dict] = {}
        for name, concepts in self.ghost_artifacts().items():
            result.setdefault(name, {"concepts": [], "containers": [], "score": 0})
            result[name]["concepts"] = concepts
        for name, containers in self.container_ghost_artifacts().items():
            result.setdefault(name, {"concepts": [], "containers": [], "score": 0})
            result[name]["containers"] = containers
        for name, info in result.items():
            info["score"] = len(info["concepts"]) + len(info["containers"])
        return result

    def resolved_refs(self) -> list[ConceptRef]:
        """Concept references where both artifact and concept exist."""
        return [
            r for r in self.concept_refs
            if r.artifact in self.artifacts and r.concept in self.concepts
        ]

    def unresolved_refs(self) -> list[ConceptRef]:
        return [
            r for r in self.concept_refs
            if r.artifact not in self.artifacts or r.concept not in self.concepts
        ]


def _parse_known_artifacts(fm_value) -> tuple[list[str], list[dict]]:
    """Flatten the `known-artifacts:` frontmatter into (all_names, unwritten_details).

    Accepts three shapes:
      - list of strings: [A, B, C]
      - list of dicts with `name:`: [{name: A, location: ..., value: ...}, ...]
      - dict with `authored:` and/or `unwritten:` sub-lists (either shape above)
    """
    names: list[str] = []
    unwritten: list[dict] = []

    def _absorb_list(items, is_unwritten: bool) -> None:
        for item in items or []:
            if isinstance(item, str):
                names.append(item)
                if is_unwritten:
                    unwritten.append({"name": item})
            elif isinstance(item, dict) and "name" in item:
                names.append(item["name"])
                if is_unwritten:
                    unwritten.append(item)

    if isinstance(fm_value, list):
        _absorb_list(fm_value, is_unwritten=False)
    elif isinstance(fm_value, dict):
        _absorb_list(fm_value.get("authored"), is_unwritten=False)
        _absorb_list(fm_value.get("unwritten"), is_unwritten=True)

    return names, unwritten


def load_corpus() -> Corpus:
    color_fm = _read_frontmatter(SCHEMA_DIR / "color-classification.md") or {}
    links = color_fm.get("primary-links", [])
    tag_defs = color_fm.get("tags", [])
    spatial_fm = color_fm.get("spatial-clusters", {}) or {}
    spatial_clusters = spatial_fm.get("classes", []) if isinstance(spatial_fm, dict) else []

    # Substrates — format definitions with their known-artifacts roster
    containers: dict[str, Container] = {}
    source_class_by_container: dict[str, str] = {}
    if SUBSTRATES_DIR.exists():
        for p in SUBSTRATES_DIR.rglob("*.md"):
            fm = _read_frontmatter(p)
            if not fm or "name" not in fm:
                continue
            name = fm["name"]
            names, unwritten = _parse_known_artifacts(fm.get("known-artifacts"))
            inst_impl = {}
            for inst_name, inst_spec in (fm.get("instance-implications") or {}).items():
                if isinstance(inst_spec, dict):
                    inst_impl[inst_name] = inst_spec.get("inherits-concepts") or []
            containers[name] = Container(
                name=name,
                source_class=fm.get("substrate-class", ""),
                known_artifacts=names,
                unwritten_details=unwritten,
                instance_implications=inst_impl,
                source_path=p,
            )
            if "substrate-class" in fm:
                source_class_by_container[name] = fm["substrate-class"]

    # Concepts
    concepts: dict[str, Concept] = {}
    if CONCEPTS_DIR.exists():
        for p in CONCEPTS_DIR.rglob("*.md"):
            fm = _read_frontmatter(p)
            if not fm or "name" not in fm:
                continue
            c = Concept(
                name=fm["name"],
                kind=fm.get("kind", "identifier"),
                link_affinity=fm.get("link-affinity", ""),
                link_affinity_secondary=fm.get("link-affinity-secondary", ""),
                description=fm.get("description", ""),
                canonical_format=fm.get("canonical-format", ""),
                aliases=fm.get("aliases", []) or [],
                known_containers=fm.get("known-containers", []) or [],
                roles=fm.get("roles", []) or [],
                lifetime=str(fm.get("lifetime", "") or ""),
                source_path=p,
            )
            concepts[c.name] = c

    # Artifacts
    artifacts: dict[str, Artifact] = {}
    concept_refs: list[ConceptRef] = []
    for p in ARTIFACTS_DIR.rglob("*.md"):
        fm = _read_frontmatter(p)
        if not fm or "name" not in fm:
            continue
        art = Artifact(
            name=fm["name"],
            link=fm.get("link", "") or fm.get("category", ""),
            link_secondary=fm.get("link-secondary", ""),
            tags=fm.get("tags", []) or [],
            container_class=fm.get("substrate", ""),
            container_instance=fm.get("substrate-instance", ""),
            substrate_hub=fm.get("substrate-hub", ""),
            location_path=(fm.get("location") or {}).get("path", ""),
            aliases=fm.get("aliases", []) or [],
            platform=fm.get("platform", {}) or {},
            fields=fm.get("fields", []) or [],
            observations=fm.get("observations", []) or [],
            anti_forensic=fm.get("anti-forensic", {}) or {},
            survival_edges=fm.get("survival-edges", []) or [],
            exit_node=_resolve_exit_node(fm.get("exit-node", False)),
            exit_attribution_sentence=_exit_node_field(fm.get("exit-node"), "attribution-sentence"),
            exit_primary_source=_exit_node_field(fm.get("exit-node"), "primary-source"),
            provenance=fm.get("provenance", []) or [],
            title_description=str(fm.get("title-description", "") or ""),
            volatility=str(fm.get("volatility", "") or ""),
            interaction_required=str(fm.get("interaction-required", "") or ""),
            source_path=p,
        )
        artifacts[art.name] = art
        for fld_name, concept_name, role in art.concept_refs():
            concept_refs.append(ConceptRef(
                artifact=art.name,
                field=fld_name,
                concept=concept_name,
                role=role,
                match_note=next(
                    (f.get("note", "") for f in art.fields if f.get("name") == fld_name),
                    "",
                ),
            ))

    # Validate roles: warn (not error) when an artifact uses a role not listed
    # on the concept's role vocabulary. Roles are extensible.
    for r in concept_refs:
        if r.role in ("unspecified", ""):
            continue
        concept = concepts.get(r.concept)
        if concept is None:
            continue
        if not concept.roles:
            continue
        if r.role not in concept.role_ids():
            sys.stderr.write(
                f"WARN: {r.artifact}.{r.field} uses role '{r.role}' not declared on "
                f"concept '{r.concept}' (known roles: {sorted(concept.role_ids())})\n"
            )

    # Scenarios — real-world use-cases that thread multiple artifacts via
    # shared join-key concepts. Each file declares the participating
    # artifacts + the concept-role pairs that connect them. Unknown artifact
    # or concept names are warned but not hard-failed.
    scenarios: list[Scenario] = []
    if SCENARIOS_DIR.exists():
        existing_arts = set(artifacts.keys())
        existing_concepts = set(concepts.keys())
        for p in sorted(SCENARIOS_DIR.rglob("*.md")):
            fm = _read_frontmatter(p)
            if not fm or "name" not in fm:
                continue
            arts_block = fm.get("artifacts") or {}
            primary = arts_block.get("primary") or [] if isinstance(arts_block, dict) else []
            corroborating = arts_block.get("corroborating") or [] if isinstance(arts_block, dict) else []
            join_keys_raw = fm.get("join-keys") or []
            join_keys: list[dict] = []
            for jk in join_keys_raw:
                if not isinstance(jk, dict):
                    continue
                c = jk.get("concept")
                r = jk.get("role", "unspecified")
                if not c:
                    continue
                if c not in existing_concepts:
                    sys.stderr.write(f"WARN: scenario '{fm['name']}' references unknown concept '{c}'\n")
                join_keys.append({"concept": c, "role": r})
            for art_name in list(primary) + list(corroborating):
                if art_name not in existing_arts:
                    sys.stderr.write(f"WARN: scenario '{fm['name']}' references unknown artifact '{art_name}'\n")

            # Optional stepwise progression. Normalize each step and warn
            # on unknown artifact/concept names in the same style as above.
            steps_raw = fm.get("steps") or []
            steps_norm: list[dict] = []
            for s in steps_raw:
                if not isinstance(s, dict):
                    continue
                s_arts = list(s.get("artifacts") or [])
                for a in s_arts:
                    if a not in existing_arts:
                        sys.stderr.write(
                            f"WARN: scenario '{fm['name']}' step {s.get('n', '?')} "
                            f"references unknown artifact '{a}'\n"
                        )
                jk = s.get("join-key") or {}
                if isinstance(jk, dict):
                    c = jk.get("concept")
                    if c and c not in existing_concepts:
                        sys.stderr.write(
                            f"WARN: scenario '{fm['name']}' step {s.get('n', '?')} "
                            f"references unknown concept '{c}'\n"
                        )
                steps_norm.append({
                    "n": s.get("n"),
                    "question": s.get("question", ""),
                    "artifacts": s_arts,
                    "join-key": jk if isinstance(jk, dict) else {},
                    "conclusion": s.get("conclusion", ""),
                    "attribution": s.get("attribution", ""),
                    "casey": s.get("casey", ""),
                    "primary-source": s.get("primary-source", ""),
                    "attribution-sentence": s.get("attribution-sentence", ""),
                })

            scenarios.append(Scenario(
                name=fm["name"],
                severity=fm.get("severity", ""),
                summary=fm.get("summary", ""),
                narrative=fm.get("narrative", ""),
                join_keys=join_keys,
                primary_artifacts=list(primary),
                corroborating_artifacts=list(corroborating),
                steps=steps_norm,
                anchors=fm.get("anchors", {}) or {},
                source_path=p,
            ))

    # Convergences — tier-2 first-class files promoting each extends-to rule
    # into its own record. Each file declares the proposition it yields,
    # the inputs that feed it, and (optionally, authored later) the explicit
    # join-chain of identifier concepts threading participating artifacts.
    convergences: list[dict] = []
    if CONVERGENCES_DIR.exists():
        for p in sorted(CONVERGENCES_DIR.glob("*.md")):
            fm = _read_frontmatter(p)
            if not fm or "name" not in fm:
                continue
            convergences.append({
                "name":              fm.get("name"),
                "summary":           fm.get("summary", ""),
                "yields":            fm.get("yields", {}),
                "inputs":            fm.get("inputs", []) or [],
                "input-sources":     fm.get("input-sources", []) or [],
                "join-chain":        fm.get("join-chain", []) or [],
                "exit-node":         fm.get("exit-node", ""),
                "via-artifacts":     fm.get("via-artifacts", []) or [],
                "degradation-paths": fm.get("degradation-paths", []) or [],
                "notes":             fm.get("notes", []) or [],
            })

    return Corpus(
        artifacts=artifacts,
        concepts=concepts,
        containers=containers,
        concept_refs=concept_refs,
        links=links,
        spatial_clusters=spatial_clusters,
        tag_defs=tag_defs,
        source_class_by_container=source_class_by_container,
        scenarios=scenarios,
        convergences=convergences,
    )


def link_color(link_id: str, links: list[dict], fallback: str = "#888888") -> str:
    for L in links:
        if L.get("id") == link_id:
            return L.get("color", fallback)
    return fallback
