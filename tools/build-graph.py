"""
Build viewer/data.json — concept-centric graph model.

Node taxonomy:
  - artifact         the big nodes — registry keys, event logs, files, ...
  - concept          the small nodes — shared forensic data types (VolumeGUID,
                     DeviceSerial, UserSID, ...) referenced by multiple artifacts
  - ghost-artifact   unwritten artifacts declared as known-containers of some
                     concept but not yet authored in the repo

Edge types:
  - contains         artifact → concept (artifact carries this data type)
  - ghost-contains   concept → ghost-artifact (concept declares an unwritten container)
  - anti-forensic    artifact → artifact (empirical survival relationship)
"""

from __future__ import annotations

import json
import math
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from graph_core import load_corpus, link_color, VIEWER_DIR, Corpus, Artifact
from next_audit import compute_pass1_outward, compute_pass2_inward, load_verified_set

GHOST_COLOR = "#555555"
CONCEPT_SIZE_BASE = 3.0


def _normalize_provenance(raw):
    """Normalize a frontmatter `provenance:` list into uniform dicts {source, section, note}."""
    if not raw:
        return []
    out = []
    for entry in raw:
        if isinstance(entry, str):
            s = entry.strip()
            if s:
                out.append({"source": s, "section": "", "note": ""})
        elif isinstance(entry, dict):
            sid = str(entry.get("source", "") or "").strip()
            if sid:
                out.append({
                    "source":  sid,
                    "section": str(entry.get("section", "") or ""),
                    "note":    str(entry.get("note", "") or ""),
                })
    return out


def _load_sources_registry():
    """Load schema/sources.yaml into a {id: {apa, author, year, title, publisher, url, note}} map."""
    import yaml
    path = Path(__file__).resolve().parent.parent / "schema" / "sources.yaml"
    if not path.exists():
        return {}
    reg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = {}
    for s in reg.get("sources") or []:
        if not isinstance(s, dict) or "id" not in s:
            continue
        out[s["id"]] = {
            "apa":       s.get("apa", "") or "",
            "author":    s.get("author", "") or "",
            "year":      str(s.get("year", "") or ""),
            "title":     s.get("title", "") or "",
            "publisher": s.get("publisher", "") or "",
            "url":       s.get("url", "") or "",
            "note":      s.get("note", "") or "",
        }
    return out


def _edge_color_for_pair(corpus, artifact_name, concept_name):
    """Pick edge color for an artifact→concept contains-edge.

    If the concept has a secondary link-affinity that MATCHES the artifact's
    link, use the secondary color (so the edge visually attaches to the
    correct half of the bi-color concept node). Otherwise fall back to the
    artifact's own link color.
    """
    art = corpus.artifacts.get(artifact_name)
    concept = corpus.concepts.get(concept_name)
    art_link = art.link if art else ""
    if concept and concept.link_affinity_secondary and concept.link_affinity_secondary == art_link:
        return link_color(concept.link_affinity_secondary, corpus.links)
    return link_color(art_link, corpus.links)


def artifact_size(art: Artifact, ref_count: int) -> float:
    base = 4
    return base + (ref_count * 2) + math.log2(1 + len(art.fields))


def concept_size(ref_count: int) -> float:
    return CONCEPT_SIZE_BASE + math.log2(1 + ref_count) * 1.5


def build() -> dict:
    corpus = load_corpus()

    nodes: list[dict] = []
    links: list[dict] = []
    node_ids: set[str] = set()
    temporal_index: list[dict] = []

    def add_node(node: dict) -> None:
        if node["id"] in node_ids:
            return
        node_ids.add(node["id"])
        nodes.append(node)

    def add_link(**props) -> None:
        links.append(props)

    # Substrate-inherited concept references — e.g., every artifact in
    # NTUSER.DAT inherits UserSID:profileOwner because the hive itself is
    # bound to a specific user profile. Synthesize these refs before the
    # ref-count tally so they participate in sizing and edge emission.
    from graph_core import ConceptRef
    for art in corpus.artifacts.values():
        container = corpus.containers.get(art.container_class)
        if not container or not container.instance_implications:
            continue
        inherited = container.instance_implications.get(art.container_instance) or []
        for inh in inherited:
            concept = inh.get("concept")
            role = inh.get("role", "unspecified")
            if not concept:
                continue
            # Skip if an explicit per-field reference with the same (concept, role)
            # already exists — the artifact author has already covered it.
            if any(r.artifact == art.name and r.concept == concept and r.role == role
                   for r in corpus.concept_refs):
                continue
            corpus.concept_refs.append(ConceptRef(
                artifact=art.name,
                field="*substrate-inherited*",
                concept=concept,
                role=role,
                match_note=f"inherited from substrate-instance {art.container_instance}",
            ))

    # Count concept references per concept and per artifact (for sizing).
    concept_ref_count: dict[str, int] = {}
    artifact_ref_count: dict[str, int] = {}
    for r in corpus.concept_refs:
        concept_ref_count[r.concept] = concept_ref_count.get(r.concept, 0) + 1
        artifact_ref_count[r.artifact] = artifact_ref_count.get(r.artifact, 0) + 1

    # Verification status — read verification_log from tools/crawl_state.yaml.
    # Used by the viewer's 'Verified-only' filter.
    import yaml as __yaml
    from pathlib import Path as __Path
    _crawl_state_path = __Path(__file__).resolve().parent / "crawl_state.yaml"
    verified_artifacts: set[str] = set()
    verified_sources: set[str] = set()
    if _crawl_state_path.exists():
        _cs = __yaml.safe_load(_crawl_state_path.read_text(encoding="utf-8")) or {}
        _vl = _cs.get("verification_log") or {}
        verified_artifacts = set((_vl.get("artifacts") or {}).keys())
        verified_sources = set((_vl.get("sources") or {}).keys())

    # Forensic-relevance signal + per-edge weights from source coverage data.
    # source-count for artifact X = number of distinct sources in the registry
    # whose coverage.artifacts includes X. Reflects how broadly documented
    # the artifact is in the DFIR literature.
    # edge_weight(X, Y) = (count of X's provenance sources whose
    # coverage.artifacts OR coverage.mentions includes Y) / len(X.provenance).
    # Measures forensic-linkage strength: sister artifacts that co-occur
    # across multiple sources that discuss X get high weight.
    sources_registry = _load_sources_registry()
    artifact_source_counts: dict[str, int] = {}
    artifact_edge_weights: dict[str, dict[str, float]] = {}

    # Build reverse index: for each source, its coverage.artifacts + mentions
    source_covers: dict[str, set[str]] = {}
    for sid, s_data in sources_registry.items():
        # sources_registry returns minimal dict; reload full registry for coverage
        pass

    # Need full source data (including coverage) — re-parse schema/sources.yaml
    import yaml as _yaml
    from pathlib import Path as _Path
    _root = _Path(__file__).resolve().parent.parent
    reg_path = _root / "schema" / "sources.yaml"
    source_substrates: dict[str, set[str]] = {}
    if reg_path.exists():
        reg_raw = _yaml.safe_load(reg_path.read_text(encoding="utf-8")) or {}
        for s in reg_raw.get("sources", []) or []:
            cov = s.get("coverage") or {}
            arts = set(cov.get("artifacts", []) or [])
            mentions = set(cov.get("mentions", []) or [])
            source_covers[s["id"]] = (arts, mentions)
            source_substrates[s["id"]] = set(cov.get("substrates", []) or [])

    # Mid-verified: strict-verified OR explicitly named in coverage.artifacts
    # by at least MIN_EXPLICIT_HITS independent verified sources.
    #
    # Prior definition (replaced 2026-04-23) accepted 3 paths: explicit
    # artifacts, mentions-only, OR substrate-wide fallback (verified source
    # declares substrate coverage without artifact-list scoping → every
    # artifact in that substrate inherited mid-verified status). That produced
    # 248/292 mid-verified, inflated by 28 broad-scope verified sources each
    # fanning out across 30-70 artifacts in their substrate without ever
    # naming them. 85% "coverage" with weak semantics.
    #
    # New bar: two verified sources must name the artifact explicitly in
    # coverage.artifacts. Mentions-path + substrate-fallback both dropped —
    # those were the two inflators. Produces ~110/292 mid-verified, matching
    # the intent of "this artifact is corroborated by name in the verified
    # literature" rather than "somebody verified something near it."
    MIN_EXPLICIT_HITS = 2
    mid_verified: set[str] = set(verified_artifacts)
    for art in corpus.artifacts.values():
        if art.name in mid_verified:
            continue
        hits = sum(
            1 for sid in verified_sources
            if art.name in source_covers.get(sid, (set(), set()))[0]
        )
        if hits >= MIN_EXPLICIT_HITS:
            mid_verified.add(art.name)

    # source-count: for each artifact, how many sources list it in coverage.artifacts
    for art in corpus.artifacts.values():
        count = sum(1 for sid, (arts, _m) in source_covers.items() if art.name in arts)
        artifact_source_counts[art.name] = count

    # edge-weights: for each artifact, the fraction of its provenance sources
    # that cover or mention each other artifact
    for art in corpus.artifacts.values():
        prov_ids = [p if isinstance(p, str) else p.get("source") for p in (art.provenance or [])]
        prov_ids = [p for p in prov_ids if p]
        n = len(prov_ids)
        if n == 0:
            continue
        # Accumulate sister-artifact occurrences across this artifact's sources
        sister_counts: dict[str, int] = {}
        for sid in prov_ids:
            if sid not in source_covers:
                continue
            arts_set, mentions_set = source_covers[sid]
            combined = arts_set | mentions_set
            for sister in combined:
                if sister == art.name:
                    continue
                sister_counts[sister] = sister_counts.get(sister, 0) + 1
        # Normalize to 0-1 weight
        weights = {sister: count / n for sister, count in sister_counts.items() if count > 0}
        if weights:
            artifact_edge_weights[art.name] = weights

    # Cross-verification index — maps each artifact to peer artifacts that
    # share at least one (concept, role) pair. This is the "these two
    # artifacts can corroborate each other" relationship: when ShellBags
    # and Recent-LNK both reference VolumeGUID:accessedVolume, the specific
    # GUID found in one can be cross-checked against the other. Crucial for
    # tier-3 forensic confidence.
    from collections import defaultdict
    # Cross-verification principle: two artifacts corroborate each other
    # ONLY when they share a forensically-unique value — i.e., an identifier
    # concept. Value-type concepts (ExecutablePath, IPAddress, URL, etc.)
    # are data CLASSES, not unique instances: two artifacts both recording
    # "an executable path" tells you nothing about whether they reference
    # the same path. Filter value-type concepts out of the corroboration
    # graph before computing pairs.
    value_type_concepts = {
        c.name for c in corpus.concepts.values() if c.kind == "value-type"
    }
    role_to_artifacts: dict[tuple[str, str], list[str]] = defaultdict(list)
    for r in corpus.concept_refs:
        if r.concept in value_type_concepts:
            continue
        if r.role and r.role != "unspecified":
            role_to_artifacts[(r.concept, r.role)].append(r.artifact)
    corroborates: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for (concept, role), artifact_list in role_to_artifacts.items():
        uniq = list(dict.fromkeys(artifact_list))  # dedup, preserve order
        if len(uniq) < 2:
            continue
        for a in uniq:
            for b in uniq:
                if a == b:
                    continue
                corroborates[a][b].append({"concept": concept, "role": role})

    # Identifier resolution — artifacts that USE an identifier (role ∈
    # {profileOwner, actingUser, authenticatingUser, targetUser, accessedVolume,
    # ranProcess, etc.}) RESOLVE it against artifacts that DEFINE the
    # identifier (role = identitySubject). This is the forensic workflow:
    # "I have a SID from RunMRU; consult SAM or ProfileList to learn whose
    # account it is." Per-artifact, emit a `resolves-identity-via` list.
    DEFINER_ROLE = "identitySubject"
    concept_definers: dict[str, list[str]] = defaultdict(list)
    for r in corpus.concept_refs:
        if r.role == DEFINER_ROLE:
            if r.artifact not in concept_definers[r.concept]:
                concept_definers[r.concept].append(r.artifact)
    resolves_via: dict[str, list[dict]] = defaultdict(list)
    for r in corpus.concept_refs:
        if r.role == DEFINER_ROLE or r.role in ("unspecified", ""):
            continue
        definers = concept_definers.get(r.concept, [])
        for d in definers:
            if d == r.artifact:
                continue
            entry = {
                "concept": r.concept,
                "user-role": r.role,
                "definer-artifact": d,
                "definer-role": DEFINER_ROLE,
            }
            # Dedup per (artifact, concept, user-role, definer) — inherited
            # refs + explicit refs shouldn't duplicate.
            key = (r.artifact, r.concept, r.role, d)
            if not any((x["concept"], x["user-role"], x["definer-artifact"]) ==
                       (r.concept, r.role, d) for x in resolves_via[r.artifact]):
                resolves_via[r.artifact].append(entry)

    # Artifact nodes + timestamp harvesting
    for art in corpus.artifacts.values():
        color = link_color(art.link, corpus.links)
        art_id = f"artifact::{art.name}"
        source_class = corpus.source_class_by_container.get(art.container_class, "")
        ceiling_max = max(
            [int(str(s.get("ceiling", "C0")).lstrip("C") or 0) for s in art.observations] or [0]
        )
        # Exit-node status is an explicit forensic judgment declared in the
        # artifact's frontmatter (`exit-node: true`), NOT derived from its
        # ceiling. A high ceiling means the propositions are strong; exit-node
        # means the artifact is where an investigation productively ends.
        # The two are related but not equivalent — the examiner decides.
        is_exit_node = bool(art.exit_node)
        art_link_secondary = (art.link_secondary or "").strip()
        art_color_secondary = link_color(art_link_secondary, corpus.links) if art_link_secondary else ""
        # Display label: for windows-evtx artifacts, render the NODE label
        # as `winevtx - [<EventID>]` — short and scannable. The full event
        # title is exposed separately as `display-title` and rendered only
        # in the details-panel header. Non-evtx containers fall back to the
        # raw slug name for both fields.
        display_title = art.name
        if art.container_class == "windows-evtx":
            # Event ID is the numeric tail of the slug (`Security-4624` → 4624,
            # `Sysmon-1` → 1). Channel-level artifacts without a numeric tail
            # (e.g. `DriverFrameworks-Operational`) fall back to the slug.
            tail = art.name.rsplit("-", 1)[-1] if "-" in art.name else ""
            if tail.isdigit():
                display_label = f"winevtx - [{tail}]"
            else:
                display_label = art.name
            if art.title_description:
                display_title = f'winevtx - "{art.title_description}"'
        else:
            display_label = art.name
        add_node({
            "id": art_id,
            "name": art.name,
            "display-label": display_label,
            "display-title": display_title,
            "kind": "artifact",
            "link": art.link,
            "link-secondary": art_link_secondary,
            "color": color,
            "color-secondary": art_color_secondary,
            "tags": art.tags,
            "size": artifact_size(art, artifact_ref_count.get(art.name, 0)),
            "substrate": art.container_class,
            "substrate-instance": art.container_instance,
            "substrate-hub": art.substrate_hub,
            "substrate-class": source_class,
            "location-path": art.location_path,
            "aliases": art.aliases,
            "observations": [s.get("proposition") for s in art.observations],
            "ceiling-max": ceiling_max,
            "is-exit-node": is_exit_node,
            # Audit justification — verbatim sentence from the single source
            # identified as strongest attribution. Empty on CULLed artifacts
            # and on exit-nodes from before the Phase-1 audit.
            "exit-attribution-sentence": art.exit_attribution_sentence,
            "exit-primary-source":       art.exit_primary_source,
            # Cross-verification: artifacts that share at least one (concept,
            # role) pair with this artifact. Each entry = {artifact, pairs:
            # [{concept, role}, ...]} — the pairs explain HOW the two
            # artifacts can corroborate each other.
            "cross-verifies-with": [
                {"artifact": peer, "pairs": pairs}
                for peer, pairs in sorted(corroborates.get(art.name, {}).items(),
                                          key=lambda kv: (-len(kv[1]), kv[0]))
            ],
            # Identifier resolution: when THIS artifact carries a concept
            # (e.g., UserSID:profileOwner) without defining it, these are
            # the artifacts that DEFINE the concept (role=identitySubject).
            # Forensic workflow: consult these to translate the identifier
            # to its real-world subject.
            "resolves-identity-via": resolves_via.get(art.name, []),
            "field-count": len(art.fields),
            "concept-ref-count": artifact_ref_count.get(art.name, 0),
            # Provenance IDs referencing the top-level `sources` registry.
            # Rendered in the Sources section of the details panel by
            # resolving each ID against data.sources at the viewer side.
            "provenance": _normalize_provenance(art.provenance),
            # Source-count = number of distinct sources where this artifact
            # appears in coverage.artifacts. Used as a forensic-relevance
            # signal: widely-documented artifacts have higher counts.
            "source-count": artifact_source_counts.get(art.name, 0),
            # Verification status — has this artifact been through the
            # 5-phase source-audit procedure? Drives the viewer's
            # Verified-only filter toggle.
            "verified": art.name in verified_artifacts,
            # Mid-verified: reachable from at least one verified source's
            # coverage without the artifact itself being audited yet. Drives
            # the 3-state verification slider's middle position — fills the
            # graph progressively as substrate anchors and catalog sources
            # get verified, without waiting for per-artifact audits.
            "mid-verified": art.name in mid_verified,
            # Edge weights to sister artifacts: for each sister Y, the
            # fraction of this artifact's sources whose content mentions Y
            # (covers + mentions). edge_weight(X, Y) = M / len(X.provenance).
            # Used by the viewer to render link-strength visually.
            "edge-weights": artifact_edge_weights.get(art.name, {}),
            # Human-readable event title. For windows-evtx artifacts the
            # viewer prefixes it with `winevtx - ` in the details header.
            "title-description": art.title_description,
            # Lifetime + interaction axes — drives the volatility slider in
            # the viewer's Config pane.
            "volatility": art.volatility,
            "interaction-required": art.interaction_required,
            "write-privilege": art.anti_forensic.get("write-privilege", ""),
            "integrity-mechanism": art.anti_forensic.get("integrity-mechanism", ""),
            # Full field list so the viewer can render edge-click details.
            # Each entry carries every property useful for answering
            # "where exactly does this field live and how is it encoded."
            "fields": [
                {
                    "name": f.get("name"),
                    "kind": f.get("kind"),
                    "location": f.get("location"),
                    "encoding": f.get("encoding"),
                    "type": f.get("type"),
                    "note": f.get("note"),
                    "clock": f.get("clock"),
                    "resolution": f.get("resolution"),
                    "update-rule": f.get("update-rule"),
                    "availability": f.get("availability"),
                    "references-data": f.get("references-data") or [],
                }
                for f in art.fields
            ],
        })

        for ts in art.timestamp_fields():
            temporal_index.append({
                "artifact": art.name,
                "field": ts.get("name"),
                "clock": ts.get("clock"),
                "resolution": ts.get("resolution"),
                "location": ts.get("location"),
                "update-rule": ts.get("update-rule"),
                "availability": ts.get("availability"),
            })

    # Concept nodes (smaller, colored by link-affinity)
    for c in corpus.concepts.values():
        color = link_color(c.link_affinity, corpus.links, fallback="#B5B5B5")
        # concept-kind splits shared-data nodes into two semantic classes:
        #   identifier  — system-assigned IDs where the SPECIFIC instance
        #                 pivots across artifacts (VolumeGUID, UserSID, etc.)
        #   value-type  — generic data types where instances differ per
        #                 artifact (ExecutablePath, URL, EmailAddress, etc.)
        # Renderer uses this to draw identifier nodes as circles and
        # value-type nodes as diamonds.
        raw_kind = (c.kind or "identifier").strip()
        concept_kind = "value-type" if raw_kind == "value-type" else "identifier"
        # Only identifier concepts are exit nodes — they resolve a specific
        # real-world entity (physical device, user account, volume) and
        # terminate the forensic chain with high confidence.
        # Value-type concepts are a DISTINCT class — they're aggregation/IOC
        # categories (ExecutablePath, URL, hash, email). They get the diamond
        # shape + outward radial force but are NOT exit nodes.
        concept_is_exit = (concept_kind == "identifier")
        # Dual link-affinity — render concept nodes bi-color when secondary
        # is declared. Edges choose which of the two colors to use based on
        # which matches the other endpoint's affinity.
        link_secondary = (c.link_affinity_secondary or "").strip()
        color_secondary = link_color(link_secondary, corpus.links) if link_secondary else ""
        add_node({
            "id": f"concept::{c.name}",
            "name": c.name,
            "kind": "concept",
            "concept-kind": concept_kind,
            "is-exit-node": concept_is_exit,
            "link": c.link_affinity,
            "link-secondary": link_secondary,
            "color": color,
            "color-secondary": color_secondary,
            "size": concept_size(concept_ref_count.get(c.name, 0)),
            "description": c.description,
            "canonical-format": c.canonical_format,
            "aliases": c.aliases,
            "known-container-count": len(c.known_containers),
            "referenced-by-count": concept_ref_count.get(c.name, 0),
            "roles": c.roles,   # [{id, description}, ...] — role vocabulary
            "lifetime": c.lifetime,
        })

    # Ghost artifact nodes — known-containers that aren't yet written
    ghost_map = corpus.ghost_artifacts()
    for ghost_name, concept_list in ghost_map.items():
        add_node({
            "id": f"ghost::{ghost_name}",
            "name": ghost_name,
            "kind": "ghost-artifact",
            "color": GHOST_COLOR,
            "size": 3 + len(concept_list),
            "declared-by-concepts": concept_list,
            "priority-score": len(concept_list),
            "status": "unwritten",
        })

    # Edges: artifact -> concept (contains). Each edge carries a semantic
    # role. When multiple fields in the same artifact reference the same
    # concept in the SAME role (e.g., ShellBags has 4 fields that all carry
    # VolumeGUID as `accessedVolume`), collapse them into ONE edge that
    # records every contributing field — same visual edge, richer metadata.
    # Different roles remain distinct edges (e.g., MFT→MFTEntryReference
    # has two edges: thisRecord and parentDirectory).
    from collections import defaultdict
    edge_map: dict[tuple[str, str, str], dict] = {}
    for r in corpus.concept_refs:
        src = f"artifact::{r.artifact}"
        dst = f"concept::{r.concept}"
        if src not in node_ids or dst not in node_ids:
            continue
        key = (src, dst, r.role)
        if key not in edge_map:
            edge_map[key] = {
                "source": src,
                "target": dst,
                "type": "contains",
                "role": r.role,
                "fields": [r.field],
                "notes": [r.match_note] if r.match_note else [],
                "color": _edge_color_for_pair(corpus, r.artifact, r.concept),
                "width": 1.8,
            }
        else:
            e = edge_map[key]
            if r.field and r.field not in e["fields"]:
                e["fields"].append(r.field)
            if r.match_note and r.match_note not in e["notes"]:
                e["notes"].append(r.match_note)

    # Emit the deduplicated edges. Keep `field` as first for back-compat
    # with the edge-click panel; the full list lives in `fields`.
    for e in edge_map.values():
        add_link(
            source=e["source"],
            target=e["target"],
            type=e["type"],
            role=e["role"],
            field=e["fields"][0],
            fields=e["fields"],
            note="; ".join(e["notes"]) if e["notes"] else "",
            color=e["color"],
            width=e["width"],
        )

    # Edges: concept -> ghost (ghost-contains)
    existing_arts = corpus.artifact_names()
    for c in corpus.concepts.values():
        for container in c.known_containers:
            if container in existing_arts:
                continue  # already linked via references-data from the real artifact
            add_link(
                source=f"concept::{c.name}",
                target=f"ghost::{container}",
                type="ghost-contains",
                color=GHOST_COLOR,
                width=1.0,
                dashed=True,
            )

    # Anti-forensic-survival edges
    for art in corpus.artifacts.values():
        for s in art.survival_edges:
            when = s.get("when", "")
            m = re.match(r"(\S+)\s+removed", when)
            if m:
                other = m.group(1)
                if f"artifact::{other}" in node_ids:
                    add_link(
                        source=f"artifact::{art.name}",
                        target=f"artifact::{other}",
                        type="anti-forensic-survival",
                        reason=s.get("reason", ""),
                        color="#FF7F50",
                        width=1.4,
                        dashed=True,
                    )

    # Emit substrate-class vocabulary as distinct ordered list (for sidebar filter)
    source_classes_seen = []
    for sc in corpus.source_class_by_container.values():
        if sc and sc not in source_classes_seen:
            source_classes_seen.append(sc)

    # Scenarios — emit as node-id / concept-id references so the viewer can
    # resolve them directly against graph.nodes without re-parsing names.
    scenarios_out = []
    for sc in corpus.scenarios:
        primary_ids = [f"artifact::{n}" for n in sc.primary_artifacts if f"artifact::{n}" in node_ids]
        corr_ids = [f"artifact::{n}" for n in sc.corroborating_artifacts if f"artifact::{n}" in node_ids]
        # Collapse join-keys to concept node-ids; keep the (concept, role)
        # tuple for edge-matching in the viewer overlay.
        jk_out = []
        for jk in sc.join_keys:
            cid = f"concept::{jk['concept']}"
            if cid in node_ids:
                jk_out.append({
                    "concept": jk["concept"],
                    "concept-id": cid,
                    "role": jk.get("role", "unspecified"),
                })
        # Stepwise progression — resolve per-step artifact names to node-ids
        # so the viewer can light them up directly without another lookup
        # pass. A step's join-key is resolved to a concept node-id if the
        # concept exists; unresolvable concepts are emitted as null so the
        # viewer can fall back to the plain name.
        steps_out = []
        for s in sc.steps:
            step_art_ids = [f"artifact::{n}" for n in (s.get("artifacts") or []) if f"artifact::{n}" in node_ids]
            jk_step = s.get("join-key") or {}
            jk_concept = jk_step.get("concept")
            jk_cid = f"concept::{jk_concept}" if jk_concept else None
            if jk_cid not in node_ids:
                jk_cid = None
            steps_out.append({
                "n": s.get("n"),
                "question": s.get("question", ""),
                "artifact-ids": step_art_ids,
                "artifact-names": list(s.get("artifacts") or []),
                "join-key": {
                    "concept": jk_concept,
                    "concept-id": jk_cid,
                    "role": jk_step.get("role", "unspecified"),
                } if jk_concept else None,
                "conclusion": s.get("conclusion", ""),
                "attribution": s.get("attribution", ""),
                "casey": s.get("casey", ""),
                "primary-source": s.get("primary-source", ""),
                "attribution-sentence": s.get("attribution-sentence", ""),
            })

        scenarios_out.append({
            "name": sc.name,
            "severity": sc.severity,
            "summary": sc.summary,
            "narrative": sc.narrative,
            "join-keys": jk_out,
            "primary-artifact-ids": primary_ids,
            "corroborating-artifact-ids": corr_ids,
            "steps": steps_out,
            "anchors": sc.anchors,
        })

    return {
        "graph": {"nodes": nodes, "links": links},
        "links": corpus.links,
        "substrate-classes": source_classes_seen,
        "spatial-clusters": corpus.spatial_clusters,
        "tags": corpus.tag_defs,
        "concepts-meta": [
            {
                "name": c.name,
                "link-affinity": c.link_affinity,
                "description": c.description,
                "aliases": c.aliases,
            }
            for c in corpus.concepts.values()
        ],
        "temporal-index": temporal_index,
        "scenarios": scenarios_out,
        "convergences": corpus.convergences,
        "sources": {
            sid: {**data, "verified": sid in verified_sources}
            for sid, data in _load_sources_registry().items()
        },
        "summary": {
            "artifact-count": len(corpus.artifacts),
            "concept-count": len(corpus.concepts),
            "ghost-count": len(ghost_map),
            "concept-refs": len(corpus.concept_refs),
            "timestamp-fields": len(temporal_index),
            "scenario-count": len(scenarios_out),
            "convergence-count": len(corpus.convergences),
        },
    }


def annotate_audit_priorities(data: dict) -> None:
    """Stamp 2-pass audit-priority scores onto each unverified artifact node.

    Pass 1 (outward-pull): unverified-peer reach via shared concepts /
    sources / convergences / scenarios. IDF-weighted so rare shared edges
    score higher. Ceiling + exit-node forensic multiplier applied.

    Pass 2 (inward-pull): weighted in-degree of claims pointing at X.
    Scenario/convergence curation weighted strongest; verified-peer xrefs
    stronger than unverified-peer; source-coverage IDF-weighted by breadth.

    Adds per-artifact fields: pass1-score, pass1-rank, pass2-score,
    pass2-rank (ranks are 1-indexed within unverified pool).
    Adds summary keys: pass1-top20, pass2-top20.
    """
    verified = load_verified_set()
    nodes = data["graph"]["nodes"]
    links = data["graph"]["links"]
    convergences = data.get("convergences", [])
    scenarios = data.get("scenarios", [])
    sources = data.get("sources", {})
    concepts_meta = data.get("concepts-meta", [])

    p1 = compute_pass1_outward(nodes, links, verified, convergences, scenarios, sources)
    p2 = compute_pass2_inward(nodes, links, verified, convergences, scenarios, sources, concepts_meta)

    p1_by_name = {name: (rank, score) for rank, (name, score, _) in enumerate(p1, 1)}
    p2_by_name = {name: (rank, score) for rank, (name, score, _) in enumerate(p2, 1)}

    for n in nodes:
        if n["kind"] != "artifact" or n["name"] in verified:
            continue
        name = n["name"]
        if name in p1_by_name:
            rank, score = p1_by_name[name]
            n["pass1-rank"] = rank
            n["pass1-score"] = score
        if name in p2_by_name:
            rank, score = p2_by_name[name]
            n["pass2-rank"] = rank
            n["pass2-score"] = score

    data["summary"]["pass1-top20"] = [
        {"name": name, "score": score, "rank": i}
        for i, (name, score, _) in enumerate(p1[:20], 1)
    ]
    data["summary"]["pass2-top20"] = [
        {"name": name, "score": score, "rank": i}
        for i, (name, score, _) in enumerate(p2[:20], 1)
    ]
    data["summary"]["unverified-count"] = sum(
        1 for n in nodes if n["kind"] == "artifact" and n["name"] not in verified
    )


def main() -> None:
    data = build()
    annotate_audit_priorities(data)
    VIEWER_DIR.mkdir(exist_ok=True)
    out = VIEWER_DIR / "data.json"
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    s = data["summary"]
    print(f"Wrote {out}")
    print(f"  Artifacts:        {s['artifact-count']}")
    print(f"  Concepts:         {s['concept-count']}")
    print(f"  Ghost artifacts:  {s['ghost-count']}")
    print(f"  Concept refs:     {s['concept-refs']}")
    print(f"  Timestamp fields: {s['timestamp-fields']}")
    print(f"  Scenarios:        {s['scenario-count']}")
    print(f"  Convergences:     {s['convergence-count']}")
    print(f"  Unverified:       {s['unverified-count']} ({s['unverified-count']/s['artifact-count']:.0%})")
    if s.get("pass1-top20"):
        print(f"  Pass-1 top: {s['pass1-top20'][0]['name']} (score {s['pass1-top20'][0]['score']})")
    if s.get("pass2-top20"):
        print(f"  Pass-2 top: {s['pass2-top20'][0]['name']} (score {s['pass2-top20'][0]['score']})")


if __name__ == "__main__":
    main()
