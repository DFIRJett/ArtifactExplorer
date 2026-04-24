"""
Next-audit prioritizer — 2-pass forensic-impact inventory.

Pass 1 (outward-pull / "1.5-audit multiplier"):
  For each non-verified artifact X, score by how many OTHER non-verified
  artifacts share X's outgoing links (concept references + source citations
  + convergence participation). Auditing X pseudo-verifies those shared
  link-targets, which transitively strengthens every other non-verified
  artifact that also references them.

  High pass-1 score = "this artifact sits on shared downstream roads;
  auditing it delivers reach to peers."

Pass 2 (inward-pull / "hub attraction"):
  For each non-verified artifact X, score by in-degree from ALL other
  nodes (verified + unverified + ghost/concept known-containers +
  convergences + scenarios). Auditing X firms up many upstream claims
  at once.

  High pass-2 score = "many things point at this artifact; verifying it
  resolves many suspected links simultaneously."

The two passes are intentionally NOT fused — they answer different
questions and a hybrid ranking obscures which leverage type dominates.
"""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import sys
from collections import Counter, defaultdict


# Forensic-weight multipliers (tiebreakers, not dominant factors)
CEILING_MULT = {"C3": 1.5, "C2": 1.2, "C1": 1.0, None: 1.0}
EXIT_NODE_MULT = 1.3  # applied to non-verified but already-tagged exit-node candidates
VERIFIED_WEIGHT = 0.3  # downweight contribution from verified-peer edges (already known)

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(r"C:\Users\mondr\Documents\ProgFor\ArtifactExplorer")
DATA_JSON = ROOT / "viewer" / "data.json"
CRAWL_YAML = ROOT / "tools" / "crawl_state.yaml"


def load_verified_set() -> set[str]:
    """Parse verification_log.artifacts from crawl_state.yaml."""
    import yaml
    with open(CRAWL_YAML, encoding="utf-8") as f:
        state = yaml.safe_load(f)
    return set((state.get("verification_log") or {}).get("artifacts", {}).keys())


def load_graph() -> dict:
    with open(DATA_JSON, encoding="utf-8") as f:
        return json.load(f)


def compute_pass1_outward(nodes: list[dict], links: list[dict], verified: set[str],
                          convergences: list[dict], scenarios: list[dict],
                          sources: dict) -> list[tuple[str, float, dict]]:
    """
    For each non-verified artifact X, score by IDF-weighted sum of shared
    outgoing links to UNVERIFIED peer artifacts.

    Refinements over raw peer-count (v2, 2026-04-23):

    1. IDF-weight concept/source shares. A concept referenced by 210
       artifacts (e.g. UserSID) contributes little per shared edge; a
       concept referenced by 6 (e.g. DeviceSerial) contributes a lot.
       Fixes the UserSID-saturation problem of v1.

       Weight per edge: log(N / freq), clamped at [0, log(N)].

    2. Verified-peer edges count at 0.3x — we've already "bought" that
       verification, so propagation to a verified peer is worth less than
       to an unverified peer. Still > 0 because the shared edge still
       corroborates the UNVERIFIED focal artifact X itself.

    3. Forensic multiplier on final score: ceiling-max * exit-node-flag.
       Tiebreaker only — not dominant.

    Higher pass-1 score = this artifact sits on discriminating (rare)
    shared-downstream roads; auditing it delivers reach to its unverified
    peers through rare edges.
    """
    art_nodes = {n["name"]: n for n in nodes if n["kind"] == "artifact"}
    total_arts = len(art_nodes)

    # Build: concept -> set of artifacts that reference it.
    concept_refs: dict[str, set[str]] = defaultdict(set)
    for l in links:
        if l["type"] != "contains":
            continue
        src = l["source"]
        tgt = l["target"]
        if src.startswith("artifact::") and tgt.startswith("concept::"):
            art = src.split("::", 1)[1]
            con = tgt.split("::", 1)[1]
            concept_refs[con].add(art)

    # Build: source-id -> set of artifacts whose provenance cites it.
    source_cites: dict[str, set[str]] = defaultdict(set)
    for sid, sdata in sources.items():
        coverage = sdata.get("coverage", {})
        arts = coverage.get("artifacts") or []
        for a in arts:
            source_cites[sid].add(a)
    for n in art_nodes.values():
        for entry in n.get("provenance") or []:
            src_id = entry.get("source") if isinstance(entry, dict) else entry
            if src_id:
                source_cites[src_id].add(n["name"])

    # Build: convergence -> set of artifacts via via-artifacts
    conv_arts: dict[str, set[str]] = defaultdict(set)
    for c in convergences:
        for a in c.get("via-artifacts") or []:
            conv_arts[c["name"]].add(a)
        for a in c.get("inputs") or []:
            conv_arts[c["name"]].add(a)

    # Scenario participation
    scen_arts: dict[str, set[str]] = defaultdict(set)
    for s in scenarios:
        for a in (s.get("primary-artifact-ids") or []) + (s.get("corroborating-artifact-ids") or []):
            scen_arts[s["name"]].add(a)

    def idf(freq: int) -> float:
        """log(total_arts / freq). Rare = high."""
        if freq <= 0:
            return 0.0
        return math.log(max(total_arts, freq + 1) / freq)

    # Score each non-verified artifact
    results = []
    for name, node in art_nodes.items():
        if name in verified:
            continue

        edge_score = 0.0  # IDF-weighted
        breakdown = {"via-concepts": 0.0, "via-sources": 0.0, "via-convergences": 0.0, "via-scenarios": 0.0}
        details = defaultdict(list)
        unique_unverified_peers = set()

        # Concepts X refs — each shared edge contributes idf(concept-popularity)
        # per peer, weighted by whether peer is verified.
        for con, arts_sharing in concept_refs.items():
            if name not in arts_sharing:
                continue
            unv_peers = (arts_sharing - {name}) - verified
            v_peers = (arts_sharing - {name}) & verified
            if not unv_peers and not v_peers:
                continue
            w = idf(len(arts_sharing))
            contrib = w * (len(unv_peers) + VERIFIED_WEIGHT * len(v_peers))
            breakdown["via-concepts"] += contrib
            if unv_peers:
                details["concepts"].append(f"{con}[freq={len(arts_sharing)},idf={w:.2f},+{len(unv_peers)}u]")
            edge_score += contrib
            unique_unverified_peers.update(unv_peers)

        # Sources X is cited by
        for sid, arts_sharing in source_cites.items():
            if name not in arts_sharing:
                continue
            unv_peers = (arts_sharing - {name}) - verified
            v_peers = (arts_sharing - {name}) & verified
            if not unv_peers and not v_peers:
                continue
            w = idf(len(arts_sharing))
            contrib = w * (len(unv_peers) + VERIFIED_WEIGHT * len(v_peers))
            breakdown["via-sources"] += contrib
            if unv_peers:
                details["sources"].append(f"{sid}[freq={len(arts_sharing)},idf={w:.2f},+{len(unv_peers)}u]")
            edge_score += contrib
            unique_unverified_peers.update(unv_peers)

        # Convergences X participates in
        for cname, parts in conv_arts.items():
            if name not in parts:
                continue
            unv_peers = (parts - {name}) - verified
            v_peers = (parts - {name}) & verified
            if not unv_peers and not v_peers:
                continue
            w = idf(len(parts)) + 1.0  # convergences are already curated, small bump
            contrib = w * (len(unv_peers) + VERIFIED_WEIGHT * len(v_peers))
            breakdown["via-convergences"] += contrib
            if unv_peers:
                details["convergences"].append(f"{cname}[+{len(unv_peers)}u]")
            edge_score += contrib
            unique_unverified_peers.update(unv_peers)

        # Scenarios X participates in (highest bump — T3 curation)
        for sname, parts in scen_arts.items():
            if name not in parts:
                continue
            unv_peers = (parts - {name}) - verified
            v_peers = (parts - {name}) & verified
            if not unv_peers and not v_peers:
                continue
            w = idf(len(parts)) + 2.0  # scenarios are T3-curated
            contrib = w * (len(unv_peers) + VERIFIED_WEIGHT * len(v_peers))
            breakdown["via-scenarios"] += contrib
            if unv_peers:
                details["scenarios"].append(f"{sname}[+{len(unv_peers)}u]")
            edge_score += contrib
            unique_unverified_peers.update(unv_peers)

        # Forensic-weight multiplier (tiebreaker)
        ceiling = node.get("ceiling-max")
        c_mult = CEILING_MULT.get(ceiling, 1.0)
        e_mult = EXIT_NODE_MULT if node.get("is-exit-node") else 1.0
        final_score = edge_score * c_mult * e_mult

        results.append((name, round(final_score, 2), {
            "edge-score": round(edge_score, 2),
            "ceiling-mult": c_mult,
            "exit-mult": e_mult,
            "breakdown": {k: round(v, 2) for k, v in breakdown.items()},
            "unique-unverified-peers": len(unique_unverified_peers),
            "details": dict(details),
            "ceiling-max": ceiling,
            "is-exit-node": node.get("is-exit-node"),
            "link": node.get("link"),
            "substrate": node.get("substrate"),
        }))

    results.sort(key=lambda r: (-r[1], r[0]))
    return results


def compute_pass2_inward(nodes: list[dict], links: list[dict], verified: set[str],
                         convergences: list[dict], scenarios: list[dict],
                         sources: dict, concepts_meta: list[dict]) -> list[tuple[str, float, dict]]:
    """
    For each non-verified artifact X, weighted in-degree of claims pointing
    at X (v2, 2026-04-23):

    - Convergence-inbound: 2.0 per curated convergence claiming X.
    - Scenario-inbound: 3.0 per curated scenario claiming X (T3 curation
      is the strongest signal we've got).
    - Source-coverage-inbound: IDF-weighted. A source listing X as one of
      30 artifacts contributes less than a source listing X as its ONLY
      artifact. `idf(source-coverage-breadth)`.
    - Cross-reference from VERIFIED peer: 2.0 per peer (peer's own audit
      already survived source-re-check — its claim ABOUT X is stronger).
    - Cross-reference from UNVERIFIED peer: 1.0 per peer (suspected link).
    - Identity-ref from VERIFIED peer: 2.5 (stronger than generic xref
      because identity-resolver claims are structural, not prose).
    - Identity-ref from UNVERIFIED peer: 1.0.

    Forensic multiplier applied at end: ceiling-max * exit-node-flag.

    Higher pass-2 score = many curated or verified voices say X is a hub;
    auditing X resolves many upstream claims at once.
    """
    art_nodes = {n["name"]: n for n in nodes if n["kind"] == "artifact"}
    total_arts = len(art_nodes)

    def idf(freq: int) -> float:
        if freq <= 0:
            return 0.0
        return math.log(max(total_arts, freq + 1) / freq)

    # v3 addition: concept-popularity for IDF-weighting the auto-xref edges.
    # Per Extend-Quota sprint-r4 finding: 14+ artifacts share `UserSID / role:
    # identitySubject`, creating an N×N auto-xref mesh. Without IDF-discount,
    # every one of those artifacts gets a uniform in-degree boost from the
    # mesh — ranking an NTFS-metadata artifact identically to a registry
    # identity hub. Fix: each xref's weight scales by the IDF of the concept
    # underlying it (if we can identify it). Rare shared concept → high IDF
    # → edge matters; UserSID-shared → low IDF → edge matters little.
    concept_popularity: dict[str, int] = defaultdict(int)
    for l in links:
        if l["type"] != "contains":
            continue
        src = l["source"]
        tgt = l["target"]
        if src.startswith("artifact::") and tgt.startswith("concept::"):
            con = tgt.split("::", 1)[1]
            concept_popularity[con] += 1

    def concept_idf_norm(concepts: list[str]) -> float:
        """Average IDF of the concepts underlying an edge, normalized to
        idf(1) = max so a single-artifact concept edge gets weight 1.0 and
        a fully-shared concept edge gets ~0."""
        if not concepts:
            return 1.0  # no concept context — assume default weight
        total_idf = 0.0
        max_idf = math.log(total_arts) if total_arts > 1 else 1.0
        for c in concepts:
            pop = concept_popularity.get(c, 1)
            total_idf += idf(pop)
        return min(1.0, (total_idf / len(concepts)) / max_idf)

    # Build the inbound ledger per artifact
    inbound: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    # Also track IDF contributions separately so we can print per-bin weights
    weighted: dict[str, float] = defaultdict(float)

    # Concepts' known-containers — look in concepts-meta but that field isn't
    # there. Instead we use the `contains` links (concept X artifact) which
    # ARE the concept-said-known-containers assertions as rendered. Every
    # concept ref is a concept claiming this artifact contains data of that
    # concept's kind — i.e., an inbound claim ON the artifact.
    for l in links:
        if l["type"] != "contains":
            continue
        tgt = l["target"]
        src = l["source"]
        # Per sample: source=artifact::X, target=concept::C. The *artifact*
        # is the carrier; concept in-degree is really on the concept. But
        # for pass-2 we want claims ABOUT the artifact. Reverse-read: the
        # artifact has a `references-data` line saying "I contain a C" —
        # authoritative per artifact, but we also count the concept's
        # *known-containers* which overlaps. Since every link is already
        # rendered from the artifact's references-data (not from concept's
        # known-containers), this alone undercounts unclaimed ghosts. We
        # handle ghost-style known-containers separately if available.
        if src.startswith("artifact::") and tgt.startswith("concept::"):
            pass  # not an inbound signal for the artifact under pass-2

    # Source claims: sources with coverage.artifacts listing X
    # IDF by how broad the source's coverage is (fewer artifacts = more specific = worth more).
    for sid, sdata in sources.items():
        coverage = sdata.get("coverage", {})
        arts_listed = coverage.get("artifacts") or []
        if not arts_listed:
            continue
        w = idf(len(arts_listed))
        for a in arts_listed:
            if a in art_nodes and a not in verified:
                inbound[a]["claim-source"].append(sid)
                weighted[a] += w

    # Convergence participation = inbound claim from tier-2
    for c in convergences:
        cname = c.get("name") or "(unnamed)"
        parts = set(c.get("via-artifacts") or []) | set(c.get("inputs") or [])
        for a in parts:
            if a in art_nodes and a not in verified:
                inbound[a]["convergence"].append(cname)
                weighted[a] += 2.0

    # Scenario participation = inbound claim from tier-3 (strongest curation)
    for s in scenarios:
        sname = s.get("name") or "(unnamed)"
        parts = set(s.get("primary-artifact-ids") or []) | set(s.get("corroborating-artifact-ids") or [])
        for a in parts:
            if a in art_nodes and a not in verified:
                inbound[a]["scenario"].append(sname)
                weighted[a] += 3.0

    # VERIFIED-artifact cross-refs to X: inspect every verified artifact's
    # frontmatter for body-level cross-references. Crude: look for the
    # artifact's name appearing in verified artifact body text. Do this
    # through grep over the artifacts/ tree — too slow here; proxy it by
    # checking the rendered graph cross-verifies-with + resolves-identity-via.
    for n in nodes:
        if n["kind"] != "artifact":
            continue
        if n["name"] in verified:
            origin = "verified-peer"
        else:
            origin = "unverified-peer"
        # cross-verifies-with entries are {artifact, pairs: [{concept, role}, ...]}
        # v3: weight each xref by IDF of the underlying concept(s) so rare-
        # concept agreements outrank generic UserSID/shared-concept mesh.
        xref_base = 2.0 if origin == "verified-peer" else 1.0
        for ref_entry in (n.get("cross-verifies-with") or []):
            ref = ref_entry.get("artifact") if isinstance(ref_entry, dict) else ref_entry
            if ref and ref in art_nodes and ref not in verified:
                pair_concepts = [p.get("concept", "") for p in (ref_entry.get("pairs") or []) if isinstance(p, dict)]
                pair_concepts = [c for c in pair_concepts if c]
                idf_mult = concept_idf_norm(pair_concepts)
                inbound[ref][f"cross-ref-from-{origin}"].append(n["name"])
                weighted[ref] += xref_base * idf_mult
        # resolves-identity-via entries are {concept, user-role, definer-artifact, definer-role}
        # v3: IDF-weight by the `concept` field.
        idref_base = 2.5 if origin == "verified-peer" else 1.0
        for ref_entry in (n.get("resolves-identity-via") or []):
            ref = ref_entry.get("definer-artifact") if isinstance(ref_entry, dict) else ref_entry
            if ref and ref in art_nodes and ref not in verified:
                concept = ref_entry.get("concept", "") if isinstance(ref_entry, dict) else ""
                idf_mult = concept_idf_norm([concept] if concept else [])
                inbound[ref][f"identity-ref-from-{origin}"].append(n["name"])
                weighted[ref] += idref_base * idf_mult

    # Score each non-verified artifact
    results = []
    for name, node in art_nodes.items():
        if name in verified:
            continue
        bins = inbound.get(name, {})
        total = sum(len(v) for v in bins.values())
        edge_score = weighted.get(name, 0.0)
        # Forensic multiplier
        ceiling = node.get("ceiling-max")
        c_mult = CEILING_MULT.get(ceiling, 1.0)
        e_mult = EXIT_NODE_MULT if node.get("is-exit-node") else 1.0
        final_score = edge_score * c_mult * e_mult

        results.append((name, round(final_score, 2), {
            "edge-score": round(edge_score, 2),
            "ceiling-mult": c_mult,
            "exit-mult": e_mult,
            "raw-in-degree": total,
            "bins": {k: len(v) for k, v in bins.items()},
            "details": {k: list(v) for k, v in bins.items()},
            "ceiling-max": ceiling,
            "is-exit-node": node.get("is-exit-node"),
            "link": node.get("link"),
            "substrate": node.get("substrate"),
        }))

    results.sort(key=lambda r: (-r[1], r[0]))
    return results


def fmt_node(name: str, info: dict) -> str:
    tags = []
    if info.get("is-exit-node"):
        tags.append("EXIT")
    if info.get("ceiling-max") == "C3":
        tags.append("C3")
    tag_str = f" [{' '.join(tags)}]" if tags else ""
    return f"{name:<40} ({info.get('substrate','?'):<26}){tag_str}"


def main() -> None:
    ap = argparse.ArgumentParser(description="2-pass audit-priority inventory")
    ap.add_argument("--top", type=int, default=20, help="show top N per pass")
    ap.add_argument("--pass", dest="which_pass", choices=["1", "2", "both"], default="both")
    ap.add_argument("--details", action="store_true", help="print per-artifact breakdown")
    args = ap.parse_args()

    verified = load_verified_set()
    graph = load_graph()
    nodes = graph["graph"]["nodes"]
    links = graph["graph"]["links"]
    convergences = graph.get("convergences", [])
    scenarios = graph.get("scenarios", [])
    sources = graph.get("sources", {})
    concepts_meta = graph.get("concepts-meta", [])

    art_total = sum(1 for n in nodes if n["kind"] == "artifact")
    print(f"Corpus: {art_total} artifacts, {len(verified)} verified "
          f"({len(verified)/art_total:.0%}), {art_total - len(verified)} unverified")
    print()

    if args.which_pass in ("1", "both"):
        print("=" * 70)
        print("PASS 1 — outward-pull (IDF-weighted, v2)")
        print("=" * 70)
        print("Score = IDF-weighted sum of shared outgoing-link contributions.")
        print("Rare shared concepts (e.g. DeviceSerial, ref'd by 6 artifacts)")
        print("count more than common ones (UserSID, ref'd by 210). Verified-")
        print("peer edges count at 0.3x. Ceiling/exit-node multiplier applied.")
        print()
        p1 = compute_pass1_outward(nodes, links, verified, convergences, scenarios, sources)
        for i, (name, score, info) in enumerate(p1[:args.top], 1):
            b = info["breakdown"]
            edge = info["edge-score"]
            cm = info["ceiling-mult"]
            em = info["exit-mult"]
            up = info["unique-unverified-peers"]
            print(f"  {i:>2}. score {score:>6.1f}  (edge {edge:.1f} x ceil {cm} x exit {em})  {fmt_node(name, info)}")
            print(f"       IDF breakdown: concepts={b['via-concepts']:.1f} sources={b['via-sources']:.1f} "
                  f"conv={b['via-convergences']:.1f} scen={b['via-scenarios']:.1f}  [unv peers: {up}]")
            if args.details:
                for k, v in info["details"].items():
                    print(f"       {k}: {', '.join(v[:5])}{'  ...' if len(v) > 5 else ''}")
        print()

    if args.which_pass in ("2", "both"):
        print("=" * 70)
        print("PASS 2 — inward-pull (hub attraction, v3 with auto-xref IDF)")
        print("=" * 70)
        print("Weighted in-degree: scenario=3.0, convergence=2.0. xref/id-ref base")
        print("weights (v-peer=2.0/2.5, u-peer=1.0) are NOW IDF-weighted by the")
        print("underlying concept's artifact-popularity (UserSID-mesh near-zero;")
        print("DeviceSerial/MFTEntryReference near-full). Ceiling/exit multiplier.")
        print()
        p2 = compute_pass2_inward(nodes, links, verified, convergences, scenarios, sources, concepts_meta)
        for i, (name, score, info) in enumerate(p2[:args.top], 1):
            bins = info["bins"]
            edge = info["edge-score"]
            cm = info["ceiling-mult"]
            em = info["exit-mult"]
            bin_str = " ".join(f"{k.replace('cross-ref-from-','xref.').replace('identity-ref-from-','id.')}={v}" for k, v in bins.items() if v)
            print(f"  {i:>2}. score {score:>6.1f}  (edge {edge:.1f} x ceil {cm} x exit {em}; raw-in={info['raw-in-degree']})  {fmt_node(name, info)}")
            if bin_str:
                print(f"       {bin_str}")
            if args.details:
                for k, v in info["details"].items():
                    print(f"       {k}: {', '.join(v[:5])}{'  ...' if len(v) > 5 else ''}")


if __name__ == "__main__":
    main()
