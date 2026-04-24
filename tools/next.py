"""
Crawl recommender — decides which artifact to author next.

Under the concept-centric model (v0.3):
  - Ghost artifacts are declared by concepts' known-containers lists.
  - Ranking = how many concepts declare a given unwritten artifact.

Modes:
  python tools/next.py                 # rank ghost artifacts by concept-in-degree
  python tools/next.py --concept <Name>  # show containers (existing + ghost) for a concept
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from graph_core import load_corpus


def print_crawl_ranking() -> None:
    corpus = load_corpus()
    all_ghosts = corpus.all_ghost_artifacts()

    print(f"Existing artifacts: {len(corpus.artifacts)}")
    print(f"Containers:         {len(corpus.containers)}")
    print(f"Concepts:           {len(corpus.concepts)}")
    print(f"Concept refs:       {len(corpus.concept_refs)}")
    print(f"Ghost artifacts:    {len(all_ghosts)}")
    print()

    if not all_ghosts:
        print("No ghost artifacts. Every concept's known-containers AND every container's")
        print("known-artifacts entry exists in the repo. To grow the graph, add a new")
        print("entry to a concept's `known-containers:` or a container's `known-artifacts:`,")
        print("then author the artifact that matches.")
        return

    print("Unwritten artifacts (ranked by aggregate declaration score):")
    print("  score = declaring-concepts + declaring-containers")
    print()
    ranked = sorted(all_ghosts.items(), key=lambda kv: (-kv[1]["score"], kv[0]))
    width = max(len(name) for name, _ in ranked)

    for i, (name, info) in enumerate(ranked, 1):
        print(f"  {i:>3}. {name:<{width}}   score {info['score']}")
        if info["concepts"]:
            print(f"       by concepts:   {', '.join(info['concepts'])}")
        if info["containers"]:
            print(f"       by containers: {', '.join(info['containers'])}")
        print()

    top_name, top_info = ranked[0]
    print(f"Recommendation: author `{top_name}` next.")
    print(f"  Score {top_info['score']} from "
          f"{len(top_info['concepts'])} concept(s), "
          f"{len(top_info['containers'])} container(s).")


def print_concept_analysis(concept_name: str) -> None:
    corpus = load_corpus()
    match = None
    lower = concept_name.lower()
    for name, c in corpus.concepts.items():
        if name.lower() == lower or any(a.lower() == lower for a in c.aliases):
            match = c
            break
    if match is None:
        print(f"Concept '{concept_name}' not found.")
        print("Known concepts:", ", ".join(sorted(corpus.concepts.keys())))
        return

    existing = []
    ghosts = []
    for container in match.known_containers:
        if container in corpus.artifacts:
            existing.append(container)
        else:
            ghosts.append(container)

    print(f"Concept: {match.name}")
    print(f"  Link affinity: {match.link_affinity}")
    print(f"  Aliases: {', '.join(match.aliases) or '(none)'}")
    print()
    print(f"Existing containers ({len(existing)}):")
    for c in existing:
        print(f"  • {c}")
    print()
    print(f"Unwritten containers ({len(ghosts)}):")
    for c in ghosts:
        print(f"  • {c}")

    if ghosts:
        # Cross-reference with other concepts to find the best next authoring target.
        ghost_map = corpus.ghost_artifacts()
        ghost_in_this = set(ghosts)
        cross_scored = [
            (name, score) for name, score in (
                (g, len(ghost_map.get(g, []))) for g in ghost_in_this
            )
        ]
        cross_scored.sort(key=lambda t: -t[1])
        print()
        print("Next-authoring priority within this concept (by multi-concept coverage):")
        for name, score in cross_scored:
            print(f"  {name:<32} appears in {score} concept(s)' known-containers")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Recommend which forensic artifact to author next"
    )
    ap.add_argument("--concept", help="analyze a specific concept (VolumeGUID, DeviceSerial, UserSID, ...)")
    args = ap.parse_args()

    if args.concept:
        print_concept_analysis(args.concept)
    else:
        print_crawl_ranking()


if __name__ == "__main__":
    main()
