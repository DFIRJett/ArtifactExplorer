"""Coverage report for ArtifactExplorer source registry.

Usage:
  python tools/coverage_report.py                   # full report
  python tools/coverage_report.py --substrate X     # sources covering substrate X
  python tools/coverage_report.py --for-artifact P  # sources applicable to artifact at path P

Drives two use cases:
  1. Attribution efficiency — for a given artifact's substrate, list the
     candidate sources (short list instead of 303 to sift through).
  2. Completeness audit — per-substrate source density; flag weak substrates.
"""
from __future__ import annotations
import argparse
import sys
import io
from collections import Counter, defaultdict
from pathlib import Path

import yaml

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

ROOT = Path(__file__).resolve().parent.parent
REG = ROOT / "schema" / "sources.yaml"
ARTIFACTS = ROOT / "artifacts"


def load_sources():
    reg = yaml.safe_load(REG.read_text(encoding="utf-8"))
    return reg["sources"]


def read_frontmatter(path: Path) -> dict:
    t = path.read_text(encoding="utf-8")
    if not t.startswith("---"):
        return {}
    parts = t.split("---", 2)
    if len(parts) < 3:
        return {}
    return yaml.safe_load(parts[1]) or {}


def full_report(srcs: list[dict]) -> None:
    print("=" * 70)
    print(f"Source registry: {len(srcs)} entries")
    print("=" * 70)

    # Kind + authority + coverage distribution
    kinds = Counter(s.get("kind", "unclassified") for s in srcs)
    auths = Counter(s.get("authority", "unclassified") for s in srcs)

    print("\nKind distribution:")
    for k, n in sorted(kinds.items(), key=lambda x: -x[1]):
        print(f"  {n:3d}  {k}")

    print("\nAuthority distribution:")
    for a, n in sorted(auths.items(), key=lambda x: -x[1]):
        print(f"  {n:3d}  {a}")

    # Sources per substrate
    per_sub = defaultdict(lambda: {"primary": 0, "secondary": 0, "tertiary": 0})
    cross_sub = {"primary": 0, "secondary": 0, "tertiary": 0}
    for s in srcs:
        auth = s.get("authority", "unknown")
        subs = (s.get("coverage") or {}).get("substrates") or []
        if not subs:
            if auth in cross_sub:
                cross_sub[auth] += 1
        else:
            for sub in subs:
                if auth in per_sub[sub]:
                    per_sub[sub][auth] += 1

    # Pair with actual artifact counts
    art_counts = Counter()
    if ARTIFACTS.exists():
        for md in ARTIFACTS.rglob("*.md"):
            fm = read_frontmatter(md)
            sub = fm.get("substrate")
            if sub:
                art_counts[sub] += 1

    print("\nSources per substrate (primary / secondary / tertiary):")
    print(f"  {'substrate':<28}{'arts':>5} | {'prim':>5} {'sec':>5} {'ter':>5}  TOTAL")
    all_subs = sorted(set(list(per_sub.keys()) + list(art_counts.keys())))
    for sub in all_subs:
        p = per_sub[sub]["primary"]
        s_ = per_sub[sub]["secondary"]
        t = per_sub[sub]["tertiary"]
        arts = art_counts.get(sub, 0)
        total = p + s_ + t
        marker = "  <-- weak" if total < 5 else ""
        print(f"  {sub:<28}{arts:>5} | {p:>5} {s_:>5} {t:>5}  {total:>3}{marker}")
    print(f"\n  <cross-substrate / behavior>     | "
          f"{cross_sub['primary']:>5} {cross_sub['secondary']:>5} {cross_sub['tertiary']:>5}  "
          f"{sum(cross_sub.values()):>3}")


def by_substrate(srcs: list[dict], target_sub: str) -> None:
    print(f"Sources covering substrate: {target_sub}")
    print("=" * 70)

    matches = []
    for s in srcs:
        subs = (s.get("coverage") or {}).get("substrates") or []
        if target_sub in subs:
            matches.append(s)

    # Group by authority
    by_auth = defaultdict(list)
    for s in matches:
        by_auth[s.get("authority", "unknown")].append(s)

    for auth in ("primary", "secondary", "tertiary", "unknown"):
        group = by_auth.get(auth, [])
        if not group:
            continue
        print(f"\n{auth.upper()} ({len(group)}):")
        for s in sorted(group, key=lambda x: x["id"]):
            kind = s.get("kind", "?")
            print(f"  [{kind:<16}] {s['id']}")
            print(f"                     {s.get('title', '')[:90]}")

    print(f"\n{len(matches)} total sources for '{target_sub}'")


def for_artifact(srcs: list[dict], artifact_path: Path) -> None:
    fm = read_frontmatter(artifact_path)
    sub = fm.get("substrate", "")
    name = fm.get("name", artifact_path.stem)
    if not sub:
        print(f"Artifact has no substrate field: {artifact_path}")
        return

    print(f"Artifact: {name}  (substrate={sub})")
    print("=" * 70)

    # Tightened filter: coverage.artifacts is authoritative when non-empty.
    # A source with a populated coverage.artifacts list applies ONLY to those
    # artifacts, regardless of its substrates. Empty artifacts list falls back
    # to substrate matching; empty both = cross-substrate catch-all.

    artifact_matches = []   # coverage.artifacts explicitly includes this artifact
    substrate_matches = []  # artifacts empty; substrates includes ours
    cross_matches = []      # artifacts empty; substrates empty (applies everywhere)

    for s in srcs:
        cov = s.get("coverage") or {}
        arts = cov.get("artifacts") or []
        subs = cov.get("substrates") or []
        if arts:
            # Authoritative list
            if name in arts:
                artifact_matches.append(s)
            # else: source explicitly scoped AWAY from this artifact
            continue
        # No artifact list - fall back to substrate
        if not subs:
            cross_matches.append(s)
        elif sub in subs:
            substrate_matches.append(s)

    def pp(group, label):
        print(f"\n{label} ({len(group)}):")
        by_auth = defaultdict(list)
        for s in group:
            by_auth[s.get("authority", "?")].append(s)
        for auth in ("primary", "secondary", "tertiary", "?"):
            g = by_auth.get(auth, [])
            if not g:
                continue
            print(f"  [{auth}]")
            for s in sorted(g, key=lambda x: x["id"])[:20]:
                kind = s.get("kind", "?")
                print(f"    {s['id']}   <{kind}>")

    if artifact_matches:
        pp(artifact_matches, "Artifact-specific")
    pp(substrate_matches, f"Substrate-level ({sub})")
    # Trim cross-substrate output (lots of MITRE entries)
    behaviors = [s for s in cross_matches if s.get("kind") == "behavior"]
    other = [s for s in cross_matches if s.get("kind") != "behavior"]
    print(f"\nCross-substrate behaviors (MITRE/ITM): {len(behaviors)} candidates (not listed)")
    if other:
        pp(other, "Cross-substrate methodology/tool-docs")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--substrate", help="Filter to one substrate")
    ap.add_argument("--for-artifact", help="Path to an artifact .md file")
    args = ap.parse_args()

    srcs = load_sources()

    if args.for_artifact:
        for_artifact(srcs, Path(args.for_artifact))
    elif args.substrate:
        by_substrate(srcs, args.substrate)
    else:
        full_report(srcs)


if __name__ == "__main__":
    main()
