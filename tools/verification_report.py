"""Verification report for DFIRCLI corpus.

Reports on which artifacts / sources have been audit-verified during
priority-driven crawl vs which still carry mass-population inheritance.

Usage:
  python tools/verification_report.py              # full report
  python tools/verification_report.py --stale      # never-verified entries
  python tools/verification_report.py --substrate <X>  # breakdown by substrate
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
CRAWL_STATE = ROOT / "tools" / "crawl_state.yaml"
ARTIFACTS = ROOT / "artifacts"


def load_verification_log() -> dict:
    if not CRAWL_STATE.exists():
        return {"artifacts": {}, "sources": {}, "convergences": {}, "scenarios": {}}
    try:
        cs = yaml.safe_load(CRAWL_STATE.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return {"artifacts": {}, "sources": {}, "convergences": {}, "scenarios": {}}
    vl = cs.get("verification_log") or {}
    return {
        "artifacts":    vl.get("artifacts", {}) or {},
        "sources":      vl.get("sources", {}) or {},
        "convergences": vl.get("convergences", {}) or {},
        "scenarios":    vl.get("scenarios", {}) or {},
    }


def load_frontier_set() -> set[str]:
    """Return artifact names in the frontier (both original and refined)."""
    if not CRAWL_STATE.exists():
        return set()
    try:
        cs = yaml.safe_load(CRAWL_STATE.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return set()
    names = set()
    for key in ("frontier", "frontier_refined"):
        f = cs.get(key) or {}
        for n in f.keys():
            names.add(n)
    return names


def compute_target_set() -> set[str]:
    """Target set = artifacts that participate in any convergence.input-sources or
    scenario step.artifacts / anchors. These are the forensically-connected
    artifacts we most want audited."""
    target = set()
    for directory in ("convergences", "scenarios"):
        d = ROOT / directory
        if not d.exists():
            continue
        for md in d.rglob("*.md"):
            t = md.read_text(encoding="utf-8")
            if not t.startswith("---"):
                continue
            parts = t.split("---", 2)
            if len(parts) < 3:
                continue
            try:
                fm = yaml.safe_load(parts[1]) or {}
            except yaml.YAMLError:
                continue
            # Convergence: input-sources[].artifacts
            for src in fm.get("input-sources") or []:
                for a in (src.get("artifacts") or []):
                    target.add(a)
            # Scenario: steps[].artifacts + top-level artifacts.primary/corroborating
            for step in fm.get("steps") or []:
                for a in step.get("artifacts") or []:
                    target.add(a)
            top_arts = fm.get("artifacts") or {}
            for bucket in ("primary", "corroborating"):
                for a in top_arts.get(bucket) or []:
                    target.add(a)
    return target


def print_progress(vl: dict, all_arts: dict, all_src_ids: set) -> None:
    """Print the crawl progress summary — four denominators."""
    verified_artifacts = set(vl["artifacts"].keys())
    verified_sources = set(vl["sources"].keys())
    frontier = load_frontier_set()
    target = compute_target_set()

    v_art = len(verified_artifacts & set(all_arts.keys()))
    v_src = len(verified_sources & all_src_ids)
    corpus_n = len(all_arts)
    source_n = len(all_src_ids)
    fron_union = verified_artifacts | frontier
    target_overlap = verified_artifacts & target
    target_n = len(target)

    print("=" * 72)
    print("CRAWL PROGRESS")
    print("=" * 72)
    print(f"  Audited / corpus-wide:       {v_art:3d} / {corpus_n:3d}  "
          f"({v_art*100//max(corpus_n,1):3d}%)   all artifacts")
    print(f"  Audited / working frontier:  {v_art:3d} / {len(fron_union):3d}  "
          f"({v_art*100//max(len(fron_union),1):3d}%)   honest progress (frontier shifts as crawl advances)")
    print(f"  Audited / target set:        {len(target_overlap):3d} / {target_n:3d}  "
          f"({len(target_overlap)*100//max(target_n,1):3d}%)   target = artifacts in convergences or scenarios")
    print(f"  Sources audited / registry:  {v_src:3d} / {source_n:3d}  "
          f"({v_src*100//max(source_n,1):3d}%)   source-side coverage")
    # Next-seed hint
    highest = None
    highest_count = -1
    if CRAWL_STATE.exists():
        try:
            cs = yaml.safe_load(CRAWL_STATE.read_text(encoding="utf-8")) or {}
            for key in ("frontier_refined", "frontier"):
                f = cs.get(key) or {}
                for n, meta in f.items():
                    if n in verified_artifacts:
                        continue
                    c = meta if isinstance(meta, int) else (meta.get("count", 0) if isinstance(meta, dict) else 0)
                    if c > highest_count:
                        highest_count = c
                        highest = n
                if highest:
                    break
        except yaml.YAMLError:
            pass
    if highest:
        print(f"  Next seed candidate:         {highest} (frontier count {highest_count})")
    print()

    # Change-log convergence trend
    try:
        cs = yaml.safe_load(CRAWL_STATE.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        cs = {}
    change_log = cs.get("seed_change_log") or []
    if change_log:
        print("CHANGE-LOG CONVERGENCE TREND")
        print("-" * 72)
        print(f"  {'seed':>4} {'artifact':<24} {'+src':>5} {'fu':>4} {'+cov':>5} {'+men':>5} {'retr':>5} {'leads':>6}")
        for e in change_log:
            c = e.get("changes", {}) or {}
            print(f"  {e.get('seed', '?'):>4} {(e.get('artifact', '?'))[:24]:<24} "
                  f"{c.get('new_sources_added', 0):>5} "
                  f"{c.get('sources_with_field_updates', 0):>4} "
                  f"{c.get('coverage_artifacts_added', 0):>5} "
                  f"{c.get('coverage_mentions_added', 0):>5} "
                  f"{c.get('retractions_from_provenance', 0):>5} "
                  f"{c.get('new_source_leads_discovered', 0):>6}")
        # Trend hint
        if len(change_log) >= 2:
            recent = change_log[-1].get("changes", {}) or {}
            prior = change_log[-2].get("changes", {}) or {}
            recent_total = sum(recent.get(k, 0) for k in (
                "coverage_artifacts_added", "coverage_mentions_added",
                "retractions_from_provenance"))
            prior_total = sum(prior.get(k, 0) for k in (
                "coverage_artifacts_added", "coverage_mentions_added",
                "retractions_from_provenance"))
            if recent_total < prior_total:
                print(f"  trend: converging (recent structural changes {recent_total} < prior {prior_total})")
            elif recent_total > prior_total:
                print(f"  trend: diverging (recent structural changes {recent_total} > prior {prior_total}) — investigate")
            else:
                print(f"  trend: flat ({recent_total})")
    print()


def load_sources() -> list[dict]:
    return yaml.safe_load(REG.read_text(encoding="utf-8"))["sources"]


def read_fm(path: Path) -> dict:
    t = path.read_text(encoding="utf-8")
    if not t.startswith("---"):
        return {}
    parts = t.split("---", 2)
    if len(parts) < 3:
        return {}
    return yaml.safe_load(parts[1]) or {}


def full_report(vl: dict) -> None:
    verified_artifacts = vl["artifacts"]
    verified_sources = vl["sources"]

    # Artifact coverage
    all_arts = {}
    for md in ARTIFACTS.rglob("*.md"):
        fm = read_fm(md)
        name = fm.get("name", md.stem)
        sub = fm.get("substrate", "")
        all_arts[name] = sub

    per_sub_total = Counter(all_arts.values())
    per_sub_verified = Counter()
    for name, sub in all_arts.items():
        if name in verified_artifacts:
            per_sub_verified[sub] += 1

    all_src_ids = {s["id"] for s in load_sources()}
    print_progress(vl, all_arts, all_src_ids)

    print("=" * 72)
    print("VERIFICATION REPORT")
    print("=" * 72)
    print(f"\nArtifacts:    {len(verified_artifacts)} verified / {len(all_arts)} total ({len(verified_artifacts)*100//max(len(all_arts),1)}%)")
    print(f"Sources:      {len(verified_sources)} verified / {len(load_sources())} total")

    # T2/T3 counts
    convs_dir = ROOT / "convergences"
    scens_dir = ROOT / "scenarios"
    n_conv = len(list(convs_dir.glob("*.md"))) if convs_dir.exists() else 0
    n_scen = len(list(scens_dir.glob("*.md"))) if scens_dir.exists() else 0
    vc = vl.get("convergences", {})
    vs = vl.get("scenarios", {})
    print(f"Convergences: {len(vc)} verified / {n_conv} total  (T2 — opt-in coverage)")
    print(f"Scenarios:    {len(vs)} verified / {n_scen} total  (T3 — opt-in coverage)")

    print("\nPer-substrate breakdown:")
    print(f"  {'substrate':<28}{'verified':>10} / {'total':>5}  {'%':>5}")
    for sub in sorted(per_sub_total.keys()):
        v = per_sub_verified.get(sub, 0)
        t = per_sub_total[sub]
        pct = v * 100 // t if t else 0
        print(f"  {sub:<28}{v:>10} / {t:>5}  {pct:>4}%")

    # Source status breakdown
    status_counts = Counter()
    for sid, meta in verified_sources.items():
        st = meta.get("status", "verified")
        status_counts[st] += 1
    # Unverified sources = total - verified
    all_src_ids = {s["id"] for s in load_sources()}
    unverified_src_count = len(all_src_ids - set(verified_sources.keys()))

    print("\nSource status:")
    print(f"  {'status':<30}  count")
    for st, n in sorted(status_counts.items(), key=lambda x: -x[1]):
        print(f"  {st:<30}  {n:>5}")
    print(f"  {'unverified':<30}  {unverified_src_count:>5}")

    print("\nVerified artifacts:")
    for name, meta in verified_artifacts.items():
        print(f"  [{meta.get('status', '?'):<25}] {name}  (seed {meta.get('audited-in-seed', '-')})")

    print("\nVerified sources:")
    for sid, meta in verified_sources.items():
        print(f"  [{meta.get('status', '?'):<30}] {sid}")


def stale_report(vl: dict) -> None:
    """List artifacts and sources that have never been verified."""
    verified_arts = set(vl["artifacts"].keys())
    verified_srcs = set(vl["sources"].keys())

    all_arts = {}
    for md in ARTIFACTS.rglob("*.md"):
        fm = read_fm(md)
        all_arts[fm.get("name", md.stem)] = fm.get("substrate", "")

    unverified_arts = set(all_arts) - verified_arts
    all_src_ids = {s["id"] for s in load_sources()}
    unverified_srcs = all_src_ids - verified_srcs

    print(f"Unverified artifacts: {len(unverified_arts)} / {len(all_arts)}")
    by_sub = defaultdict(list)
    for name in sorted(unverified_arts):
        by_sub[all_arts[name]].append(name)
    for sub in sorted(by_sub.keys()):
        print(f"\n  {sub} ({len(by_sub[sub])}):")
        for name in by_sub[sub][:10]:
            print(f"    - {name}")
        if len(by_sub[sub]) > 10:
            print(f"    ... +{len(by_sub[sub]) - 10} more")

    print(f"\nUnverified sources: {len(unverified_srcs)} / {len(all_src_ids)}")
    # Break down by kind
    src_by_id = {s["id"]: s for s in load_sources()}
    by_kind = defaultdict(list)
    for sid in sorted(unverified_srcs):
        k = src_by_id[sid].get("kind", "unclassified")
        by_kind[k].append(sid)
    for k in sorted(by_kind.keys()):
        print(f"\n  {k} ({len(by_kind[k])}):")
        for sid in by_kind[k][:5]:
            print(f"    - {sid}")
        if len(by_kind[k]) > 5:
            print(f"    ... +{len(by_kind[k]) - 5} more")


def substrate_report(vl: dict, substrate: str) -> None:
    verified_arts = vl["artifacts"]
    all_arts = {}
    for md in ARTIFACTS.rglob("*.md"):
        fm = read_fm(md)
        if fm.get("substrate") == substrate:
            all_arts[fm.get("name", md.stem)] = md

    print(f"Substrate: {substrate}  —  {len(all_arts)} artifacts")
    verified_here = [n for n in all_arts if n in verified_arts]
    unverified_here = [n for n in all_arts if n not in verified_arts]
    print(f"  Verified: {len(verified_here)}")
    for n in verified_here:
        meta = verified_arts[n]
        print(f"    [{meta.get('status', '?'):<15}] {n}")
    print(f"  Unverified: {len(unverified_here)}")
    for n in unverified_here[:20]:
        print(f"    - {n}")
    if len(unverified_here) > 20:
        print(f"    ... +{len(unverified_here) - 20} more")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stale", action="store_true", help="List never-verified entries")
    ap.add_argument("--substrate", help="Show per-substrate breakdown")
    args = ap.parse_args()

    vl = load_verification_log()

    if args.stale:
        stale_report(vl)
    elif args.substrate:
        substrate_report(vl, args.substrate)
    else:
        full_report(vl)


if __name__ == "__main__":
    main()
