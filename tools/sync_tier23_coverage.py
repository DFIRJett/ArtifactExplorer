"""Bidirectional sync: tier_23_source_database → source.coverage.{convergences,scenarios}.

H-006 B-5 — pushes accumulated Phase 5 tier-applicability entries back to the
canonical source records. After running, sources that were declared to apply
to tier-2 convergences or tier-3 scenarios carry that declaration in the
registry and participate in opt-in validator checks.

Idempotent: safe to re-run. Preserves existing coverage.{convergences,scenarios}
values, only adds what's in the database.

Usage:
  python tools/sync_tier23_coverage.py            # apply
  python tools/sync_tier23_coverage.py --dry-run  # report only
"""
from __future__ import annotations
import sys, io, yaml, pathlib, argparse

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_sources_with_header():
    txt = (ROOT / "schema" / "sources.yaml").read_text(encoding="utf-8")
    header_lines = []
    for line in txt.splitlines(keepends=True):
        if line.startswith("#") or line.strip() == "":
            header_lines.append(line)
        else:
            break
    header = "".join(header_lines)
    data = yaml.safe_load(txt)
    return header, data


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="report only, no writes")
    args = ap.parse_args()

    cs = yaml.safe_load((ROOT / "tools" / "crawl_state.yaml").read_text(encoding="utf-8")) or {}
    tier_db = cs.get("tier_23_source_database") or {}
    t2_entries = tier_db.get("tier-2-applicable") or []
    t3_entries = tier_db.get("tier-3-applicable") or []

    header, sources = load_sources_with_header()
    idx = {s["id"]: s for s in sources["sources"]}

    changes = []

    for entry in t2_entries:
        sid = entry.get("source")
        if not sid or sid not in idx:
            continue
        convs = entry.get("tier-2-applies-to") or []
        broadly = entry.get("tier-2-broadly") or entry.get("tier-2-applies-broadly")
        s = idx[sid]
        cov = s.setdefault("coverage", {})
        if broadly is True and cov.get("convergences-broadly") is not True:
            cov["convergences-broadly"] = True
            changes.append(f"{sid}: convergences-broadly=true")
        existing = cov.get("convergences") or []
        added = []
        for c in convs:
            if c not in existing:
                existing.append(c)
                added.append(c)
        if added:
            cov["convergences"] = existing
            changes.append(f"{sid}: +convergences {added}")

    for entry in t3_entries:
        sid = entry.get("source")
        if not sid or sid not in idx:
            continue
        scens = entry.get("tier-3-applies-to") or []
        broadly = (entry.get("tier-3-broadly") or
                   entry.get("tier-3-applies-broadly") or
                   entry.get("tier-3-applies-to-all-scenarios"))
        s = idx[sid]
        cov = s.setdefault("coverage", {})
        if broadly is True and cov.get("scenarios-broadly") is not True:
            cov["scenarios-broadly"] = True
            changes.append(f"{sid}: scenarios-broadly=true")
        existing = cov.get("scenarios") or []
        added = []
        for c in scens:
            if c not in existing:
                existing.append(c)
                added.append(c)
        if added:
            cov["scenarios"] = existing
            changes.append(f"{sid}: +scenarios {added}")

    print(f"tier-2 entries in database: {len(t2_entries)}")
    print(f"tier-3 entries in database: {len(t3_entries)}")
    print(f"Source.coverage changes:    {len(changes)}")
    for c in changes[:40]:
        print(f"  {c}")
    if len(changes) > 40:
        print(f"  ... and {len(changes) - 40} more")

    if args.dry_run:
        print("\n(dry-run — no files written)")
        return

    if not changes:
        print("\nNo changes to write.")
        return

    body = yaml.safe_dump(sources, sort_keys=False, allow_unicode=True, width=9999, default_flow_style=False)
    (ROOT / "schema" / "sources.yaml").write_text(header + body, encoding="utf-8", newline="\n")
    print("\nschema/sources.yaml updated.")


if __name__ == "__main__":
    main()
