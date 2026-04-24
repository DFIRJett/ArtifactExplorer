"""Pending decisions report — aggregates crawl-state queues.

Run at pause points (every ~5 seeds) to triage accumulating items that
need register / skip / defer / retract decisions.

Output: per-queue counts + top items. Does NOT modify any files.
"""
from __future__ import annotations
import sys
import io
from pathlib import Path

import yaml

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

ROOT = Path(__file__).resolve().parent.parent
CRAWL_STATE = ROOT / "tools" / "crawl_state.yaml"
SOURCES = ROOT / "schema" / "sources.yaml"


def load_crawl_state() -> dict:
    if not CRAWL_STATE.exists():
        return {}
    try:
        return yaml.safe_load(CRAWL_STATE.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        print(f"  !! crawl_state.yaml parse error: {e}", file=sys.stderr)
        return {}


def load_sources() -> list[dict]:
    if not SOURCES.exists():
        return []
    return yaml.safe_load(SOURCES.read_text(encoding="utf-8")).get("sources", []) or []


def section(title: str) -> None:
    print()
    print(f"-- {title} " + "-" * max(0, 70 - len(title) - 4))


def report() -> None:
    cs = load_crawl_state()
    srcs = load_sources()

    print("=" * 72)
    print("PENDING DECISIONS REPORT")
    print("=" * 72)

    # ---- new_source_leads ----
    leads = cs.get("new_source_leads") or []
    section(f"new_source_leads ({len(leads)})")
    if leads:
        print("  Candidate sources discovered during crawls. Decide per item:")
        print("    register -> add to schema/sources.yaml")
        print("    skip     -> out of scope")
        print("    defer    -> insufficient info")
        for lead in leads[:10]:
            if isinstance(lead, dict):
                desc = lead.get("lead") or lead.get("url") or str(lead)
                seen = lead.get("seen-in", "")
                status = lead.get("status", "")
                print(f"  - {desc[:70]}")
                if seen:
                    print(f"      seen-in: {seen}")
                if status:
                    print(f"      status:  {status}")
            else:
                print(f"  - {str(lead)[:70]}")
        if len(leads) > 10:
            print(f"  ... +{len(leads) - 10} more")
    else:
        print("  (empty)")

    # ---- fa_citation_audit_queue ----
    fa = cs.get("fa_citation_audit_queue") or {}
    section(f"fa_citation_audit_queue")
    if isinstance(fa, dict):
        pending = fa.get("pending")
        count = fa.get("count")
        if pending:
            print(f"  PENDING — {count} FA citations flagged for per-artifact validation.")
            print("  Next batch: verify 5-10 citations; retract or confirm.")
        else:
            print("  Resolved.")

    # ---- tier23_review_queue ----
    t23 = cs.get("tier23_review_queue") or []
    section(f"tier23_review_queue ({len(t23)})")
    if t23:
        print("  Methodology-source references noted during artifact crawls.")
        print("  Escalate to convergence/scenario attribution passes.")
        for item in t23[:5]:
            if isinstance(item, dict):
                repo = item.get("repository", "")
                ctx = item.get("context") or item.get("artifact-context", "")
                print(f"  - repo={repo}  context={ctx}")
                for ref in item.get("references", [])[:3]:
                    print(f"      * {ref}")
            else:
                print(f"  - {item}")
        if len(t23) > 5:
            print(f"  ... +{len(t23) - 5} more")
    else:
        print("  (empty)")

    # ---- discovered_artifacts_not_in_corpus ----
    disc = cs.get("discovered_artifacts_not_in_corpus") or []
    section(f"discovered_artifacts_not_in_corpus ({len(disc)})")
    if disc:
        print("  Artifact names seen in repos that we don't have in our corpus.")
        print("  Decide: add to corpus / skip / defer.")
        for item in disc[:10]:
            if isinstance(item, dict):
                name = item.get("name", "?")
                seen = item.get("seen-in", "")
                print(f"  - {name}  (seen in: {seen})")
            else:
                print(f"  - {item}")
        if len(disc) > 10:
            print(f"  ... +{len(disc) - 10} more")
    else:
        print("  (empty)")

    # ---- verification_log status review ----
    vl = cs.get("verification_log") or {}
    v_sources = vl.get("sources") or {}
    dead = [sid for sid, meta in v_sources.items()
            if (meta or {}).get("status") == "verified-dead"]
    sub_only = [sid for sid, meta in v_sources.items()
                if (meta or {}).get("status") == "verified-substrate-level"]

    section("verification_log — status-needing-action")
    if dead:
        print(f"  verified-dead ({len(dead)}): consider removing entry OR keeping with note.")
        for sid in dead:
            # count citations
            cite_count = 0
            for art_file in ROOT.rglob("artifacts/**/*.md"):
                t = art_file.read_text(encoding="utf-8")
                if sid in t:
                    cite_count += 1
            print(f"    - {sid}  ({cite_count} artifact(s) still cite this)")
    if sub_only:
        print(f"  verified-substrate-level ({len(sub_only)}): audit other citing artifacts for retraction.")
        for sid in sub_only:
            cite_count = 0
            for art_file in ROOT.rglob("artifacts/**/*.md"):
                t = art_file.read_text(encoding="utf-8")
                if sid in t:
                    cite_count += 1
            print(f"    - {sid}  ({cite_count} artifact(s) cite this; review for substrate-only scope)")
    if not dead and not sub_only:
        print("  (no status-action items)")

    # ---- duplicate URL quick check ----
    section("duplicate-URL check (light)")
    url_map: dict[str, list[str]] = {}
    for s in srcs:
        url = (s.get("url") or "").strip()
        if url:
            url_map.setdefault(url, []).append(s["id"])
    dupes = {u: ids for u, ids in url_map.items() if len(ids) > 1}
    if dupes:
        print(f"  {len(dupes)} URLs appear on 2+ source entries:")
        for url, ids in list(dupes.items())[:5]:
            print(f"    {url}")
            for sid in ids:
                print(f"      - {sid}")
        if len(dupes) > 5:
            print(f"    ... +{len(dupes) - 5} more")
    else:
        print("  no duplicate URLs detected")

    # ---- summary ----
    section("SUMMARY")
    total_pending = (
        len(leads)
        + len(t23)
        + len(disc)
        + len(dead)
        + len(sub_only)
        + len(dupes)
    )
    print(f"  Total pending decisions across queues: {total_pending}")
    print()
    if total_pending == 0:
        print("  Nothing requires triage. Proceed to next seed.")
    elif total_pending < 10:
        print("  Lightweight triage session. Handle inline before next seed.")
    else:
        print("  Enough accumulated to justify a triage commit before next seed.")


if __name__ == "__main__":
    report()
