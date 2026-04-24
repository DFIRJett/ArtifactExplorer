"""Dead-source verification tool — multi-check liveness + Wayback archive lookup.

Usage:
  python tools/verify_dead_sources.py <source-id> [<source-id> ...]
  python tools/verify_dead_sources.py --all-suspicious     # runs against verified-dead-pending + a curated suspicious list
  python tools/verify_dead_sources.py --dead-pending       # runs against sources marked verified-dead-pending in crawl_state

For each target URL, the tool performs:
  1. HEAD request via curl with a common user-agent (detects transient vs true dead)
  2. URL-variant attempts (trailing slash, www / no-www prefix)
  3. Wayback Machine snapshot lookup via https://archive.org/wayback/available?url=<url>
  4. Final verdict: alive / moved-to <url> / dead-confirmed + (wayback snapshot if available)

Never modifies schema/sources.yaml or crawl_state.yaml — produces a report.
The report can be used to decide per-source: keep / update URL / mark verified-dead / remove.

Exit codes: 0 (all checked), 1 (invalid args).
"""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
import io
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import yaml

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "schema" / "sources.yaml"
CRAWL_STATE = ROOT / "tools" / "crawl_state.yaml"

UA = "Mozilla/5.0 (compatible; ArtifactExplorer-crawl-verifier/1.0)"
TIMEOUT = 15

# Sources proactively flagged as possibly-dead (same mechanical batch as the
# already-confirmed-dead ms-driverframeworks-um-operational)
SUSPICIOUS_LIST = [
    "ms-scm-events",
    "ms-powershell-operational",
    "ms-tsv-lsm-operational",
    "ms-dns-client-operational",
    "ms-defender-events",
]


def head(url: str) -> tuple[int, str]:
    """Return (status_code, final_url_after_redirects). Returns (0, '') on failure.

    Note: we parse stdout regardless of curl's returncode — curl may return
    rc=23 on Windows due to /dev/null write failures even when the HTTP
    request itself succeeded and -w values are present in stdout. Only
    missing stdout indicates actual no-response.
    """
    try:
        r = subprocess.run(
            ["curl", "-sI", "-L", "-A", UA, "--max-time", str(TIMEOUT), "-o", "/dev/null",
             "-w", "%{http_code}|%{url_effective}", url],
            capture_output=True, text=True, timeout=TIMEOUT + 5)
        if not r.stdout.strip():
            return (0, "")
        parts = r.stdout.strip().split("|", 1)
        code = int(parts[0]) if parts[0].isdigit() else 0
        final = parts[1] if len(parts) > 1 else ""
        return (code, final)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return (0, "")


def variants(url: str) -> list[str]:
    """Yield URL variants to try when primary returns non-200."""
    p = urlparse(url)
    out = [url]
    # Toggle trailing slash
    if p.path.endswith("/"):
        out.append(urlunparse(p._replace(path=p.path.rstrip("/"))))
    else:
        out.append(urlunparse(p._replace(path=p.path + "/")))
    # Toggle www
    if p.netloc.startswith("www."):
        out.append(urlunparse(p._replace(netloc=p.netloc[4:])))
    else:
        out.append(urlunparse(p._replace(netloc="www." + p.netloc)))
    # Force https if http
    if p.scheme == "http":
        out.append(urlunparse(p._replace(scheme="https")))
    return list(dict.fromkeys(out))  # preserve order, dedup


def wayback_snapshot(url: str) -> dict:
    """Return Wayback Machine info: {available, url, timestamp} or {available: False}."""
    api = f"https://archive.org/wayback/available?url={url}"
    try:
        r = subprocess.run(
            ["curl", "-s", "-A", UA, "--max-time", str(TIMEOUT), api],
            capture_output=True, text=True, timeout=TIMEOUT + 5)
        if r.returncode != 0:
            return {"available": False, "reason": f"curl rc={r.returncode}"}
        d = json.loads(r.stdout)
        closest = (d.get("archived_snapshots") or {}).get("closest") or {}
        if closest.get("available"):
            return {
                "available": True,
                "url": closest.get("url"),
                "timestamp": closest.get("timestamp"),
                "status": closest.get("status"),
            }
        return {"available": False}
    except Exception as e:
        return {"available": False, "reason": str(e)}


def verify_one(sid: str, url: str) -> dict:
    """Return a verdict record for one source."""
    result = {"id": sid, "url": url, "attempts": [], "verdict": None}

    for i, variant in enumerate(variants(url)):
        code, final = head(variant)
        result["attempts"].append({"url": variant, "status": code, "final": final})
        if code and 200 <= code < 400:
            result["verdict"] = "alive"
            if final and final != variant and final != url:
                result["verdict"] = "moved"
                result["new-url"] = final
            else:
                result["new-url"] = variant if variant != url else None
            return result
        # Soft-wall detection: 403 / 429 is NOT dead, just blocked
        if code in (403, 429):
            result["verdict"] = "bot-blocked"
            result["suggestion"] = "page likely live; WebFetch/curl blocked. Verify via browser."
            return result

    # All variants returned non-2xx and non-bot-block. Check Wayback
    wb = wayback_snapshot(url)
    result["wayback"] = wb
    if wb.get("available"):
        result["verdict"] = "dead-with-wayback"
        result["suggestion"] = f"page 404 live but Wayback has snapshot ({wb['timestamp']}) — preserve reference via Wayback URL"
    else:
        result["verdict"] = "dead-confirmed"
        result["suggestion"] = "page 404 + no Wayback snapshot — safe to remove"
    return result


def load_sources() -> dict[str, str]:
    return {s["id"]: s["url"] for s in yaml.safe_load(SOURCES.read_text(encoding="utf-8"))["sources"]}


def load_dead_pending() -> list[str]:
    if not CRAWL_STATE.exists():
        return []
    cs = yaml.safe_load(CRAWL_STATE.read_text(encoding="utf-8")) or {}
    vl_sources = (cs.get("verification_log") or {}).get("sources") or {}
    return [sid for sid, meta in vl_sources.items()
            if (meta or {}).get("status") == "verified-dead-pending"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*", help="Source IDs to verify")
    ap.add_argument("--all-suspicious", action="store_true",
                    help="Run against the hardcoded SUSPICIOUS_LIST")
    ap.add_argument("--dead-pending", action="store_true",
                    help="Run against crawl_state verified-dead-pending sources")
    args = ap.parse_args()

    srcs = load_sources()
    targets = list(args.ids)
    if args.all_suspicious:
        targets.extend(SUSPICIOUS_LIST)
    if args.dead_pending:
        targets.extend(load_dead_pending())

    if not targets:
        print("No targets. Provide IDs, --all-suspicious, or --dead-pending.")
        return 1
    targets = list(dict.fromkeys(targets))  # dedup preserve order

    results = []
    for sid in targets:
        url = srcs.get(sid)
        if not url:
            print(f"\n!! {sid}: NOT IN REGISTRY")
            continue
        r = verify_one(sid, url)
        results.append(r)
        print(f"\n=== {sid} ===")
        print(f"  URL: {url}")
        for a in r["attempts"]:
            print(f"    {a['status']:>3}  {a['url'][:80]}")
        if r.get("wayback"):
            wb = r["wayback"]
            if wb.get("available"):
                print(f"  Wayback: {wb.get('url')} ({wb.get('timestamp')})")
            else:
                print(f"  Wayback: none available")
        print(f"  VERDICT: {r['verdict']}")
        if r.get("new-url"):
            print(f"  NEW URL: {r['new-url']}")
        if r.get("suggestion"):
            print(f"  SUGGEST: {r['suggestion']}")

    # Summary
    print()
    print("=" * 72)
    print(f"Summary: {len(results)} verified")
    by_verdict = {}
    for r in results:
        by_verdict.setdefault(r["verdict"], []).append(r["id"])
    for v, ids in by_verdict.items():
        print(f"  {v:<20} {len(ids):>3} — {', '.join(ids)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
