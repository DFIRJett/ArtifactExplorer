"""URL-health sweep — check every URL in schema/sources.yaml for liveness.

Motivation: 5 MS Learn URL-rot incidents surfaced during r3/r4 audits
(ProfileList / Credentials-cached / LSA-Cached-Logons / Security-5381 /
Security-5379). All followed the same pattern — docs migrated from
/threat-protection/auditing/ to /previous-versions/windows/it-pro/... —
and each slipped through because audits only fetch the URLs relevant
to their focal artifact. This tool sweeps them all at once.

Classification:
  ok              HTTP 200 / 301-307 to a 200
  404             Not Found (target for URL replacement)
  403             Forbidden (bot filter — page is usually live; NOT rot)
  5xx             Server error (transient; flag for re-check)
  timeout         no response within cutoff
  conn-error      DNS / connection reset / TLS failure
  skip            non-http URL (filesystem paths, anchor-only, etc.)

Output:
  tools/_url_health_report.yaml — structured per-source status
  stdout — human summary (counts + 404 list by source-id)

Usage: python tools/url_health_sweep.py [--workers N] [--timeout S]
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import pathlib
import sys
import time
import urllib.request
import urllib.error
import yaml
import ssl

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(r"C:\Users\mondr\Documents\ProgFor\ArtifactExplorer")
SOURCES = ROOT / "schema" / "sources.yaml"
REPORT = ROOT / "tools" / "_url_health_report.yaml"

HDRS = {
    "User-Agent": "Mozilla/5.0 (ArtifactExplorer URL-health sweep; see schema/sources.yaml)",
    "Accept": "*/*",
}


def classify_url(url: str, timeout: float = 6.0) -> tuple[str, str]:
    if not url or not isinstance(url, str):
        return "skip", "no-url"
    if not url.lower().startswith(("http://", "https://")):
        return "skip", "non-http"
    ctx = ssl.create_default_context()
    # Some MS / GitHub pages are strict about UA; the custom header above helps.
    req = urllib.request.Request(url, headers=HDRS, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            code = r.status
            if 200 <= code < 300:
                return "ok", str(code)
            if 300 <= code < 400:
                return "ok", f"redirect-{code}"
            return f"{code}", f"http-{code}"
    except urllib.error.HTTPError as e:
        code = e.code
        if code == 405:
            # HEAD not allowed; retry with GET
            try:
                req2 = urllib.request.Request(url, headers=HDRS, method="GET")
                with urllib.request.urlopen(req2, timeout=timeout, context=ctx) as r:
                    c2 = r.status
                    if 200 <= c2 < 300:
                        return "ok", f"get-{c2}"
                    return f"{c2}", f"get-{c2}"
            except urllib.error.HTTPError as e2:
                return str(e2.code), f"get-{e2.code}"
            except Exception as e2:
                return "conn-error", str(e2)[:80]
        if code == 404:
            return "404", "http-404"
        if code == 403:
            return "403", "http-403"
        if 500 <= code < 600:
            return f"5xx", f"http-{code}"
        return str(code), f"http-{code}"
    except urllib.error.URLError as e:
        reason = str(e.reason) if hasattr(e, "reason") else str(e)
        if "timed out" in reason.lower():
            return "timeout", "timeout"
        return "conn-error", reason[:80]
    except TimeoutError:
        return "timeout", "timeout"
    except Exception as e:
        return "conn-error", str(e)[:80]


def load_sources() -> list[dict]:
    with open(SOURCES, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("sources") or []


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--limit", type=int, default=0, help="cap sources (0 = all)")
    args = ap.parse_args()

    sources = load_sources()
    if args.limit:
        sources = sources[:args.limit]
    print(f"Sweeping {len(sources)} sources (workers={args.workers}, timeout={args.timeout}s)...")
    t0 = time.time()

    results: list[dict] = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {
            ex.submit(classify_url, s.get("url", ""), args.timeout): s
            for s in sources
        }
        done = 0
        for fut in cf.as_completed(futures):
            s = futures[fut]
            try:
                status, detail = fut.result()
            except Exception as e:
                status, detail = "conn-error", str(e)[:80]
            results.append({
                "id": s.get("id", ""),
                "url": s.get("url", ""),
                "status": status,
                "detail": detail,
                "kind": s.get("kind", ""),
            })
            done += 1
            if done % 50 == 0:
                print(f"  ...{done}/{len(sources)} ({time.time()-t0:.1f}s)")

    # Tally
    from collections import Counter
    tally = Counter(r["status"] for r in results)
    print()
    print(f"Done in {time.time()-t0:.1f}s. Results:")
    for k, v in tally.most_common():
        print(f"  {k:<12} {v}")

    # 404 list (the actionable category)
    four04 = [r for r in results if r["status"] == "404"]
    if four04:
        print()
        print(f"404 sources ({len(four04)}):")
        for r in sorted(four04, key=lambda r: r["id"]):
            print(f"  {r['id']:<55} {r['url']}")

    # 5xx list (transient — flag for re-check)
    fxx = [r for r in results if r["status"] == "5xx"]
    if fxx:
        print()
        print(f"5xx sources ({len(fxx)}):")
        for r in sorted(fxx, key=lambda r: r["id"]):
            print(f"  {r['id']:<55} {r['detail']}  {r['url']}")

    # Conn-error list
    conn = [r for r in results if r["status"] == "conn-error"]
    if conn:
        print()
        print(f"conn-error sources ({len(conn)}):")
        for r in sorted(conn, key=lambda r: r["id"])[:20]:
            print(f"  {r['id']:<55} {r['detail']}")
        if len(conn) > 20:
            print(f"  ... ({len(conn)-20} more)")

    # Structured report
    report = {
        "swept-at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source-count": len(sources),
        "elapsed-seconds": round(time.time() - t0, 1),
        "tally": dict(tally),
        "results": sorted(results, key=lambda r: (r["status"], r["id"])),
    }
    REPORT.write_text(
        yaml.safe_dump(report, sort_keys=False, allow_unicode=True, width=1_000_000),
        encoding="utf-8",
    )
    print()
    print(f"Wrote {REPORT.name}")


if __name__ == "__main__":
    main()
