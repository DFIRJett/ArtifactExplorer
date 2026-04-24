"""
DFIRCLI dev server + file watcher.

Starts a local HTTP server for viewer/ and watches artifact/container/schema
files. On any change, rebuilds viewer/data.json automatically. You just
reload the browser.

Usage:
    python tools/serve.py               # default http://localhost:8000
    python tools/serve.py --port 8001
    python tools/serve.py --no-open     # don't auto-open browser

Stop with Ctrl+C.
"""

from __future__ import annotations

import argparse
import http.server
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VIEWER_DIR = ROOT / "viewer"
WATCH_DIRS = [
    ROOT / "artifacts",
    ROOT / "substrates",
    ROOT / "schema",
    ROOT / "scenarios",
    ROOT / "concepts",
    ROOT / "convergences",
]
BUILD_SCRIPT = ROOT / "tools" / "build-graph.py"


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler rooted at viewer/, no per-request log noise."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(VIEWER_DIR), **kwargs)

    def log_message(self, *_a, **_kw):
        pass  # suppress per-request logs; watcher output is the signal

    def end_headers(self):
        # Tell the browser never to cache data.json so reload always fetches fresh.
        if self.path.endswith("data.json"):
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        super().end_headers()


class DualStackServer(http.server.ThreadingHTTPServer):
    """Listens on both IPv4 (127.0.0.1) and IPv6 (::1).

    Windows resolves 'localhost' to ::1 by default; a v4-only bind causes
    the browser to hit ::1 and get 'connection refused' while curl still
    works via 127.0.0.1. Dual-stack fixes both.
    """

    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        # Accept IPv4 clients too (disable IPv6-only mode).
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except (AttributeError, OSError):
            pass
        super().server_bind()


def start_server(port: int) -> http.server.ThreadingHTTPServer:
    # Try dual-stack IPv6+IPv4 first. Fall back to IPv4-only if IPv6 is disabled.
    try:
        httpd = DualStackServer(("::", port), QuietHandler)
    except OSError as e_v6:
        try:
            httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), QuietHandler)
        except OSError as e_v4:
            print(f"Failed to bind port {port}:")
            print(f"  IPv6 attempt: {e_v6}")
            print(f"  IPv4 attempt: {e_v4}")
            print(f"Try a different port: python tools/serve.py --port {port + 1}")
            sys.exit(1)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


def verify_reachable(port: int, timeout: float = 2.0) -> list[str]:
    """Return list of localhost addresses that successfully connect."""
    reachable = []
    for host in ("127.0.0.1", "::1"):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                reachable.append(host)
        except OSError:
            pass
    return reachable


def snapshot_mtimes(dirs: list[Path]) -> dict[str, int]:
    out: dict[str, int] = {}
    for d in dirs:
        if not d.exists():
            continue
        for p in d.rglob("*.md"):
            try:
                out[str(p)] = p.stat().st_mtime_ns
            except (FileNotFoundError, PermissionError):
                pass
    # Also watch the build script itself — editing it should trigger a rebuild.
    try:
        out[str(BUILD_SCRIPT)] = BUILD_SCRIPT.stat().st_mtime_ns
    except FileNotFoundError:
        pass
    return out


def run_build() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [sys.executable, str(BUILD_SCRIPT)],
            check=True,
            capture_output=True,
            text=True,
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, (e.stdout or "") + (e.stderr or "")
    except FileNotFoundError:
        return False, f"build script not found: {BUILD_SCRIPT}"


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def rel(path: str) -> str:
    try:
        return str(Path(path).relative_to(ROOT))
    except ValueError:
        return path


def classify_changes(
    before: dict[str, int], after: dict[str, int]
) -> tuple[list[str], list[str], list[str]]:
    added = sorted(p for p in after if p not in before)
    removed = sorted(p for p in before if p not in after)
    modified = sorted(p for p in after if p in before and after[p] != before[p])
    return added, modified, removed


def main() -> None:
    ap = argparse.ArgumentParser(
        description="DFIRCLI dev server + auto-rebuild watcher"
    )
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="seconds between filesystem checks",
    )
    ap.add_argument(
        "--debounce",
        type=float,
        default=3.0,
        help="seconds of filesystem quiet required before rebuilding. "
             "Lets rapid batches of edits produce a single rebuild instead of N. "
             "Set to 0 to rebuild immediately on any change.",
    )
    ap.add_argument(
        "--no-open",
        action="store_true",
        help="do not auto-open the browser",
    )
    args = ap.parse_args()

    # Initial build.
    print(f"[{ts()}] initial build...")
    ok, output = run_build()
    if ok:
        for line in output.strip().splitlines():
            print(f"           {line}")
    else:
        print(f"           BUILD FAILED:\n{output}")

    # Start server.
    httpd = start_server(args.port)

    # Verify connectivity on both v4 and v6 loopback (Windows-localhost sanity).
    time.sleep(0.3)
    reachable = verify_reachable(args.port)
    if not reachable:
        print(f"[{ts()}] WARNING: server bound but loopback not reachable. Check firewall.")
    else:
        if "127.0.0.1" in reachable and "::1" in reachable:
            print(f"[{ts()}] server listening (dual-stack IPv4 + IPv6)")
        elif "127.0.0.1" in reachable:
            print(f"[{ts()}] server listening (IPv4 only)")
        elif "::1" in reachable:
            print(f"[{ts()}] server listening (IPv6 only)")

    url = f"http://localhost:{args.port}"
    url_v4 = f"http://127.0.0.1:{args.port}"
    print(f"[{ts()}] open:  {url}")
    print(f"[{ts()}]   or:  {url_v4}  (if 'localhost' misbehaves)")
    print(f"[{ts()}] watching {', '.join(str(d.relative_to(ROOT)) for d in WATCH_DIRS)} + tools/build-graph.py")
    if args.debounce > 0:
        print(f"[{ts()}] debounce: {args.debounce}s (batches of saves coalesce into one rebuild)")
    print(f"[{ts()}] edit any .md file — browser reload shows updates. Ctrl+C to stop.\n")

    if not args.no_open:
        try:
            webbrowser.open(url, new=2)
        except Exception:
            pass  # headless / no display — not fatal

    # Watch loop with debounce:
    #   - On file change, capture the PRE-BATCH snapshot once and keep updating
    #     `last` as changes continue
    #   - Only rebuild after `debounce` seconds of filesystem quiet
    #   - Rapid batches coalesce into one rebuild reporting all changes together
    last = snapshot_mtimes(WATCH_DIRS)
    pending_pre_snapshot = None     # state before the batch started
    quiet_seconds = 0.0

    try:
        while True:
            time.sleep(args.poll_interval)
            now = snapshot_mtimes(WATCH_DIRS)

            if now != last:
                # Filesystem changed — (re)start the debounce window
                if pending_pre_snapshot is None:
                    pending_pre_snapshot = last
                last = now
                quiet_seconds = 0.0
                if args.debounce == 0:
                    # Immediate-mode — skip debounce and rebuild below
                    pass
                else:
                    continue

            if pending_pre_snapshot is None:
                continue  # no pending changes

            # Stable poll; accumulate quiet time
            quiet_seconds += args.poll_interval
            if args.debounce > 0 and quiet_seconds < args.debounce:
                continue

            # Debounce window satisfied — rebuild now
            added, modified, removed = classify_changes(pending_pre_snapshot, now)
            print(f"\n[{ts()}] batch changes ({len(added)+len(modified)+len(removed)} file(s)):")
            for p in added:
                print(f"           + {rel(p)}")
            for p in modified:
                print(f"           ~ {rel(p)}")
            for p in removed:
                print(f"           - {rel(p)}")

            ok, output = run_build()
            if ok:
                last_line = output.strip().splitlines()[-1] if output.strip() else ""
                print(f"[{ts()}] rebuilt — reload browser")
                if last_line:
                    print(f"           {last_line}")
            else:
                print(f"[{ts()}] BUILD FAILED:\n{output}")
                # Keep pending state cleared so next batch isn't blamed
                # for this build's error; the next filesystem change will
                # kick off a fresh debounce cycle.
                pending_pre_snapshot = None
                quiet_seconds = 0.0
                continue

            pending_pre_snapshot = None
            quiet_seconds = 0.0
    except KeyboardInterrupt:
        print(f"\n[{ts()}] shutting down.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
