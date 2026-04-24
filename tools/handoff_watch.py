"""HANDOFF / INBOX watcher — streaming events for primary+secondary coordination.

Unified watcher both instances can share (either can run it; emitted events
are the same). Combines three prior behaviors into one tool:

  1. file-mtime watch — emits when HANDOFF.md or INBOX/*.md changes.
     (Was: monitor b0reyg6mk inlined in primary's session.)
  2. mutual-idle beacon — emits a green-icon line when both Status blocks
     read `awaiting-counterpart` simultaneously.
     (Was: monitor bfshrfk7r inlined in primary's session.)
  3. state-transition emit — emits when either side's state changes
     (working -> awaiting-counterpart, etc). Useful for detecting that
     the counterpart picked up or released a task.

Each event is a single stdout line — consumable by any Monitor-style
tool or by plain tail-pipe-grep.

Usage:
  python tools/handoff_watch.py --mode all          # everything (default)
  python tools/handoff_watch.py --mode files        # file changes only
  python tools/handoff_watch.py --mode beacon       # mutual-idle only
  python tools/handoff_watch.py --mode state        # state transitions only
  python tools/handoff_watch.py --state             # one-shot: print both Status blocks and exit
  python tools/handoff_watch.py --poll-s 4          # file-mtime poll interval (default 4)
  python tools/handoff_watch.py --beacon-s 10       # mutual-idle re-emit interval (default 10)

Memory-folder write rules respected: this script reads only — no writes.
Secondary can invoke this from project folder without permission issues.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import time

sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")

MEMORY_ROOT = pathlib.Path(
    r"C:\Users\mondr\.claude\projects\C--Users-mondr-Documents-ProgFor-ArtifactExplorer\memory"
)
HANDOFF = MEMORY_ROOT / "HANDOFF.md"
INBOX = MEMORY_ROOT / "INBOX"
STATUS = INBOX / "STATUS.md"

STATE_PATTERN = re.compile(r"\*\*state:\*\* ([a-z-]+)")
ON_PATTERN = re.compile(r"\*\*on:\*\* ([^\n]+)")


def read_state(path: pathlib.Path) -> tuple[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:
        return "err", str(e)[:60]
    m = STATE_PATTERN.search(text)
    state = m.group(1) if m else "unknown"
    on = ""
    mo = ON_PATTERN.search(text)
    if mo:
        on = mo.group(1).strip()[:120]
    return state, on


def snap_mtimes() -> dict[str, float]:
    state: dict[str, float] = {}
    if HANDOFF.exists():
        state["HANDOFF.md"] = HANDOFF.stat().st_mtime
    for p in INBOX.glob("*.md"):
        state[f"INBOX/{p.name}"] = p.stat().st_mtime
    return state


def oneshot_state() -> None:
    p_state, p_on = read_state(STATUS)
    s_state, s_on = read_state(HANDOFF)
    print(f"primary.state   = {p_state}")
    print(f"primary.on      = {p_on}")
    print(f"secondary.state = {s_state}")
    print(f"secondary.on    = {s_on}")
    IDLE_LIKE = {"idle", "awaiting-counterpart", "paused"}
    mutual = (p_state in IDLE_LIKE and s_state in IDLE_LIKE)
    print(f"mutual-idle     = {mutual}")


def watch(mode: str, poll_s: float, beacon_s: float) -> None:
    """Stream events. Exit via signal / timeout."""
    prev_files = snap_mtimes() if mode in ("all", "files") else {}
    prev_p_state, prev_s_state = None, None
    if mode in ("all", "state", "beacon"):
        prev_p_state, _ = read_state(STATUS)
        prev_s_state, _ = read_state(HANDOFF)

    print(
        f"[handoff-watch] armed mode={mode} poll-s={poll_s} beacon-s={beacon_s} "
        f"initial primary={prev_p_state} secondary={prev_s_state} files={len(prev_files)}"
    )

    last_beacon = 0.0
    while True:
        time.sleep(poll_s)
        now = time.time()

        # --- File-mtime events ---
        if mode in ("all", "files"):
            try:
                cur_files = snap_mtimes()
            except Exception as e:
                print(f"[handoff-watch] files-err {e}")
                cur_files = prev_files
            added = set(cur_files) - set(prev_files)
            removed = set(prev_files) - set(cur_files)
            changed = [k for k in cur_files if k in prev_files and cur_files[k] != prev_files[k]]
            for k in sorted(added):
                print(f"[+new] {k}")
            for k in sorted(removed):
                print(f"[-del] {k}")
            for k in sorted(changed):
                print(f"[mod] {k}")
            prev_files = cur_files

        # --- State-transition events ---
        if mode in ("all", "state", "beacon"):
            p_state, p_on = read_state(STATUS)
            s_state, s_on = read_state(HANDOFF)
            if mode in ("all", "state"):
                if p_state != prev_p_state:
                    print(f"[state] primary: {prev_p_state} -> {p_state} | on: {p_on}")
                if s_state != prev_s_state:
                    print(f"[state] secondary: {prev_s_state} -> {s_state} | on: {s_on}")
            prev_p_state, prev_s_state = p_state, s_state

            # --- Mutual-idle beacon ---
            # Fires when NEITHER side is actively working — i.e., both are in
            # an idle-like state (idle / awaiting-counterpart / paused). The
            # intent is "nobody's going to move without external prompt."
            # `working` and `blocked` are the active states that suppress the
            # beacon; unknown/err states also suppress.
            if mode in ("all", "beacon"):
                IDLE_LIKE = {"idle", "awaiting-counterpart", "paused"}
                if p_state in IDLE_LIKE and s_state in IDLE_LIKE:
                    if now - last_beacon >= beacon_s:
                        print(
                            f"\U0001F7E2 MUTUAL-IDLE \U0001F7E2 "
                            f"primary={p_state} + secondary={s_state} "
                            f"— no counterpart-bound activity \U0001F7E2"
                        )
                        last_beacon = now


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--mode",
        choices=["all", "files", "state", "beacon"],
        default="all",
        help="which event classes to emit",
    )
    ap.add_argument("--state", action="store_true", help="one-shot state dump, then exit")
    ap.add_argument("--poll-s", type=float, default=4.0, help="file-mtime + state poll interval")
    ap.add_argument("--beacon-s", type=float, default=10.0, help="mutual-idle re-emit interval")
    args = ap.parse_args()

    if args.state:
        oneshot_state()
        return

    try:
        watch(args.mode, args.poll_s, args.beacon_s)
    except KeyboardInterrupt:
        print("[handoff-watch] interrupted; exiting.")


if __name__ == "__main__":
    main()
