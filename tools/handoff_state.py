"""Handoff baton-protocol state parser.

Reads Status blocks from:
  - memory/HANDOFF.md (secondary's Status block, inline at top)
  - memory/INBOX/STATUS.md (primary's Status block, full file)

Outputs combined state in human-readable or JSON form. Used by primary's
monitor scripts to poll for counterpart-`awaiting-counterpart` transitions
without relying on mtime polling (which false-fires on mid-write edits).

Usage:
  python tools/handoff_state.py              # human-readable combined view
  python tools/handoff_state.py --json       # JSON for script consumption
  python tools/handoff_state.py --primary    # primary's block only
  python tools/handoff_state.py --secondary  # secondary's block only
  python tools/handoff_state.py --watch      # poll every 15s, emit on state change
  python tools/handoff_state.py --wait-for <value>
      # exit 0 when counterpart (secondary) reaches state=value; useful in
      # Monitor `until` loops instead of `sleep`+`grep` patterns

Reference: memory/HANDOFF_PROTOCOL.md
"""
from __future__ import annotations
import argparse
import json
import re
import sys
import time
from pathlib import Path

# Force utf-8 stdout so Unicode content in status-block notes (e.g., em-dash,
# right-arrow, smart quotes) doesn't crash on Windows cp1252 default.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

ROOT = Path(__file__).resolve().parent.parent
# Memory folder is outside the project tree — under the user's Claude config.
# Resolve via home directory so the path works regardless of where the repo
# sits in the filesystem.
_USER_HOME = Path.home()
MEM = _USER_HOME / ".claude" / "projects" / "C--Users-mondr-Documents-ProgFor-DFIRCLI" / "memory"
HANDOFF = MEM / "HANDOFF.md"
INBOX_STATUS = MEM / "INBOX" / "STATUS.md"

FIELDS = ("handoff-version", "state", "on", "blocker-type", "note", "as-of")
VALID_STATES = {"idle", "working", "blocked", "paused", "awaiting-counterpart"}


def _parse_block(text: str) -> dict:
    """Extract the status-block fields from markdown. Tolerates missing
    fields + returns None-valued fields for anything absent so callers
    get a consistent shape."""
    out = {f: None for f in FIELDS}
    # Match lines like `- **state:** value` OR `- **state:** value <trailing>`.
    for line in text.splitlines():
        m = re.match(r"^-\s*\*\*([a-z-]+):\*\*\s*(.*?)\s*$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if key in FIELDS:
            # strip surrounding em-dash placeholders for absent values
            if val in ("—", "-", ""):
                val = None
            out[key] = val
    return out


def read_secondary() -> dict:
    """Read secondary's Status block (inline in HANDOFF.md)."""
    if not HANDOFF.exists():
        return {"_error": f"HANDOFF not found at {HANDOFF}"}
    text = HANDOFF.read_text(encoding="utf-8", errors="replace")
    # Find the Status section — starts at `## Status — secondary` and runs
    # until the next `---` horizontal rule or next `##` heading.
    m = re.search(
        r"(?ms)^##\s+Status\s+—\s+secondary\s*\n(.*?)(?=\n---\s*\n|\n##\s|\Z)",
        text,
    )
    if not m:
        return {"_error": "secondary Status block not found in HANDOFF.md"}
    parsed = _parse_block(m.group(1))
    parsed["_source"] = str(HANDOFF.relative_to(MEM.parent))
    return parsed


def read_primary() -> dict:
    """Read primary's Status block (from memory/INBOX/STATUS.md)."""
    if not INBOX_STATUS.exists():
        return {"_error": f"INBOX/STATUS.md not found at {INBOX_STATUS}"}
    text = INBOX_STATUS.read_text(encoding="utf-8", errors="replace")
    parsed = _parse_block(text)
    parsed["_source"] = str(INBOX_STATUS.relative_to(MEM.parent))
    return parsed


def fmt_block(name: str, data: dict) -> str:
    if "_error" in data:
        return f"  {name:<10}  [error] {data['_error']}"
    state = data.get("state") or "(unknown)"
    on = data.get("on") or "—"
    note = data.get("note") or ""
    bt = data.get("blocker-type") or ""
    as_of = data.get("as-of") or ""
    out = [f"  {name:<10}  state={state:<20}  on={on}"]
    if bt and state == "blocked":
        out.append(f"              blocker-type={bt}")
    if note:
        out.append(f"              note={note[:100]}" + ("..." if len(note) > 100 else ""))
    if as_of:
        out.append(f"              as-of={as_of}")
    return "\n".join(out)


def combined_view() -> str:
    sec = read_secondary()
    pri = read_primary()
    lines = ["HANDOFF baton state (per memory/HANDOFF_PROTOCOL.md):", ""]
    lines.append(fmt_block("primary", pri))
    lines.append(fmt_block("secondary", sec))
    # Simple co-state interpretation
    sec_state = sec.get("state")
    pri_state = pri.get("state")
    if sec_state and pri_state:
        lines.append("")
        if sec_state == "awaiting-counterpart" and pri_state == "working":
            lines.append("  -> ball is in primary's court")
        elif pri_state == "awaiting-counterpart" and sec_state == "working":
            lines.append("  -> ball is in secondary's court")
        elif sec_state == "blocked" or pri_state == "blocked":
            lines.append("  -> one side is blocked; see blocker-type + note")
        elif sec_state == "idle" and pri_state == "idle":
            lines.append("  -> both idle; no in-flight baton")
    return "\n".join(lines)


def watch(interval: int = 15) -> None:
    """Poll every <interval> seconds; emit a line on any state change."""
    prev = (read_primary().get("state"), read_secondary().get("state"))
    print(f"[watch] starting (interval={interval}s); initial state primary={prev[0]} secondary={prev[1]}")
    while True:
        time.sleep(interval)
        cur = (read_primary().get("state"), read_secondary().get("state"))
        if cur != prev:
            ts = time.strftime("%H:%M:%S")
            print(f"[watch {ts}] primary: {prev[0]} -> {cur[0]} | secondary: {prev[1]} -> {cur[1]}")
            prev = cur


def wait_for(value: str, side: str = "secondary", interval: int = 15) -> int:
    """Block until <side>'s state matches <value>. Returns 0 on match, 2 on invalid input."""
    if value not in VALID_STATES:
        print(f"invalid state value: {value}. Must be one of: {sorted(VALID_STATES)}", file=sys.stderr)
        return 2
    if side not in ("primary", "secondary"):
        print(f"invalid side: {side}. Must be 'primary' or 'secondary'", file=sys.stderr)
        return 2
    reader = read_primary if side == "primary" else read_secondary
    while True:
        state = reader().get("state")
        if state == value:
            ts = time.strftime("%H:%M:%S")
            print(f"[wait-for {ts}] {side} reached state={value}")
            return 0
        time.sleep(interval)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="output JSON instead of human-readable")
    ap.add_argument("--primary", action="store_true", help="show only primary's block")
    ap.add_argument("--secondary", action="store_true", help="show only secondary's block")
    ap.add_argument("--watch", action="store_true", help="poll every 15s and emit on state change")
    ap.add_argument("--wait-for", metavar="STATE", help="block until secondary reaches STATE (use with --side primary for primary)")
    ap.add_argument("--side", default="secondary", choices=("primary", "secondary"), help="which side --wait-for applies to")
    ap.add_argument("--interval", type=int, default=15, help="polling interval in seconds (--watch / --wait-for)")
    args = ap.parse_args()

    if args.watch:
        try:
            watch(args.interval)
        except KeyboardInterrupt:
            return 0
        return 0

    if args.wait_for:
        return wait_for(args.wait_for, args.side, args.interval)

    if args.primary:
        data = read_primary()
    elif args.secondary:
        data = read_secondary()
    else:
        data = {"primary": read_primary(), "secondary": read_secondary()}

    if args.json:
        print(json.dumps(data, indent=2, default=str))
    elif args.primary or args.secondary:
        name = "primary" if args.primary else "secondary"
        print(fmt_block(name, data))
    else:
        print(combined_view())
    return 0


if __name__ == "__main__":
    sys.exit(main())
