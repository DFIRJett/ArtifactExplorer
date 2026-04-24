#!/usr/bin/env python3
"""
One-shot migration: for each artifact frontmatter, replace the legacy
`sources:` block with a new `provenance:` array of source-registry IDs.

Uses tools/_provenance_map.yaml (produced by extract_sources.py) to know
which artifact gets which IDs.

Preserves document byte-for-byte EXCEPT that:
  - every `sources:\n(...indented block...)` is removed
  - a `provenance:` block is inserted in its place (as a flow list when
    small, block list otherwise), using the IDs in the map
  - file ends unchanged (body after closing --- is never touched)

Idempotent: re-running when `sources:` is already absent is a no-op.
"""
from __future__ import annotations
import re
import sys
import pathlib
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAP = ROOT / "tools" / "_provenance_map.yaml"


def load_map() -> dict[str, list[str]]:
    data = yaml.safe_load(MAP.read_text(encoding="utf-8"))
    out: dict[str, list[str]] = {}
    for m in data["mapping"]:
        rel = m["artifact"].replace("/", "\\") if sys.platform == "win32" else m["artifact"]
        # store both forward-slash and native forms
        ids = [entry["id"] if isinstance(entry, dict) else entry for entry in m["provenance"]]
        out[m["artifact"]] = ids
    return out


SOURCES_RE = re.compile(r"(?m)^sources:\s*\n(?:(?: {2,}|\t).*\n|\s*-[ \t].*\n(?:(?: {2,}|\t).*\n)*)+")


def render_provenance(ids: list[str]) -> str:
    if not ids:
        return "provenance: []\n"
    if len(ids) <= 4 and sum(len(i) for i in ids) < 100:
        return "provenance: [" + ", ".join(ids) + "]\n"
    lines = ["provenance:"]
    for sid in ids:
        lines.append(f"  - {sid}")
    return "\n".join(lines) + "\n"


def migrate_file(path: pathlib.Path, ids: list[str]) -> bool:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return False
    # Split into fm / body
    parts = text.split("---", 2)
    if len(parts) < 3:
        return False
    fm = parts[1]
    body = "---".join(parts[2:]) if False else parts[2]

    # Remove sources: block from fm
    new_fm, n = SOURCES_RE.subn("", fm)
    # If file had provenance: already, leave alone (idempotent)
    if re.search(r"(?m)^provenance:", new_fm):
        if n == 0:
            return False  # nothing to do
        # else sources: got stripped above but provenance existed; still save
        final = "---" + new_fm + "---" + body
        path.write_text(final, encoding="utf-8", newline="")
        return True

    # Insert provenance block at end of fm (before closing ---)
    # Strip trailing newlines of fm, then add provenance, then one newline
    stripped = new_fm.rstrip("\n")
    prov = render_provenance(ids)
    new_fm_final = stripped + "\n" + prov

    final = "---" + new_fm_final + "---" + body
    path.write_text(final, encoding="utf-8", newline="")
    return True


def main():
    mapping = load_map()
    # Also compute unsourced artifacts (all *.md under artifacts/ not in mapping)
    all_artifacts = sorted(str(p.relative_to(ROOT)).replace("\\", "/")
                            for p in (ROOT / "artifacts").rglob("*.md"))
    sourced = set(mapping.keys())
    unsourced = [a for a in all_artifacts if a not in sourced]

    n_updated = 0
    n_empty = 0
    for rel, ids in mapping.items():
        p = ROOT / rel
        if migrate_file(p, ids):
            n_updated += 1
    for rel in unsourced:
        p = ROOT / rel
        if migrate_file(p, []):
            n_empty += 1
    print(f"Migrated {n_updated} sourced artifacts")
    print(f"Added empty provenance to {n_empty} unsourced artifacts")
    print(f"Total artifacts covered: {n_updated + n_empty} / {len(all_artifacts)}")


if __name__ == "__main__":
    main()
