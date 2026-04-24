"""Populate provenance on all convergences and scenarios.

For each convergence:
  base = union of member-artifact provenance (via input-sources.artifacts)
  methodology = Casey scale + catalogs + tier-3 behavior
  +ms-advanced-audit-policy if touches windows-evtx
  +regripper-plugins if touches windows-registry-hive
  final = dedup(base + methodology)

For each scenario:
  base = union of member-artifact provenance via step.artifacts + convergence-referenced artifacts
  methodology = Casey scale + DFIR Report + catalogs + tier-3 behavior
  + substrate-specific additions
  final = dedup(base + methodology)

Writes provenance as a block-list at the end of each entity's frontmatter.
"""
import sys, io, re, pathlib, yaml
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

ROOT = pathlib.Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts"
CONVERGENCES = ROOT / "convergences"
SCENARIOS = ROOT / "scenarios"

# Methodology sources to apply universally per tier
CONV_METHODOLOGY = [
    "casey-2002-error-uncertainty-loss-digital-evidence",
    "casey-2020-standardization-evaluative-opinions",
    "forensicartifacts-repo",
    "kape-files-repo",
    "insiderthreatmatrix-repo",
]

SCENARIO_METHODOLOGY = CONV_METHODOLOGY + [
    "thedfirreport",
]

# Substrate-triggered additions
SUBSTRATE_SOURCES = {
    "windows-evtx":          "ms-advanced-audit-policy",
    "windows-registry-hive": "regripper-plugins",
}


def read_fm(path: pathlib.Path) -> tuple[str, dict, str]:
    """Return (pre, parsed_fm, post) where pre+fm_text+post reconstitutes the file.
    Returns (None, None, None) if no frontmatter."""
    txt = path.read_text(encoding="utf-8")
    if not txt.startswith("---"):
        return None, None, None
    parts = txt.split("---", 2)
    if len(parts) < 3:
        return None, None, None
    try:
        fm = yaml.safe_load(parts[1]) or {}
    except Exception as e:
        print(f"  YAML error in {path.name}: {e}", file=sys.stderr)
        return None, None, None
    return parts[0], fm, parts[2]


PROVENANCE_RE = re.compile(
    r"(?m)^provenance:[ \t]*(?:\[.*?\]|(?:\n(?:[ \t]+-.*(?:\n(?![ \t]).*)*))*)\n?"
)


def render_provenance_block(ids: list[str]) -> str:
    if not ids:
        return "provenance: []\n"
    lines = ["provenance:"]
    for sid in ids:
        lines.append(f"  - {sid}")
    return "\n".join(lines) + "\n"


def write_provenance(path: pathlib.Path, ids: list[str]) -> None:
    """Insert or replace provenance in the frontmatter of path."""
    text = path.read_text(encoding="utf-8")
    parts = text.split("---", 2)
    fm_text = parts[1]
    body = parts[2]
    # Remove any existing provenance block
    new_fm, _ = PROVENANCE_RE.subn("", fm_text)
    # Append new provenance
    stripped = new_fm.rstrip("\n")
    final_fm = stripped + "\n" + render_provenance_block(ids)
    path.write_text("---" + final_fm + "---" + body, encoding="utf-8", newline="")


def load_artifact_provenance() -> dict[str, list[str]]:
    """Return { artifact_name: [source_ids] }."""
    out = {}
    for md in ARTIFACTS.rglob("*.md"):
        _, fm, _ = read_fm(md)
        if not fm:
            continue
        name = fm.get("name", md.stem)
        prov = fm.get("provenance") or []
        ids = [p if isinstance(p, str) else p.get("source") for p in prov]
        ids = [i for i in ids if i]
        out[name] = ids
    return out


def load_artifact_substrates() -> dict[str, str]:
    """Return { artifact_name: substrate }."""
    out = {}
    for md in ARTIFACTS.rglob("*.md"):
        _, fm, _ = read_fm(md)
        if not fm:
            continue
        name = fm.get("name", md.stem)
        sub = fm.get("substrate", "")
        out[name] = sub
    return out


def dedup_preserving_order(xs):
    seen = set()
    out = []
    for x in xs:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out


def populate_convergences(art_prov: dict, art_sub: dict) -> int:
    n = 0
    for md in sorted(CONVERGENCES.rglob("*.md")):
        _, fm, _ = read_fm(md)
        if not fm:
            continue
        member_artifacts = []
        for src in fm.get("input-sources") or []:
            for a in (src.get("artifacts") or []):
                member_artifacts.append(a)
        # Derive base from member artifacts
        base = []
        substrates = set()
        for a in member_artifacts:
            base.extend(art_prov.get(a, []))
            if a in art_sub:
                substrates.add(art_sub[a])
        # Methodology (universal)
        prov = base + CONV_METHODOLOGY[:]
        # Substrate-triggered additions
        for sub in substrates:
            if sub in SUBSTRATE_SOURCES:
                prov.append(SUBSTRATE_SOURCES[sub])
        prov = dedup_preserving_order(prov)
        write_provenance(md, prov)
        n += 1
    return n


def load_convergence_artifacts() -> dict[str, list[str]]:
    """Return {convergence_name: [member_artifact_names]}."""
    out = {}
    for md in CONVERGENCES.rglob("*.md"):
        _, fm, _ = read_fm(md)
        if not fm:
            continue
        name = fm.get("name", md.stem)
        arts = []
        for src in fm.get("input-sources") or []:
            for a in src.get("artifacts") or []:
                arts.append(a)
        out[name] = list(set(arts))
    return out


def populate_scenarios(art_prov: dict, art_sub: dict, conv_arts: dict) -> int:
    n = 0
    for md in sorted(SCENARIOS.rglob("*.md")):
        _, fm, _ = read_fm(md)
        if not fm:
            continue
        # Union of step artifacts + convergence-referenced artifacts
        member_artifacts = []
        for step in fm.get("steps") or []:
            for a in (step.get("artifacts") or []):
                member_artifacts.append(a)
            conv = step.get("convergence")
            if conv:
                member_artifacts.extend(conv_arts.get(conv, []))
        # Also pick up the (deprecated) top-level scenario.artifacts block
        top_arts = fm.get("artifacts") or {}
        for bucket in ("primary", "corroborating"):
            for a in (top_arts.get(bucket) or []):
                member_artifacts.append(a)
        # Derive base
        base = []
        substrates = set()
        for a in member_artifacts:
            base.extend(art_prov.get(a, []))
            if a in art_sub:
                substrates.add(art_sub[a])
        prov = base + SCENARIO_METHODOLOGY[:]
        for sub in substrates:
            if sub in SUBSTRATE_SOURCES:
                prov.append(SUBSTRATE_SOURCES[sub])
        prov = dedup_preserving_order(prov)
        write_provenance(md, prov)
        n += 1
    return n


def main():
    art_prov = load_artifact_provenance()
    art_sub = load_artifact_substrates()
    conv_arts = load_convergence_artifacts()
    print(f"Loaded provenance for {len(art_prov)} artifacts")
    print(f"Loaded substrates for {len(art_sub)} artifacts")

    n_conv = populate_convergences(art_prov, art_sub)
    print(f"Wrote provenance to {n_conv} convergences")

    n_scen = populate_scenarios(art_prov, art_sub, conv_arts)
    print(f"Wrote provenance to {n_scen} scenarios")


if __name__ == "__main__":
    main()
