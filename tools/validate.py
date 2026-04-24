#!/usr/bin/env python3
"""validate.py — DFIRCLI corpus validator.

Reads every .md file under the data tree (artifacts/, substrates/,
concepts/ or concepts/, scenarios/), parses the YAML frontmatter,
and validates it against the matching JSON Schema in schema/. Also
checks that every artifact references-data (concept, role) pair matches
an entry in schema/concepts.yaml.

Run:    python tools/validate.py
Exit:   0 when all files pass; 1 when any validation or integrity error
        is found. Intended for use as a CI gate.

Zero required dependencies beyond PyYAML (already used by the build).
Uses the `jsonschema` library when installed for full Draft 2020-12
validation; falls back to a minimal in-repo validator that covers the
highest-value checks (required keys, enum values, concept+role lookup)
when jsonschema is unavailable.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import yaml

try:
    import jsonschema
    _HAS_JSONSCHEMA = True
except ImportError:  # pragma: no cover — fallback path
    _HAS_JSONSCHEMA = False

ROOT = Path(__file__).parent.parent

# ---- paths -----------------------------------------------------------------
SCHEMA_DIR = ROOT / "schema"
ARTIFACTS_DIR    = (ROOT / "data" / "artifacts")    if (ROOT / "data" / "artifacts").exists()    else (ROOT / "artifacts")
SUBSTRATES_DIR   = (ROOT / "data" / "substrates")   if (ROOT / "data" / "substrates").exists()   else (ROOT / "substrates")
CONCEPTS_DIR     = (ROOT / "data" / "concepts")     if (ROOT / "data" / "concepts").exists()     else (ROOT / "concepts")
SCENARIOS_DIR    = (ROOT / "data" / "scenarios")    if (ROOT / "data" / "scenarios").exists()    else (ROOT / "scenarios")
CONVERGENCES_DIR = (ROOT / "data" / "convergences") if (ROOT / "data" / "convergences").exists() else (ROOT / "convergences")

# ---- pretty-print helpers --------------------------------------------------
RESET = "\033[0m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
DIM = "\033[2m"


def _supports_color() -> bool:
    return sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if _supports_color() else text


# ---- data classes ----------------------------------------------------------
@dataclass
class ValidationIssue:
    severity: str           # "error" | "warning"
    path: Path
    message: str
    detail: str = ""


@dataclass
class ValidationReport:
    checked: int = 0
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "warning"]

    def add(self, severity: str, path: Path, message: str, detail: str = "") -> None:
        self.issues.append(ValidationIssue(severity, path, message, detail))


# ---- frontmatter parsing ---------------------------------------------------
def read_frontmatter(path: Path) -> dict | None:
    """Return the parsed YAML frontmatter or None if no fence is present."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return None
    end = text.find("---", 3)
    if end < 0:
        return None
    try:
        fm = yaml.safe_load(text[3:end])
    except yaml.YAMLError as e:
        raise ValueError(f"YAML parse error: {e}") from e
    return fm if isinstance(fm, dict) else None


# ---- schema loading --------------------------------------------------------
def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8"))


def load_concepts_registry() -> dict[str, dict]:
    """Return {concept-name: {kind, roles:set}} from schema/concepts.yaml."""
    reg = yaml.safe_load((SCHEMA_DIR / "concepts.yaml").read_text(encoding="utf-8"))
    concepts = {}
    for name, meta in (reg.get("concepts") or {}).items():
        concepts[name] = {
            "kind": meta.get("kind", ""),
            "roles": set(meta.get("roles") or []),
            "description": meta.get("description", ""),
        }
    return concepts


def load_sources_registry() -> set[str]:
    """Return the set of IDs in schema/sources.yaml."""
    path = SCHEMA_DIR / "sources.yaml"
    if not path.exists():
        return set()
    reg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {s["id"] for s in (reg.get("sources") or []) if isinstance(s, dict) and "id" in s}


def load_sources_full() -> dict[str, dict]:
    """Return full per-ID source dicts from schema/sources.yaml."""
    path = SCHEMA_DIR / "sources.yaml"
    if not path.exists():
        return {}
    reg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {s["id"]: s for s in (reg.get("sources") or []) if isinstance(s, dict) and "id" in s}


def validate_sources_registry(report: ValidationReport) -> None:
    """Validate schema/sources.yaml against schema/sources.schema.json and
    check ID uniqueness. Every entry must carry author + title + url."""
    path = SCHEMA_DIR / "sources.yaml"
    if not path.exists():
        return
    try:
        reg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        report.add("error", path, f"YAML parse error: {e}")
        return
    report.checked += 1
    schema = load_schema("sources")
    if _HAS_JSONSCHEMA:
        _validate_with_jsonschema(reg, schema, path, report)

    seen: dict[str, int] = {}
    for i, s in enumerate(reg.get("sources") or []):
        if not isinstance(s, dict):
            continue
        sid = s.get("id")
        if sid in seen:
            report.add("error", path, f"duplicate source id '{sid}' at indices {seen[sid]} and {i}")
        elif sid:
            seen[sid] = i


def validate_provenance(fm: dict, sources: set[str], path: Path, report: ValidationReport,
                        source_full: dict[str, dict] | None = None,
                        substrate: str | None = None,
                        artifact_name: str | None = None,
                        convergence_name: str | None = None,
                        scenario_slug: str | None = None) -> None:
    """Check every provenance entry resolves to a source registry ID. When
    source_full is supplied, additionally warn on coverage mismatches.

    Tier-1 (artifact + substrate) — STRICT rules:
      - If coverage.artifacts is non-empty, it is AUTHORITATIVE. Any citing
        artifact not in the list is flagged.
      - Otherwise fall back to coverage.substrates matching.

    Tier-2 (convergence) — OPT-IN rule:
      - If coverage.convergences-broadly is true: any citation is valid.
      - If coverage.convergences is non-empty: citing convergence must be
        in the list. Otherwise warn.
      - If both absent: no warning (methodology sources legitimately apply
        across convergences without enumeration).

    Tier-3 (scenario) — OPT-IN rule, analogous to T2 via scenarios-broadly
    and coverage.scenarios.
    """
    for item in fm.get("provenance") or []:
        sid = item if isinstance(item, str) else (item.get("source") if isinstance(item, dict) else None)
        if not sid:
            continue
        if sid not in sources:
            report.add("error", path, f"provenance references unknown source id '{sid}' (not in schema/sources.yaml)")
            continue
        if not source_full:
            continue
        src = source_full.get(sid) or {}
        cov = src.get("coverage") or {}

        # Tier-1 (artifact + substrate) — STRICT coverage-consistency
        if artifact_name or substrate:
            arts = cov.get("artifacts") or []
            subs = cov.get("substrates") or []
            if arts:
                if artifact_name and artifact_name not in arts:
                    report.add("warning", path,
                               f"provenance source '{sid}' lists specific artifacts; "
                               f"'{artifact_name}' is not among them (source covers: {', '.join(arts[:5])}{'...' if len(arts) > 5 else ''})")
                continue
            if substrate and subs and substrate not in subs:
                report.add("warning", path,
                           f"provenance source '{sid}' does not cover substrate '{substrate}' "
                           f"(source covers: {', '.join(subs)})")

        # Tier-2 (convergence) — OPT-IN rule
        if convergence_name:
            if cov.get("convergences-broadly") is True:
                continue
            convs = cov.get("convergences") or []
            if convs and convergence_name not in convs:
                report.add("warning", path,
                           f"provenance source '{sid}' declares convergence coverage "
                           f"but '{convergence_name}' is not among them "
                           f"(source covers: {', '.join(convs[:5])}{'...' if len(convs) > 5 else ''})")

        # Tier-3 (scenario) — OPT-IN rule
        if scenario_slug:
            if cov.get("scenarios-broadly") is True:
                continue
            scens = cov.get("scenarios") or []
            if scens and scenario_slug not in scens:
                report.add("warning", path,
                           f"provenance source '{sid}' declares scenario coverage "
                           f"but '{scenario_slug}' is not among them "
                           f"(source covers: {', '.join(scens[:5])}{'...' if len(scens) > 5 else ''})")


# ---- validation passes -----------------------------------------------------
def _validate_with_jsonschema(fm: dict, schema: dict, path: Path, report: ValidationReport) -> None:
    validator = jsonschema.Draft202012Validator(schema)
    for err in sorted(validator.iter_errors(fm), key=lambda e: list(e.absolute_path)):
        loc = "/".join(str(p) for p in err.absolute_path) or "(root)"
        report.add("error", path, f"{loc}: {err.message}")


def _validate_minimal(fm: dict, schema: dict, path: Path, report: ValidationReport) -> None:
    """Fallback: check `required` keys and top-level enum constraints only."""
    for key in schema.get("required", []):
        if key not in fm:
            report.add("error", path, f"missing required key: {key}")
    for key, spec in (schema.get("properties") or {}).items():
        if key not in fm or not isinstance(spec, dict):
            continue
        enum = spec.get("enum")
        if enum is not None and fm[key] not in enum:
            report.add("error", path, f"{key}: value '{fm[key]}' not in allowed set {enum}")


def validate_frontmatter(fm: dict, schema: dict, path: Path, report: ValidationReport) -> None:
    if _HAS_JSONSCHEMA:
        _validate_with_jsonschema(fm, schema, path, report)
    else:
        _validate_minimal(fm, schema, path, report)


def validate_references(fm: dict, concepts: dict[str, dict], path: Path, report: ValidationReport) -> None:
    """Walk every artifact field's references-data and verify concept + role match the registry."""
    for field_spec in fm.get("fields") or []:
        if not isinstance(field_spec, dict):
            continue
        for ref in field_spec.get("references-data") or []:
            if not isinstance(ref, dict):
                continue
            concept = ref.get("concept")
            role = ref.get("role")
            if concept and concept not in concepts:
                report.add("error", path, f"field '{field_spec.get('name')}' references unknown concept '{concept}' (not in schema/concepts.yaml)")
                continue
            if concept and role and role not in concepts[concept]["roles"]:
                report.add("warning", path, f"field '{field_spec.get('name')}' uses role '{role}' not in concept {concept}'s role set", detail=f"known roles: {sorted(concepts[concept]['roles'])}")


def validate_name_matches_filename(fm: dict, path: Path, report: ValidationReport) -> None:
    name = fm.get("name")
    expected = path.stem
    if name and name != expected:
        report.add("error", path, f"frontmatter name '{name}' does not match filename '{expected}'")


# ---- main loops ------------------------------------------------------------
def validate_directory(directory: Path, schema_name: str, report: ValidationReport,
                       *, concepts: dict[str, dict] | None = None,
                       sources: set[str] | None = None,
                       source_full: dict[str, dict] | None = None,
                       check_name: bool = True) -> None:
    if not directory.exists():
        return
    schema = load_schema(schema_name)
    for md in sorted(directory.rglob("*.md")):
        report.checked += 1
        try:
            fm = read_frontmatter(md)
        except ValueError as e:
            report.add("error", md, str(e))
            continue
        if fm is None:
            report.add("error", md, "no YAML frontmatter fence found")
            continue
        validate_frontmatter(fm, schema, md, report)
        if check_name:
            validate_name_matches_filename(fm, md, report)
        if schema_name == "artifact" and concepts is not None:
            validate_references(fm, concepts, md, report)
        if sources is not None:
            substrate = fm.get("substrate") if schema_name == "artifact" else None
            artifact_name = fm.get("name") if schema_name == "artifact" else None
            convergence_name = fm.get("name") if schema_name == "convergence" else None
            scenario_slug = md.stem if schema_name == "scenario" else None
            validate_provenance(fm, sources, md, report,
                                source_full=source_full,
                                substrate=substrate,
                                artifact_name=artifact_name,
                                convergence_name=convergence_name,
                                scenario_slug=scenario_slug)


def main() -> int:
    report = ValidationReport()
    try:
        concepts = load_concepts_registry()
    except FileNotFoundError:
        print(_c(RED, "ERROR: schema/concepts.yaml missing — run Phase 2 setup first"), file=sys.stderr)
        return 2

    validate_sources_registry(report)
    sources = load_sources_registry()
    source_full = load_sources_full()

    validate_directory(SUBSTRATES_DIR,   "substrate",   report, sources=sources, source_full=source_full, check_name=True)
    validate_directory(CONCEPTS_DIR,     "concept",     report, sources=sources, source_full=source_full, check_name=True)
    validate_directory(ARTIFACTS_DIR,    "artifact",    report, concepts=concepts, sources=sources, source_full=source_full, check_name=True)
    validate_directory(SCENARIOS_DIR,    "scenario",    report, sources=sources, source_full=source_full, check_name=False)
    validate_directory(CONVERGENCES_DIR, "convergence", report, sources=sources, source_full=source_full, check_name=True)

    # ---- report ---------------------------------------------------------
    print()
    print(_c(DIM, f"validator: {'jsonschema (full)' if _HAS_JSONSCHEMA else 'minimal fallback'}"))
    print(f"checked: {report.checked} files")
    print(f"errors:  {len(report.errors)}")
    print(f"warnings:{len(report.warnings)}")
    print()

    for issue in report.issues:
        label = _c(RED, "ERROR") if issue.severity == "error" else _c(YELLOW, "WARN")
        try:
            rel = issue.path.relative_to(ROOT)
        except ValueError:
            rel = issue.path
        print(f"  {label}  {rel}")
        print(f"         {issue.message}")
        if issue.detail:
            print(f"         {_c(DIM, issue.detail)}")

    if report.errors:
        print()
        print(_c(RED, f"FAILED — {len(report.errors)} error(s)"))
        return 1
    print()
    if report.warnings:
        print(_c(YELLOW, f"passed with {len(report.warnings)} warning(s)"))
    else:
        print(_c(GREEN, "all clean"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
