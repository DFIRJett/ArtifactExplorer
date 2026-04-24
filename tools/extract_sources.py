#!/usr/bin/env python3
"""
Extract existing artifact `sources:` blocks into a single
`schema/sources.yaml` registry and emit a per-artifact migration map.

Reads:  artifacts/**/*.md  (frontmatter `sources:` arrays)
Writes: schema/sources.yaml         (deduplicated source registry)
        tools/_provenance_map.yaml  (artifact -> list of source IDs)

Does NOT mutate artifact files — that's a separate migration step.
"""
from __future__ import annotations
import re
import sys
import pathlib
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts"
SOURCES_OUT = ROOT / "schema" / "sources.yaml"
MAP_OUT = ROOT / "tools" / "_provenance_map.yaml"


def slugify(text: str, max_len: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:max_len].strip("-")


def derive_id(src: dict) -> str:
    """Generate a slug-like ID from (url, author, title)."""
    url = (src.get("url") or "").strip()
    author = (src.get("author") or "").strip()
    title = (src.get("title") or "").strip()

    # Microsoft Learn event pages: event-<NNNN>
    m = re.search(r"/event-(\d+)", url)
    if m and "microsoft.com" in url:
        return f"ms-event-{m.group(1)}"

    # Ultimate Windows Security event lookup
    m = re.search(r"eventID=(\d+)", url)
    if m and "ultimatewindowssecurity" in url:
        return f"uws-event-{m.group(1)}"

    # MITRE ATT&CK techniques
    m = re.search(r"/techniques/(T\d+(?:/\d+)?)/?", url)
    if m:
        return f"mitre-{m.group(1).lower().replace('/', '-')}"

    # libyal repos
    m = re.search(r"github\.com/libyal/([a-z0-9-]+)", url)
    if m:
        slug = slugify(title or m.group(1), 30)
        return f"libyal-{m.group(1)}" + (f"-{slug}" if slug and slug != m.group(1) else "")

    # Microsoft generic Learn / Docs
    if "microsoft.com" in url or "msdn.microsoft" in url:
        return f"ms-{slugify(title, 35)}"

    # MITRE non-technique
    if "attack.mitre.org" in url or "mitre" in author.lower():
        return f"mitre-{slugify(title, 35)}"

    # Named-author fallback
    last = author.split(",")[0].split(" ")[-1] if author else "unknown"
    year = str(src.get("year") or "nd").replace("n.d.", "nd")
    slug = slugify(title, 30)
    return f"{slugify(last, 20)}-{year}-{slug}".strip("-")


PUBLISHER_MAP = [
    ("learn.microsoft.com",         "Microsoft Learn"),
    ("docs.microsoft.com",          "Microsoft Learn"),
    ("msdn.microsoft",              "Microsoft Learn"),
    ("techcommunity.microsoft",     "Microsoft Tech Community"),
    ("github.com/libyal",           "libyal"),
    ("github.com/ForensicArtifacts","Forensic Artifacts"),
    ("github.com/AndrewRathbun",    "Andrew Rathbun (GitHub)"),
    ("attack.mitre.org",            "MITRE ATT&CK"),
    ("ultimatewindowssecurity.com", "Ultimate Windows Security"),
    ("sans.org",                    "SANS Institute"),
    ("insiderthreatmatrix.org",     "Insider Threat Matrix"),
    ("thedfirreport.com",           "The DFIR Report"),
    ("13cubed",                     "13Cubed"),
    ("aboutdfir",                   "AboutDFIR"),
    ("anydesk.com",                 "AnyDesk"),
    ("ericzimmerman.github",        "Eric Zimmerman (tools site)"),
    ("specterops.io",               "SpecterOps"),
    ("posts.specterops.io",         "SpecterOps"),
    ("windowsir.blogspot",          "Windows Incident Response (Harlan Carvey)"),
    ("cisa.gov",                    "CISA"),
    ("youtube.com",                 "YouTube"),
]


def derive_publisher(src: dict) -> str:
    url = (src.get("url") or "").lower()
    author = (src.get("author") or "").lower()

    for needle, label in PUBLISHER_MAP:
        if needle.lower() in url:
            return label

    if "bambenek" in author: return "Bambenek Labs"
    if "anssi" in author:    return "ANSSI"

    # fall back to URL host
    m = re.search(r"https?://([^/]+)/", url + "/")
    if m:
        host = m.group(1)
        host = re.sub(r"^www\.", "", host)
        return host
    return ""


def apa_format(src: dict) -> str:
    author = (src.get("author") or "").strip()
    year = str(src.get("year") or "n.d.").strip()
    if year == "nd":
        year = "n.d."
    title = (src.get("title") or "").strip().rstrip(".")
    url = (src.get("url") or "").strip()
    publisher = derive_publisher(src)

    # Author formatting: keep corporate authors as-is; already-formatted "Last, F." too
    author_render = author if author else "Unknown author"
    if author_render.endswith("."):
        author_render = author_render[:-1]

    parts = [f"{author_render}. ({year}). {title}."]
    if publisher:
        parts.append(f" {publisher}.")
    if url:
        parts.append(f" {url}")
    return "".join(parts).strip()


def load_fm(path: pathlib.Path):
    txt = path.read_text(encoding="utf-8", errors="replace")
    if not txt.startswith("---"):
        return None
    parts = txt.split("---", 2)
    if len(parts) < 3:
        return None
    try:
        return yaml.safe_load(parts[1]) or {}
    except Exception as e:
        print(f"  YAML error in {path.name}: {e}", file=sys.stderr)
        return None


def main():
    # key: (url, title, author, year) tuple -> canonical source record
    registry: dict[tuple, dict] = {}
    id_to_key: dict[str, tuple] = {}
    # reverse assignment: ensure unique IDs across different sources
    used_ids: set[str] = set()

    per_artifact_map: list[dict] = []

    for md in sorted(ARTIFACTS.rglob("*.md")):
        fm = load_fm(md)
        if not fm:
            continue
        srcs = fm.get("sources") or []
        if not srcs:
            continue

        ids_here: list[dict] = []
        for s in srcs:
            if not isinstance(s, dict):
                continue
            url = (s.get("url") or "").strip()
            title = (s.get("title") or "").strip()
            author = (s.get("author") or "").strip()
            year = str(s.get("year") or "").strip()
            # Primary dedup: URL (authoritative). Fallback: author+title+year when URL missing.
            key = ("url", url) if url else ("noref", author, title, year)

            if key in registry:
                for sid, k in id_to_key.items():
                    if k == key:
                        ids_here.append({"id": sid, "title": title})
                        break
                continue

            sid = derive_id(s)
            # handle collisions: append numeric suffix
            base = sid
            n = 2
            while sid in used_ids:
                sid = f"{base}-{n}"
                n += 1

            used_ids.add(sid)
            id_to_key[sid] = key

            record = {"id": sid}
            # Required fields first (always emitted)
            record["author"] = (s.get("author") or "").strip() or "Unknown"
            record["title"] = (s.get("title") or "").strip() or "Untitled"
            record["url"] = (s.get("url") or "").strip()
            # Optional fields — only emit when populated
            year = str(s.get("year") or "").strip()
            if year and year not in ("nd",):
                record["year"] = year
            elif year == "nd":
                record["year"] = "n.d."
            pub = derive_publisher(s)
            if pub:
                record["publisher"] = pub
            if s.get("note"):
                record["note"] = s["note"]
            # APA string rebuilt from whatever we have
            record["apa"] = apa_format(s)
            registry[key] = record
            ids_here.append({"id": sid, "title": title})

        rel = str(md.relative_to(ROOT)).replace("\\", "/")
        per_artifact_map.append({"artifact": rel, "provenance": ids_here})

    # Emit registry (sorted by ID)
    records = sorted(registry.values(), key=lambda r: r["id"])
    SOURCES_OUT.parent.mkdir(parents=True, exist_ok=True)
    with SOURCES_OUT.open("w", encoding="utf-8", newline="\n") as f:
        f.write("# DFIRCLI source registry — APA-formatted bibliographic entries\n")
        f.write("# referenced by `provenance:` on artifacts, concepts, convergences, scenarios.\n")
        f.write("# DRAFT — regenerated from legacy per-artifact `sources:` blocks. Review before trusting.\n\n")
        yaml.safe_dump({"sources": records}, f, sort_keys=False, allow_unicode=True, width=9999)

    MAP_OUT.parent.mkdir(parents=True, exist_ok=True)
    with MAP_OUT.open("w", encoding="utf-8", newline="\n") as f:
        yaml.safe_dump({"mapping": per_artifact_map}, f, sort_keys=False, allow_unicode=True, width=9999)

    print(f"Registry:   {len(records)} unique sources -> {SOURCES_OUT.relative_to(ROOT)}")
    print(f"Mapping:    {len(per_artifact_map)} artifacts -> {MAP_OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
