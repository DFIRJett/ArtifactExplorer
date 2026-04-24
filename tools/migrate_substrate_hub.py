"""Backfill substrate-hub field on filesystem-domain artifacts per H-018 Item 2.

Per notes/substrate-hierarchy-proposal.md: 38 artifacts get a substrate-hub
value that names the curated forensic grouping (User scope / System scope /
NTFS Core / NTFS Metadata / Streams / FAT / Disk Metadata). Substrate view's
subgroupOf() will prefer substrate-hub when present, falling back to existing
logic for non-assigned substrate classes.

Field placement: inserted after the `substrate-instance:` line (if present)
or after the `substrate:` line. Idempotent — re-running is a no-op.
"""

import pathlib
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(r"C:\Users\mondr\Documents\ProgFor\DFIRCLI")
ARTIFACTS = ROOT / "artifacts"

# Mapping: artifact-name -> substrate-hub value (per proposal § Data)
HUB_MAP = {
    # Filesystem/Artifact - User scope (15)
    "AutomaticDestinations": "User scope",
    "BrowserDownload-LNK": "User scope",
    "CustomDestinations": "User scope",
    "Desktop-LNK": "User scope",
    "JumpList-AppID-Mapping": "User scope",
    "JumpList-DestList-Entry": "User scope",
    "JumpList-Embedded-LNK": "User scope",
    "JumpList-PinnedItem": "User scope",
    "NetworkShare-LNK": "User scope",
    "OfficeRecent-LNK": "User scope",
    "Outlook-OST": "User scope",
    "Outlook-PST": "User scope",
    "Recent-LNK": "User scope",
    "RecycleBin-I-Metadata": "User scope",
    "ShellBags": "User scope",
    "ShellLNK": "User scope",

    # Filesystem/Artifact - System scope (3)
    "Startup-LNK": "System scope",
    "Prefetch": "System scope",
    "Recycle-Bin-INFO2": "System scope",

    # Filesystem/Metadata - NTFS Core (4)
    "MFT": "NTFS Core",
    "LogFile": "NTFS Core",
    "UsnJrnl": "NTFS Core",
    "I30-Index": "NTFS Core",

    # Filesystem/Metadata - NTFS Metadata (7)
    "Bitmap": "NTFS Metadata",
    "Boot": "NTFS Metadata",
    "Secure-SDS": "NTFS Metadata",
    "Extended-Attributes": "NTFS Metadata",
    "Extend-Quota": "NTFS Metadata",
    "Reparse": "NTFS Metadata",
    "ObjId": "NTFS Metadata",

    # Filesystem/Metadata - Streams (4)
    "AlternateDataStream-Generic": "Streams",
    "Zone-Identifier-ADS": "Streams",
    "LogFile-T-Stream": "Streams",
    "UsnJrnl-Max-Stream": "Streams",

    # Filesystem/Metadata - FAT (2)
    "FAT32-Boot": "FAT",
    "exFAT-Boot": "FAT",

    # Filesystem/Disk - Disk Metadata (3)
    "EFI-System-Partition": "Disk Metadata",
    "MBR": "Disk Metadata",
    "VSS-Shadow-Copies": "Disk Metadata",
}


def find_artifact(name: str) -> pathlib.Path | None:
    matches = list(ARTIFACTS.glob(f"*/{name}.md"))
    if not matches:
        return None
    if len(matches) > 1:
        raise RuntimeError(f"Multiple matches for {name}: {matches}")
    return matches[0]


def add_hub(path: pathlib.Path, hub: str) -> str:
    text = path.read_text(encoding="utf-8")
    if f"substrate-hub: {hub}" in text:
        return "already-set"
    if "substrate-hub:" in text:
        # present with a different value — overwrite
        new = re.sub(r"^substrate-hub: .*$", f"substrate-hub: {hub}", text, count=1, flags=re.MULTILINE)
        path.write_text(new, encoding="utf-8")
        return "overwritten"
    # Insert after substrate-instance line (preferred) or substrate: line
    # (inline-compact substrate: {…} shape also supported)
    # Match "substrate: <val>" or "substrate-instance: <val>" lines that
    # are NOT inside a compact inline block.
    patterns = [
        r"^(substrate-instance: [^\n]+\n)",
        r"^(substrate-instance:\s*\n(?:  [^\n]*\n)*)",
        r"^(substrate: [^\n]+\n)",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.MULTILINE)
        if m:
            insertion = m.group(1) + f"substrate-hub: {hub}\n"
            new = text.replace(m.group(0), insertion, 1)
            path.write_text(new, encoding="utf-8")
            return "inserted"
    return "no-anchor-found"


def main():
    results = {"inserted": 0, "overwritten": 0, "already-set": 0, "missing-file": 0, "no-anchor-found": 0}
    for name, hub in HUB_MAP.items():
        p = find_artifact(name)
        if p is None:
            print(f"  MISS: no file for {name}")
            results["missing-file"] += 1
            continue
        status = add_hub(p, hub)
        print(f"  {status}: {name} -> {hub}")
        results[status] += 1

    print()
    for k, v in results.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
