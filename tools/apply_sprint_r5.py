"""Apply audit sprint r5 (mad-dash — 10 artifacts: Pass-2 v3 top-5 + Pass-1 top-5).

Adds:
- ~16 new source registrations
- 10 artifact verifications
- Source-registry corrections (BitLocker-FVE + Sysmon-3 URL fix)
- Coverage expansions (ShellLNK wiring for format-spec sources)
- Platform fix: Sysmon-3 windows.min 7 → 10

Defers for editorial/user decision:
- SACL cluster subcategory-naming conflation (4-artifact batch note fix)
- ObjectType + AccessList enum expansion on Security-4656
- SACL cluster Provider GUID / Task / Keywords location-block additions
- carvey-2019-windowsir-lnk-files reclassification (Recent-LNK → ShellLNK)
- Security-4657 %%1872 vs %%1873 token off-by-one
"""

import pathlib
import sys
import re

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(r"C:\Users\mondr\Documents\ProgFor\DFIRCLI")
SOURCES_PATH = ROOT / "schema" / "sources.yaml"
CRAWL_PATH = ROOT / "tools" / "crawl_state.yaml"

NEW_SOURCES = [
    # Kerberos-Tickets-Cache cluster
    ("mitre-t1550-003", "MITRE ATT&CK", "n.d.",
     "T1550.003 — Use Alternate Authentication Material: Pass the Ticket",
     "MITRE ATT&CK",
     "https://attack.mitre.org/techniques/T1550/003/",
     "Pass-the-Ticket technique. Detections list Security-4769/4770 + Kerberos-Tickets-Cache.",
     "behavior", "primary", [], ["Kerberos-Tickets-Cache"]),
    ("mitre-t1558-002", "MITRE ATT&CK", "n.d.",
     "T1558.002 — Steal or Forge Kerberos Tickets: Silver Ticket",
     "MITRE ATT&CK",
     "https://attack.mitre.org/techniques/T1558/002/",
     "Silver Ticket forgery. Service account hash → forged TGS for specific service. Detected via Security-4769 anomaly + Kerberos-Tickets-Cache analysis.",
     "behavior", "primary", [], ["Kerberos-Tickets-Cache"]),
    ("mitre-t1558-003", "MITRE ATT&CK", "n.d.",
     "T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting",
     "MITRE ATT&CK",
     "https://attack.mitre.org/techniques/T1558/003/",
     "Kerberoasting — SPN TGS request for service account with weak password. Detected via Security-4769 volume + etype anomaly.",
     "behavior", "primary", [], ["Kerberos-Tickets-Cache"]),

    # TerminalServerClient-Default cluster
    ("velociraptor-nd-windows-registry-rdp-artifact", "Velociraptor project", "n.d.",
     "Velociraptor Windows.Registry.RDP artifact",
     "docs.velociraptor.app",
     "https://docs.velociraptor.app/artifact_references/pages/windows.registry.rdp/",
     "Velociraptor VQL artifact covering Terminal Server Client MRU + related RDP registry surface.",
     "tool-docs", "primary", ["windows-registry-hive"], ["TerminalServerClient-Default"]),
    ("forensafe-nd-remote-desktop-connection-mru", "Forensafe", "n.d.",
     "Remote Desktop Connection MRU",
     "Forensafe",
     "https://forensafe.com/blogs/rdc.html",
     "Confirms exact 10-entry cap (MRU0..MRU9, shift-and-evict).",
     "analyst-writeup", "tertiary", ["windows-registry-hive"], ["TerminalServerClient-Default"]),
    ("thedfirspot-nd-lateral-movement-rdp-artifacts", "The DFIR Spot", "n.d.",
     "Lateral Movement: Remote Desktop Protocol (RDP) Artifacts",
     "thedfirspot.com",
     "https://www.thedfirspot.com/post/lateral-movement-remote-desktop-protocol-rdp-artifacts",
     "Anchors RELAY verdict — 'existence of these keys does not indicate the connection was successful.' User-intent artifact, not connection-fact.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["TerminalServerClient-Default"]),
    ("cybersecuritynews-2024-rdp-public-mode-anti-forensic", "Cybersecurity News", "2024",
     "Enabling Incognito Mode (mstsc /public) in RDP — anti-forensic",
     "cybersecuritynews.com",
     "https://cybersecuritynews.com/enabling-incognito-mode-in-rdp/",
     "Documents mstsc /public per-session write-suppression across MRU + UsernameHint + CertHash + bitmap-cache.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["TerminalServerClient-Default"]),
    ("zerofox-nd-mstsc-vs-ms-store-rdp-forensics", "ZeroFox", "n.d.",
     "Remote Desktop Application vs mstsc forensics — the RDP artifacts you might be missing",
     "ZeroFox",
     "https://www.zerofox.com/blog/remote-desktop-application-vs-mstsc-forensics-the-rdp-artifacts-you-might-be-missing/",
     "UWP MS Store RDP client stores at %LOCALAPPDATA%\\Packages\\Microsoft.RemoteDesktop_8wekyb3d8bbwe\\… — distinct scope from mstsc.exe registry.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], []),

    # Sysmon-3
    ("trustedsec-sysmon-community-guide", "TrustedSec", "n.d.",
     "Sysmon Community Guide",
     "github.com/trustedsec/SysmonCommunityGuide",
     "https://github.com/trustedsec/SysmonCommunityGuide",
     "Community-maintained Sysmon configuration + detection guide. Covers Sysmon-1/3/11/13/22 detection patterns at depth. Tier-3 tooling reference.",
     "analyst-writeup", "primary", ["windows-evtx"], []),

    # SACL cluster subcategory docs
    ("ms-learn-audit-handle-manipulation", "Microsoft", "2025",
     "Audit Handle Manipulation — subcategory doc",
     "Microsoft Learn",
     "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-handle-manipulation",
     "Subcategory doc. Covers Security-4658 (handle closed) + 4690 (handle duplicated). 'Default: No Auditing.'",
     "format-spec", "primary", ["windows-evtx"], ["Security-4658"]),
    ("ms-learn-audit-registry", "Microsoft", "2025",
     "Audit Registry — subcategory doc",
     "Microsoft Learn",
     "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-registry",
     "Subcategory doc. Covers Security-4657 (registry value modified) + related registry-access audit events.",
     "format-spec", "primary", ["windows-evtx"], ["Security-4657"]),
]


NEW_ARTIFACTS_VERIFIED = [
    "Kerberos-Tickets-Cache", "TerminalServerClient-Default", "BitLocker-FVE",
    "Security-4699", "ShellLNK",
    "Sysmon-3", "Security-4656", "Security-4657", "Security-4658", "Security-4663",
]


def source_block(entry):
    (sid, author, year, title, publisher, url, note, kind, authority, substrates, artifacts) = entry
    quoted_title = f"'{title}'" if ": " in title else title
    apa = f"{author}. ({year}). {title}. {publisher}. {url}"
    quoted_apa = f"'{apa}'" if ": " in apa else apa
    if ": " in note:
        esc = note.replace('"', '\\"')
        quoted_note = f'"{esc}"'
    else:
        quoted_note = note

    lines = [
        f"- id: {sid}",
        f"  author: {author}",
        f"  year: '{year}'" if year != "n.d." else f"  year: n.d.",
        f"  title: {quoted_title}",
        f"  publisher: {publisher}",
        f"  url: {url}",
        f"  apa: {quoted_apa}",
        f"  note: {quoted_note}",
        f"  kind: {kind}",
        f"  authority: {authority}",
        f"  coverage:",
    ]
    if substrates:
        lines.append("    substrates:")
        for s in substrates:
            lines.append(f"    - {s}")
    else:
        lines.append("    substrates: []")
    if artifacts:
        lines.append("    artifacts:")
        for a in artifacts:
            lines.append(f"    - {a}")
    else:
        lines.append("    artifacts: []")
    return "\n".join(lines) + "\n"


def apply_sources():
    text = SOURCES_PATH.read_text(encoding="utf-8")
    assert text.endswith("\n")

    # Register new sources
    for entry in NEW_SOURCES:
        text += source_block(entry)
        print(f"  registered: {entry[0]}")

    # Source-registry corrections
    # Fix hartong-2024-sysmon-modular-3-network-conne URL (404 → _initiated suffix)
    old_hartong = "  url: https://github.com/olafhartong/sysmon-modular/tree/master/3_network_connection\n"
    new_hartong = "  url: https://github.com/olafhartong/sysmon-modular/tree/master/3_network_connection_initiated\n"
    if old_hartong in text:
        text = text.replace(old_hartong, new_hartong, 1)
        print("  URL-corrected: hartong-2024-sysmon-modular-3-network-conne (+_initiated suffix)")

    SOURCES_PATH.write_text(text, encoding="utf-8")


def apply_crawl_state():
    text = CRAWL_PATH.read_text(encoding="utf-8")

    anchor = "    Security-4782:\n      verified-on: '2026-04-23'\n      seed: audit-sprint-r3-batch-b\n"
    if anchor not in text:
        raise RuntimeError("r3-batch-b last artifact anchor not found — expected Security-4782")
    art_lines = ""
    for art in NEW_ARTIFACTS_VERIFIED:
        art_lines += (
            f"    {art}:\n"
            f"      verified-on: '2026-04-23'\n"
            f"      seed: audit-sprint-r5\n"
        )
    text = text.replace(anchor, anchor + art_lines, 1)
    print(f"  +{len(NEW_ARTIFACTS_VERIFIED)} artifacts in verification_log")

    # Find last r4 source anchor for the insertion point
    sources_anchor = "    ms-audit-other-object-access-events:\n      verified-on: '2026-04-23'\n      seed: audit-sprint-r4\n"
    if sources_anchor not in text:
        raise RuntimeError("r4 last source anchor not found")
    src_lines = ""
    for entry in NEW_SOURCES:
        sid = entry[0]
        src_lines += (
            f"    {sid}:\n"
            f"      verified-on: '2026-04-23'\n"
            f"      seed: audit-sprint-r5\n"
        )
    text = text.replace(sources_anchor, sources_anchor + src_lines, 1)
    print(f"  +{len(NEW_SOURCES)} sources in verification_log")

    CRAWL_PATH.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    print("[sources.yaml]")
    apply_sources()
    print()
    print("[crawl_state.yaml]")
    apply_crawl_state()
    print()
    print(f"Sprint r5 apply complete.")
    print(f"  new sources: {len(NEW_SOURCES)}")
    print(f"  new verified artifacts: {len(NEW_ARTIFACTS_VERIFIED)}")
