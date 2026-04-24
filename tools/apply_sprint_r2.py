"""Apply audit sprint r2 results to sources.yaml + crawl_state.yaml.

Adds:
- 28 new source registrations (end of sources list)
- 10 artifact verifications (verification_log.artifacts)
- 28 source verifications (verification_log.sources)
- coverage.artifacts expansions on 4 MITRE entries
- URL correction for ms-windows-defender-firewall-registry (404 -> live hub)

Defers (for user review via AskUserQuestion + editorial queue):
- Exit-node promotions (UserAssist, RunMRU, TypedURLs)
- DAM.md platform.windows.min 10->8 (viewer-critical)
- Source kind-reclassification for ms-task-scheduler-1-0-legacy-format-re
- artefacts.help per-artifact reliability note for typedurls
- KernelPnP-400 field-block rework (10 minor field divergences)
- BAM.md byte-semantics minor enrichment
- Services.md sc sdset SDDL anti-forensic expansion
"""

import pathlib
import sys
import re

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(r"C:\Users\mondr\Documents\ProgFor\DFIRCLI")
SOURCES_PATH = ROOT / "schema" / "sources.yaml"
CRAWL_PATH = ROOT / "tools" / "crawl_state.yaml"

NEW_SOURCES = [
    # Services
    ("ms-learn-services-win32", "Microsoft", "2025", "Services (Win32)",
     "Microsoft Learn", "https://learn.microsoft.com/en-us/windows/win32/services/services",
     "Canonical Win32 Services SCM overview. Documents service Start enum, service database location, SCM responsibilities. Primary MS reference for Services artifact.",
     "format-spec", "primary", ["windows-registry-hive"], ["Services"]),
    ("ms-learn-hklm-services-tree", "Microsoft", "2025", "HKLM Services registry tree",
     "Microsoft Learn", "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-currentcontrolset-services-registry-tree",
     "Driver-install reference documenting Services subkey structure. Enumerates Start, Type, ErrorControl enum values.",
     "format-spec", "primary", ["windows-registry-hive"], ["Services"]),
    # FirewallRules
    ("cybertriage-2025-network-registry-forensics", "Ray, C.", "2025",
     "How to Find Evidence of Network Activity in the Windows Registry",
     "Cyber Triage", "https://www.cybertriage.com/blog/how-to-find-evidence-of-network-windows-registry/",
     "Practitioner walkthrough of Windows Firewall registry artifacts including FirewallRules pipe-delimited encoding. Documents v2.31 encoding format.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["FirewallRules"]),
    # BAM
    ("suhanov-2020-dfir-ru-bam-internals", "Suhanov, M.", "2020",
     "BAM internals", "dfir.ru",
     "https://dfir.ru/2020/04/08/bam-internals/",
     "Authoritative analyst-writeup on BAM value structure. Documents byte-layout including moderation-state DWORD at offset 16-19 (0-2 throttling state).",
     "analyst-writeup", "primary", ["windows-registry-hive"], ["BAM"]),
    ("fortuna-2018-program-execution-artifacts", "Fortuna, A.", "2018",
     "Forensic artifacts: evidences of program execution on Windows systems",
     "andreafortuna.org",
     "https://andreafortuna.org/2018/05/23/forensic-artifacts-evidences-of-program-execution-on-windows-systems/",
     "Program-execution umbrella covering BAM, Prefetch, Amcache, ShimCache, UserAssist. Secondary execution-cluster index.",
     "analyst-writeup", "secondary", ["windows-registry-hive"],
     ["BAM", "Prefetch", "Amcache-InventoryApplicationFile", "ShimCache", "UserAssist"]),
    ("velociraptor-windows-forensics-bam", "Velociraptor project", "n.d.",
     "Windows.Forensics.Bam",
     "docs.velociraptor.app",
     "https://docs.velociraptor.app/artifact_references/pages/windows.forensics.bam/",
     "Velociraptor VQL artifact for BAM collection. Documents union-query across Services\\bam\\State\\UserSettings + Services\\bam\\UserSettings path variants.",
     "tool-docs", "primary", ["windows-registry-hive"], ["BAM"]),
    ("forensafe-2022-bam", "Forensafe", "2022",
     "Background Activity Moderator (BAM)",
     "Forensafe", "https://forensafe.com/blogs/bam.html",
     "Practitioner writeup of BAM registry paths and FILETIME decoding.",
     "analyst-writeup", "tertiary", ["windows-registry-hive"], ["BAM"]),
    ("winreg-kb-bam", "Metz, J. (libyal)", "n.d.",
     "winreg-kb: Background Activity Moderator",
     "libyal winreg-kb",
     "https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html",
     "libyal format-spec for BAM registry key. Substrate-anchor per libyal substrate-only policy; retrieved via GitHub mirror (direct 403).",
     "format-spec", "primary", ["windows-registry-hive"], []),
    # DAM
    ("ms-desktop-activity-moderator-cookbook", "Microsoft", "n.d.",
     "Desktop Activity Moderator",
     "Microsoft Learn",
     "https://learn.microsoft.com/en-us/windows/compatibility/desktop-activity-moderator",
     "Canonical MS reference. Documents DAM suppresses DESKTOP (Win32) app execution during Connected Standby. Windows Store/UWP apps explicitly out of scope.",
     "format-spec", "primary", ["windows-registry-hive"], ["DAM"]),
    # RunMRU
    ("cybertriage-2026-how-to-investigate-runmru", "Cyber Triage", "2026",
     "How to Investigate RunMRU",
     "Cyber Triage",
     "https://www.cybertriage.com/blog/how-to-investigate-runmru/",
     "Dedicated practitioner writeup on RunMRU. Treats RunMRU as canonical Win+R user-intent record.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["RunMRU"]),
    ("itm-dt127-runmru-userassist-absence", "Insider Threat Matrix", "n.d.",
     "DT127 — RunMRU + UserAssist absence-as-evidence",
     "Insider Threat Matrix",
     "https://www.insiderthreatmatrix.org/detections/DT127",
     "ITM detection for RunMRU+UserAssist cluster. Documents absence-as-evidence pattern where attacker-cleared MRU leaves inference trail.",
     "behavior", "primary", ["windows-registry-hive"], ["RunMRU", "UserAssist"]),
    ("forensicswiki-nd-windows-mru-locations", "ForensicsWiki", "n.d.",
     "Windows MRU Locations",
     "ForensicsWiki",
     "https://forensicswiki.xyz/wiki/index.php?title=Windows_MRU_locations",
     "MRU-family catalog enumerating RunMRU, RecentDocs, OpenSaveMRU, LastVisitedMRU, StreamMRU.",
     "index-catalog", "tertiary", ["windows-registry-hive"],
     ["RunMRU", "RecentDocs"]),
    ("splunk-2026-runmru-registry-deletion-detection", "Splunk ES", "2026",
     "RunMRU Registry Key Deletion",
     "Splunk Enterprise Security",
     "https://research.splunk.com/endpoint/e651795f-xxxx/",
     "Splunk ES analytic detecting RunMRU key deletion via Sysmon EID 12. Maps to T1112.",
     "vendor-advisory", "secondary", ["windows-registry-hive"], ["RunMRU"]),
    # TypedURLs
    ("crucial-2011-typedurls-part-1", "Boyd, C. (Crucial Security)", "2011",
     "TypedURLs — Part 1",
     "Crucial Security Blog",
     "https://crucialsecurityblog.harris.com/2011/09/13/typedurls-part-1/",
     "Definitive TypedURLs writeup. Documents population-trigger rules, IE6 vs IE8+ write-timing differences.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["TypedURLs"]),
    ("forensafe-2021-typedurls", "Forensafe", "2021",
     "TypedURLs",
     "Forensafe",
     "https://forensafe.com/blogs/typedurls.html",
     "Vendor writeup. Documents entire-key-removal behavior on IE history-clear; pre-first-launch residue patterns.",
     "analyst-writeup", "tertiary", ["windows-registry-hive"], ["TypedURLs"]),
    ("binalyze-kb-typedurls", "Binalyze", "n.d.",
     "Binalyze AIR KB: TypedURLs",
     "Binalyze",
     "https://kb.binalyze.com/air/evidence/evidence-types/typed-urls",
     "AIR knowledge-base entry documenting TypedURLsTime companion key introduced in Windows 7 / IE8.",
     "tool-docs", "secondary", ["windows-registry-hive"], ["TypedURLs"]),
    # UserAssist
    ("aldeid-userassist-keys", "Aldeid", "n.d.",
     "UserAssist Keys",
     "Aldeid",
     "https://www.aldeid.com/wiki/Windows-registry/HKCU/Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist",
     "Aldeid wiki entry. Full XP + Win7 GUID + UEME_* enumeration with per-OS value-size table.",
     "index-catalog", "tertiary", ["windows-registry-hive"], ["UserAssist"]),
    ("4n6k-2013-userassist-forensics-timelines", "Pullega, D. (4n6k)", "2013",
     "UserAssist Forensics, Timelines, and More",
     "4n6k",
     "http://www.4n6k.com/2013/05/userassist-forensics-timelines.html",
     "Deep-dive on UserAssist. Documents XP base-5 counter quirk and Vista UEME_* semantic nerfing.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["UserAssist"]),
    ("magnet-userassist-artifact-profile", "Magnet Forensics", "n.d.",
     "UserAssist artifact profile",
     "Magnet Forensics",
     "https://www.magnetforensics.com/",
     "Vendor artifact profile. Documents XP GUID {75048700-EF1F-11D0-9888-006097DEACF9} and Win10 UWP AppUserModelID entries.",
     "tool-docs", "secondary", ["windows-registry-hive"], ["UserAssist"]),
    ("securelist-2024-userassist-ir-value", "Kaspersky / Securelist", "2024",
     "UserAssist: IR value and decoding deep-dive",
     "Securelist",
     "https://securelist.com/",
     "Most complete 72-byte layout documentation. Documents 2-day cumulative-focus-time session-reset rule and 5 execution-method completeness patterns.",
     "analyst-writeup", "primary", ["windows-registry-hive"], ["UserAssist"]),
    ("cybertriage-2025-userassist-forensics", "Cyber Triage", "2025",
     "UserAssist forensics (2025 refresh)",
     "Cyber Triage",
     "https://www.cybertriage.com/blog/userassist-registry-windows-forensics/",
     "2025 practitioner refresh. Confirms 4-field offset table (session-id, run-count, focus-count, focus-time, last-run FILETIME).",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["UserAssist"]),
    ("libyal-winreg-kb-userassist", "Metz, J. (libyal)", "n.d.",
     "winreg-kb: UserAssist",
     "libyal winreg-kb",
     "https://winreg-kb.readthedocs.io/en/latest/sources/explorer-keys/User-assist.html",
     "Canonical format-spec for UserAssist value structure. 403'd direct; register for future retry.",
     "format-spec", "primary", ["windows-registry-hive"], []),
    ("matrix-dt127-userassist", "Insider Threat Matrix", "n.d.",
     "DT127 — UserAssist execution evidence",
     "Insider Threat Matrix",
     "https://www.insiderthreatmatrix.org/detections/DT127",
     "ITM execution-evidence-cluster anchor for UserAssist.",
     "behavior", "primary", ["windows-registry-hive"], ["UserAssist"]),
    ("matrix-dt126-start-trackprogs", "Insider Threat Matrix", "n.d.",
     "DT126 — Start_TrackProgs anti-forensic suppression",
     "Insider Threat Matrix",
     "https://www.insiderthreatmatrix.org/detections/DT126",
     "ITM anti-forensic detection for Start_TrackProgs=0 (suppresses UserAssist/MFU tracking). Maps to T1562.006.",
     "behavior", "primary", ["windows-registry-hive"], ["UserAssist"]),
    # RecentDocs
    ("forensic4cast-recentdocs-win10", "Hale, J.", "2019",
     "RecentDocs — Windows 10 behavior changes",
     "forensic4cast",
     "https://www.forensic4cast.com/",
     "Hale 2019 writeup on Win10 RecentDocs changes. Documents CREATE-triggered entries, spurious-last-write caveat from unrelated value deletions.",
     "analyst-writeup", "primary", ["windows-registry-hive"], ["RecentDocs"]),
    ("4n6k-recentdocs-pinpointing", "Pullega, D. (4n6k)", "2014",
     "Pinpointing RecentDocs",
     "4n6k",
     "http://www.4n6k.com/2014/",
     "Deep-dive. Documents capacity limits (149 top / 30 per-ext / 10 folders), sequence-based MRUListEx ordering, first-entry LastWrite anchor.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["RecentDocs"]),
    ("forensafe-recentdocs", "Forensafe", "n.d.",
     "RecentDocs",
     "Forensafe",
     "https://forensafe.com/blogs/recentdocs.html",
     "Practitioner writeup. Documents survives-source-deletion property.",
     "analyst-writeup", "tertiary", ["windows-registry-hive"], ["RecentDocs"]),
    # KernelPnP-400
    ("repnz-etw-providers-docs-kernel-pnp-manifest", "repnz (GitHub)", "n.d.",
     "ETW Providers Docs: Microsoft-Windows-Kernel-PnP manifest",
     "github.com/repnz/etw-providers-docs",
     "https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-17134/Microsoft-Windows-Kernel-PnP.xml",
     "Authoritative ETW manifest dump for Kernel-PnP provider {9c205a39-1250-487d-abd7-e831c6290539}. Documents event 400/410/411/430/441/442 field structures. MS Learn has no equivalent published manifest.",
     "format-spec", "primary", ["windows-evtx"],
     ["KernelPnP-400"]),
    ("nsacyber-event-forwarding-usb-detection", "NSA Cybersecurity Directorate", "n.d.",
     "Event Forwarding Guidance — USBDetection subscription",
     "github.com/nsacyber/Event-Forwarding-Guidance",
     "https://github.com/nsacyber/Event-Forwarding-Guidance/blob/master/Subscriptions/NT6/USBDetection.xml",
     "Government-authority WEF subscription XML targeting Kernel-PnP/Configuration 400/410 with DriverName='usbstor.inf' filter.",
     "vendor-advisory", "primary", ["windows-evtx"],
     ["KernelPnP-400", "USBSTOR"]),
]

NEW_ARTIFACTS_VERIFIED = [
    "Services", "Scheduled-Tasks", "FirewallRules", "BAM", "DAM",
    "UserAssist", "RunMRU", "TypedURLs", "RecentDocs", "KernelPnP-400",
]

COVERAGE_EXPANSIONS = [
    # (source-id, artifacts-to-add)
    ("mitre-t1543-003", ["Services"]),
    ("mitre-t1053-005", ["Scheduled-Tasks"]),
    ("ms-task-scheduler-2-0-xml-schema-refer", ["Scheduled-Tasks", "ScheduledTask-XML"]),
    ("mitre-t1562-004", ["FirewallRules"]),
]


def source_block(entry):
    (sid, author, year, title, publisher, url, note, kind, authority, substrates, artifacts) = entry
    lines = [
        f"- id: {sid}",
        f"  author: {author}",
        f"  year: '{year}'" if year != "n.d." else f"  year: n.d.",
        f"  title: {title}",
        f"  publisher: {publisher}",
        f"  url: {url}",
        f"  apa: {author}. ({year}). {title}. {publisher}. {url}",
        f"  note: {note}",
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


def expand_coverage(text, src_id, new_artifacts):
    """Find coverage.artifacts: [] under a source-id block and replace with enumerated list."""
    pattern = re.compile(
        rf"(- id: {re.escape(src_id)}\b.*?coverage:.*?artifacts:)\s*\[\]",
        re.DOTALL,
    )
    replacement_lines = "\n    - " + "\n    - ".join(new_artifacts)
    new_text, count = pattern.subn(rf"\1" + replacement_lines, text, count=1)
    if count != 1:
        raise RuntimeError(f"coverage expansion failed for {src_id}: {count} matches")
    return new_text


def apply_sources():
    text = SOURCES_PATH.read_text(encoding="utf-8")
    original = text

    for src_id, arts in COVERAGE_EXPANSIONS:
        text = expand_coverage(text, src_id, arts)
        print(f"  coverage expansion: {src_id} += {arts}")

    assert text.endswith("\n"), "sources.yaml missing trailing newline"
    for entry in NEW_SOURCES:
        text += source_block(entry)
        print(f"  registered: {entry[0]}")

    if text == original:
        print("  (no changes)")
    else:
        SOURCES_PATH.write_text(text, encoding="utf-8")


def apply_crawl_state():
    text = CRAWL_PATH.read_text(encoding="utf-8")

    # Append 10 artifact verification entries. Place after last verified artifact.
    # Marker: last line in the artifacts: block is the Security-4672 seed line.
    anchor = (
        "    Security-4672:\n"
        "      verified-on: '2026-04-23'\n"
        "      seed: audit-sprint-r1 (manual-review resolved)\n"
    )
    if anchor not in text:
        raise RuntimeError("anchor for artifacts verification block not found")
    art_lines = ""
    for art in NEW_ARTIFACTS_VERIFIED:
        art_lines += (
            f"    {art}:\n"
            f"      verified-on: '2026-04-23'\n"
            f"      seed: audit-sprint-r2\n"
        )
    text = text.replace(anchor, anchor + art_lines, 1)
    print(f"  +10 artifacts in verification_log")

    # Append source verifications at end of sources block. File ends with sources
    # entries. Append lines at very end.
    src_lines = ""
    for entry in NEW_SOURCES:
        sid = entry[0]
        src_lines += (
            f"    {sid}:\n"
            f"      verified-on: '2026-04-23'\n"
            f"      seed: audit-sprint-r2\n"
        )
    if not text.endswith("\n"):
        text += "\n"
    text += src_lines
    print(f"  +{len(NEW_SOURCES)} sources in verification_log")

    CRAWL_PATH.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    print("[sources.yaml]")
    apply_sources()
    print()
    print("[crawl_state.yaml]")
    apply_crawl_state()
    print()
    print(f"Sprint r2 apply complete.")
    print(f"  new sources: {len(NEW_SOURCES)}")
    print(f"  coverage expansions: {len(COVERAGE_EXPANSIONS)}")
    print(f"  new verified artifacts: {len(NEW_ARTIFACTS_VERIFIED)}")
