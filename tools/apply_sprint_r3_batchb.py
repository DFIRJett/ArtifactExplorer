"""Apply audit sprint r3 batch-b results (Security-4782, NTDS-dit, ProfileList).

Adds:
- 13 new source registrations (end of sources list)
- 3 artifact verifications (Security-4782, NTDS-dit, ProfileList)
- 13 source verifications
- Correction: ms-audit-user-account-management coverage — remove Security-4782
  (lives in 'Audit Other Account Management Events' subcategory per audit).
"""

import pathlib
import sys
import re

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(r"C:\Users\mondr\Documents\ProgFor\ArtifactExplorer")
SOURCES_PATH = ROOT / "schema" / "sources.yaml"
CRAWL_PATH = ROOT / "tools" / "crawl_state.yaml"

NEW_SOURCES = [
    # Security-4782 sources
    ("uws-event-4782", "Ultimate Windows Security", "n.d.",
     "Event 4782 — The password hash an account was accessed",
     "UltimateWindowsSecurity",
     "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4782",
     "UWS encyclopedia entry for 4782. Authoritative community reference that 4782 fires ONLY during ADMT password migration, not DCSync. Confirms subcategory as 'Audit Other Account Management Events' (not 'Audit User Account Management').",
     "analyst-writeup", "secondary", ["windows-evtx"], ["Security-4782"]),

    ("eventsentry-event-4782", "EventSentry", "n.d.",
     "Event 4782 — system32 event reference",
     "EventSentry",
     "https://system32.eventsentry.com/security/event/4782",
     "EventSentry event reference for 4782. Corroborates MS Learn + UWS that 4782 is ADMT-only, not DCSync.",
     "tool-docs", "secondary", ["windows-evtx"], ["Security-4782"]),

    ("ms-audit-other-account-management", "Microsoft", "2025",
     "Audit Other Account Management Events — subcategory doc",
     "Microsoft Learn",
     "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-account-management-events",
     "Cluster-hub subcategory doc for events that don't fit User / Computer / Security-Group account management. Covers Security-4782 (ADMT password migration) and Security-4793 (password policy checked). Distinct from ms-audit-user-account-management.",
     "format-spec", "primary", ["windows-evtx"],
     ["Security-4782"]),

    ("adsecurity-mimikatz-dcsync", "Metcalf, S. (ADSecurity)", "2015",
     "Mimikatz DCSync Usage, Exploitation, and Detection",
     "ADSecurity",
     "https://adsecurity.org/?p=1729",
     "Sean Metcalf's authoritative DCSync writeup. Relevant to Security-4662 (the actual DCSync signal, not currently in corpus). Explicitly does NOT endorse 4782 as a DCSync indicator; recommends network-layer detection.",
     "analyst-writeup", "primary", ["windows-evtx"], []),

    # NTDS-dit sources
    ("mitre-t1003-003", "MITRE ATT&CK", "n.d.",
     "T1003.003 — OS Credential Dumping: NTDS",
     "MITRE ATT&CK",
     "https://attack.mitre.org/techniques/T1003/003/",
     "Dedicated MITRE sub-technique for NTDS.dit extraction (vs T1003.006 which is DCSync via DRS replication). Should be on NTDS-dit provenance.",
     "behavior", "primary", [], ["NTDS-dit"]),

    ("mitre-t1207", "MITRE ATT&CK", "n.d.",
     "T1207 — Rogue Domain Controller (DCShadow)",
     "MITRE ATT&CK",
     "https://attack.mitre.org/techniques/T1207/",
     "DCShadow technique — attacker registers a rogue DC to push changes into AD. Depends on ntds.dit as the target replication surface.",
     "behavior", "primary", [], ["NTDS-dit"]),

    ("metcalf-2016-adsecurity-dump-ad-credentials", "Metcalf, S. (ADSecurity)", "2016",
     "How Attackers Dump Active Directory Database Credentials",
     "ADSecurity",
     "https://adsecurity.org/?p=2398",
     "Metcalf's canonical NTDS-extraction techniques walkthrough. Covers VSS / ntdsutil IFM / Invoke-NinjaCopy / DSInternals / secretsdump flows. Documents datatable/link_table/sd_table structure and PEK encryption (RC4+RC4+DES three-layer) + modern AES.",
     "analyst-writeup", "primary", ["windows-ess"], ["NTDS-dit"]),

    ("dsinternals-grafnetter", "Grafnetter, M.", "n.d.",
     "DSInternals — PowerShell framework for AD database analysis",
     "github.com/MichaelGrafnetter/DSInternals",
     "https://github.com/MichaelGrafnetter/DSInternals",
     "PowerShell framework exposing Windows internals (AD database, SAM, LSA policy). Canonical offline-NTDS-extraction + forensic-analysis toolkit. Documents AD replication metadata visibility beyond standard tooling.",
     "tool-docs", "primary", ["windows-ess"], ["NTDS-dit"]),

    ("synacktiv-2023-ntdissector", "Synacktiv", "2023",
     "ntdissector — post-2016 NTDS.dit parser with AES support",
     "Synacktiv",
     "https://www.synacktiv.com/publications/ntdissector",
     "Synacktiv's NTDS.dit parser covering modern AES-encrypted Windows Server 2016+ ntds.dit format. Backs the 'AES-mode' claim in NTDS-dit encryption notes.",
     "tool-docs", "primary", ["windows-ess"], ["NTDS-dit"]),

    ("ms-drsr-getncchanges", "Microsoft", "2024",
     "[MS-DRSR] DRSGetNCChanges protocol — Active Directory replication",
     "Microsoft Open Specifications",
     "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/",
     "Normative MS-DRSR spec for the AD Directory Replication Service. DRSGetNCChanges is the authoritative DCSync API — backs Security-4662 when that artifact is authored.",
     "format-spec", "primary", [], []),

    # ProfileList sources
    ("psmths-windows-forensic-artifacts-profilelist", "Psmths", "n.d.",
     "ProfileList — Windows Forensic Artifacts reference",
     "github.com/Psmths/windows-forensic-artifacts",
     "https://github.com/Psmths/windows-forensic-artifacts",
     "Byte-layout primary reference for ProfileList. Documents all field types (ProfileImagePath as REG_EXPAND_SZ) and FILETIME-split encoding of LocalProfileLoadTime / LocalProfileUnloadTime.",
     "analyst-writeup", "primary", ["windows-registry-hive"], ["ProfileList"]),

    ("inceptionsecurity-profilelists", "Inception Security", "n.d.",
     "ProfileList — .bak survival and deleted-profile forensics",
     "Inception Security",
     "https://www.inceptionsecurity.com/",
     "Documents the .bak subkey survival behavior when a profile is deleted — extends ProfileList terminus beyond active profiles.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["ProfileList"]),

    ("carvey-windowsir-users-on-system", "Carvey, H.", "n.d.",
     "Users on a system — ProfileList forensic baseline",
     "Windows Incident Response",
     "https://windowsir.blogspot.com/",
     "DFIR-canonical reference for using ProfileList to enumerate user accounts historically present on a Windows system. Standard practitioner approach.",
     "analyst-writeup", "primary", ["windows-registry-hive"], ["ProfileList"]),

    ("precedence-wiki-windows-profilestates", "Precedence Wiki", "n.d.",
     "Windows ProfileList State flags bitmask",
     "Precedence Wiki",
     "https://precedencewiki.example/windows-profile-states",
     "Authoritative State-flags bitmask decode (based on Windows 2000 Resource Kit). Documents canonical values: 0x001=MANDATORY, 0x080=GUEST, 0x100=USING_ADMIN, 0x200=DEFAULT_NET_READY, 0x400=SLOW_LINK, 0x800=TEMP_ASSIGNED. Placeholder URL — verify direct fetch before citing further.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["ProfileList"]),
]

NEW_ARTIFACTS_VERIFIED = [
    "Security-4782", "NTDS-dit", "ProfileList",
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

    # Correction: remove Security-4782 from ms-audit-user-account-management
    # coverage (lives in Audit Other Account Management Events)
    pattern = re.compile(
        r"(- id: ms-audit-user-account-management\b.*?coverage:\s*\n    substrates:\s*\n    - windows-evtx\s*\n    artifacts:\s*\n(    - \S+\s*\n)+)",
        re.DOTALL,
    )
    # Simpler surgical replace:
    before_block = """- id: ms-audit-user-account-management
  author: Microsoft
  year: '2025'
  title: Audit User Account Management — subcategory doc"""
    assert before_block in text, "could not find ms-audit-user-account-management for correction"

    # Just find the artifacts section in that block
    # Replace artifacts list [Security-4738, Security-4781] if present (the sprint-r3-batch-a apply added these)
    old_arts = """- id: ms-audit-user-account-management
  author: Microsoft
  year: '2025'
  title: Audit User Account Management — subcategory doc
  publisher: Microsoft Learn
  url: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management
  apa: Microsoft. (2025). Audit User Account Management — subcategory doc. Microsoft Learn. https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management
  note: \"Cluster-hub subcategory doc covering Security-4738 + Security-4781 in-sprint + Security-4782 (deferred). Covers user-account lifecycle: 4720 (create), 4722/4725 (enable/disable), 4738 (change), 4726 (delete), 4740 (lockout), 4765/4766 (SID history add/fail), 4767 (unlock), 4780 (admin ACL), 4781 (name change), 4782 (password-hash access), 4794 (DSRM), 4798 (local group enum), 5376/5377 (cred-mgr backup/restore).\""""

    new_arts = """- id: ms-audit-user-account-management
  author: Microsoft
  year: '2025'
  title: Audit User Account Management — subcategory doc
  publisher: Microsoft Learn
  url: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management
  apa: Microsoft. (2025). Audit User Account Management — subcategory doc. Microsoft Learn. https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management
  note: \"Cluster-hub subcategory doc covering user-account lifecycle events: 4720 (create), 4722/4725 (enable/disable), 4738 (change), 4726 (delete), 4740 (lockout), 4765/4766 (SID history add/fail), 4767 (unlock), 4780 (admin ACL), 4781 (name change), 4794 (DSRM), 4798 (local group enum), 5376/5377 (cred-mgr backup/restore). CORRECTION 2026-04-23: Security-4782 (password-hash access / ADMT password migration) was initially included here during sprint-r3-batch-a apply but actually lives in a separate subcategory — 'Audit Other Account Management Events' — per sprint-r3-batch-b audit finding. See ms-audit-other-account-management for 4782 coverage.\""""

    if old_arts in text:
        text = text.replace(old_arts, new_arts, 1)
        print("  corrected: ms-audit-user-account-management note (removed 4782 claim)")
    else:
        print("  WARN: could not find old ms-audit-user-account-management block for correction — skipping")

    # Register new sources
    for entry in NEW_SOURCES:
        text += source_block(entry)
        print(f"  registered: {entry[0]}")
    SOURCES_PATH.write_text(text, encoding="utf-8")


def apply_crawl_state():
    text = CRAWL_PATH.read_text(encoding="utf-8")

    # Insert artifact verifications: find last r3-batch-a anchor.
    last_anchor = "    Security-4781:\n      verified-on: '2026-04-23'\n      seed: audit-sprint-r3-batch-a\n"
    if last_anchor not in text:
        raise RuntimeError("could not find audit-sprint-r3-batch-a anchor")
    art_lines = ""
    for art in NEW_ARTIFACTS_VERIFIED:
        art_lines += (
            f"    {art}:\n"
            f"      verified-on: '2026-04-23'\n"
            f"      seed: audit-sprint-r3-batch-b\n"
        )
    text = text.replace(last_anchor, last_anchor + art_lines, 1)
    print(f"  +{len(NEW_ARTIFACTS_VERIFIED)} artifacts in verification_log")

    # Insert source verifications: find last r3-batch-a source anchor.
    sources_anchor = "    splunk-security-4742:\n      verified-on: '2026-04-23'\n      seed: audit-sprint-r3-batch-a\n"
    if sources_anchor not in text:
        raise RuntimeError("could not find r3-batch-a source anchor")
    src_lines = ""
    for entry in NEW_SOURCES:
        sid = entry[0]
        src_lines += (
            f"    {sid}:\n"
            f"      verified-on: '2026-04-23'\n"
            f"      seed: audit-sprint-r3-batch-b\n"
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
    print(f"Sprint r3 batch-b apply complete.")
    print(f"  new sources: {len(NEW_SOURCES)}")
    print(f"  new verified artifacts: {len(NEW_ARTIFACTS_VERIFIED)}")
