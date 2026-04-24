"""Apply audit sprint r3 partial results (7 of 10 completed; 3 rate-limited).

Completed: Security-4728, 4732, 4738, 4741, 4742, 4743, 4781.
Deferred: Security-4782, NTDS-dit, ProfileList (rate limit, rerun after reset).

Adds:
- 17 new source registrations (end of sources list)
- 7 artifact verifications
- 17 source verifications
- coverage.artifacts expansions on 3 new MS Learn subcategory docs
  (ms-audit-security-group-management, ms-audit-computer-account-management,
  ms-audit-user-account-management) — each covers a focused 2-3 event set

Defers (manual-review or next session):
- Platform.min staleness (4732/4738/4742/4743 + minor on 4781) — batched
  fix waiting for user AskUserQuestion
- UAC encoding MAJOR on 4738 (propagates to 4741, 4742) — needs user review
- Body-content enrichments (field-set completeness on several events)
"""

import pathlib
import sys
import re

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(r"C:\Users\mondr\Documents\ProgFor\DFIRCLI")
SOURCES_PATH = ROOT / "schema" / "sources.yaml"
CRAWL_PATH = ROOT / "tools" / "crawl_state.yaml"

NEW_SOURCES = [
    # Cluster-hub subcategory docs (covering multiple cluster events each)
    ("ms-audit-security-group-management", "Microsoft", "2025",
     "Audit Security Group Management — subcategory doc",
     "Microsoft Learn",
     "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management",
     "Cluster-hub subcategory doc covering Security-4728 + Security-4732 in-sprint, plus 15 sibling group-management events (4727/4729/4730/4731/4733/4734/4735/4737/4754/4755/4756/4757/4758/4764/4799) out-of-sprint. Highest-leverage single source for the AD group-change cluster.",
     "format-spec", "primary", ["windows-evtx"],
     ["Security-4728", "Security-4732"]),

    ("ms-audit-computer-account-management", "Microsoft", "2025",
     "Audit Computer Account Management — subcategory doc",
     "Microsoft Learn",
     "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-computer-account-management",
     "Cluster-hub subcategory doc covering Security-4741 + Security-4742 + Security-4743 at one URL. The computer-account triad — CREATE / CHANGE / DELETE. Lifecycle-level coverage for the machine-account abuse surface (noPac, RBCD precondition, MAQ abuse, SPN-jacking).",
     "format-spec", "primary", ["windows-evtx"],
     ["Security-4741", "Security-4742", "Security-4743"]),

    ("ms-audit-user-account-management", "Microsoft", "2025",
     "Audit User Account Management — subcategory doc",
     "Microsoft Learn",
     "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management",
     "Cluster-hub subcategory doc covering Security-4738 + Security-4781 in-sprint + Security-4782 (deferred). Covers user-account lifecycle: 4720 (create), 4722/4725 (enable/disable), 4738 (change), 4726 (delete), 4740 (lockout), 4765/4766 (SID history add/fail), 4767 (unlock), 4780 (admin ACL), 4781 (name change), 4782 (password-hash access), 4794 (DSRM), 4798 (local group enum), 5376/5377 (cred-mgr backup/restore).",
     "format-spec", "primary", ["windows-evtx"],
     ["Security-4738", "Security-4781"]),

    # MS-SAMR normative spec (resolves the 4738 UAC-encoding MAJOR)
    ("ms-samr-user-account-codes", "Microsoft", "2024",
     "[MS-SAMR] USER_ACCOUNT Codes",
     "Microsoft Open Specifications",
     "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec",
     "Normative MS-SAMR spec for SAM USER_ACCOUNT bitmask. Distinct encoding from AD schema userAccountControl. This is what 4738/4741/4742 OldUacValue/NewUacValue fields actually carry (the corpus previously cited AD UAC bits, which have a different layout — DONT_REQ_PREAUTH = 0x00010000 SAM vs 0x400000 AD, etc.). Analyst-facing — SIEM rules must use SAM bitmask to match 47xx-family UAC fields.",
     "format-spec", "primary", [], []),

    ("ms-kb-useraccountcontrol", "Microsoft", "2024",
     "UserAccountControl property flags — KB305144",
     "Microsoft Learn",
     "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties",
     "MS KB305144 AD schema userAccountControl flag reference — the bit-layout used by AD tooling (ADUC, PowerShell Get-ADUser, LDAP attribute-read). Distinct from MS-SAMR USER_ACCOUNT codes used by 47xx audit events.",
     "format-spec", "primary", [], []),

    # TechNet archive wikis / community encyclopedias
    ("ms-technet-wiki-4728-4729", "Microsoft (TechNet archive)", "2014",
     "Active Directory Event ID 4728-4729 — when user added or removed from security-enabled global group",
     "Microsoft Learn (TechNet archive)",
     "https://learn.microsoft.com/en-us/archive/technet-wiki/17049.active-directory-event-id-4728-4729-when-user-added-or-removed-from-security-enabled-global-group",
     "Archived TechNet wiki. Confirms field layout with concrete example. Covers both Security-4728 (member added) and Security-4729 (member removed).",
     "analyst-writeup", "primary", ["windows-evtx"],
     ["Security-4728"]),

    ("uws-event-4728", "Ultimate Windows Security", "n.d.",
     "Event 4728 — A member was added to a security-enabled global group",
     "UltimateWindowsSecurity",
     "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4728",
     "UWS practitioner encyclopedia page. Confirms DC-only scope and platform range. Part of UWS's per-event encyclopedia pattern (pages exist for all 8 cluster events — batch registration opportunity).",
     "analyst-writeup", "secondary", ["windows-evtx"], ["Security-4728"]),

    ("uws-event-4732", "Ultimate Windows Security", "n.d.",
     "Event 4732 — A member was added to a security-enabled local group",
     "UltimateWindowsSecurity",
     "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4732",
     "UWS page for 4732. Surfaces 2016+ Expiration field annotation not in MS Learn.",
     "analyst-writeup", "secondary", ["windows-evtx"], ["Security-4732"]),

    ("uws-event-4738", "Ultimate Windows Security", "n.d.",
     "Event 4738 — A user account was changed",
     "UltimateWindowsSecurity",
     "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4738",
     "UWS page for 4738. Community reference corroborating MS-SAMR USER_ACCOUNT codes as the correct UAC bitmask.",
     "analyst-writeup", "secondary", ["windows-evtx"], ["Security-4738"]),

    ("eventsentry-event-4728", "EventSentry", "n.d.",
     "Event 4728 — system32 event reference",
     "EventSentry",
     "https://system32.eventsentry.com/security/event/4728",
     "EventSentry event reference. Confirms all 10 EventData field names and extended platform range.",
     "tool-docs", "secondary", ["windows-evtx"], ["Security-4728"]),

    ("wetnav-event-4732", "Windows Event Threat Navigator", "n.d.",
     "Event 4732",
     "Windows Event Threat Navigator",
     "https://wetnav.gihub.io/",
     "WETNAV event navigator — low-priority reference (content currently skeletal).",
     "index-catalog", "tertiary", ["windows-evtx"], ["Security-4732"]),

    ("ms-event-4733", "Microsoft", "2017",
     "Event 4733 — A member was removed from a security-enabled local group",
     "Microsoft Learn",
     "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4733",
     "MS Learn page for 4733 (sibling-cleanup pair to 4732). Not in-sprint but registered for future authoring.",
     "format-spec", "primary", ["windows-evtx"], []),

    # 4741 cluster — noPac / MAQ / SPN-jacking sources
    ("ms-kb5008102-samr-hardening-cve-2021-42278", "Microsoft MSRC", "2021",
     "KB5008102 — Active Directory Security Accounts Manager hardening (CVE-2021-42278)",
     "Microsoft Support",
     "https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e",
     "noPac / CVE-2021-42278 patch advisory. Covers Security-4741 + Security-4742 + Security-4743 in the computer-account-lifecycle. Introduces NEW events 16990/16991 on Directory-Services-SAM channel (new substrate-instance frontier candidate).",
     "vendor-advisory", "primary", ["windows-evtx"],
     ["Security-4741", "Security-4742", "Security-4743"]),

    ("velazco-2021-hunting-samaccountname-spoofing", "Velazco, P.", "2021",
     "Hunting sAMAccountName spoofing (CVE-2021-42278 / CVE-2021-42287)",
     "Splunk Research",
     "https://research.splunk.com/stories/detect-samaccountname-spoofing/",
     "Splunk detection for noPac rename signature. 4781 + 4768 + 4769 correlation pattern. Dedicated Security-4781 detection source.",
     "analyst-writeup", "primary", ["windows-evtx"], ["Security-4781"]),

    ("packetlabs-2024-maq-fuels-ad-attacks", "Packetlabs", "2024",
     "MachineAccountQuota fuels AD attacks",
     "Packetlabs",
     "https://www.packetlabs.net/posts/",
     "MAQ-abuse attack-chain catalog. Covers noPac + ADCS abuse + RBCD + SCCM NAA as interlocking machine-account-creation attacks. Abuse-chain-focused (no event primitives).",
     "analyst-writeup", "secondary", ["windows-evtx"], []),

    # 4742 cluster — RBCD / SPN-jacking
    ("eladshamir-spn-jacking", "Shamir, E.", "2022",
     "SPN-jacking",
     "Elad Shamir blog",
     "https://eladshamir.com/2022/02/10/SPN-jacking.html",
     "Original SPN-jacking research by the RBCD discoverer. Direct 4742-native detection via ServicePrincipalNames attribute changes.",
     "analyst-writeup", "primary", ["windows-evtx"], ["Security-4742"]),

    ("splunk-security-4742", "Splunk Research", "2024",
     "Security-4742 — 5 detections (T1134.005, T1207, T1210)",
     "Splunk Research",
     "https://research.splunk.com/sources/ea830adf-5450-489a-bcdc-fb8d2cbe674c/",
     "Splunk ES production detection catalog for Security-4742. Maps to T1134.005 (SID-history injection), T1207 (rogue DC), T1210 (exploitation of remote services).",
     "analyst-writeup", "primary", ["windows-evtx"], ["Security-4742"]),
]

NEW_ARTIFACTS_VERIFIED = [
    "Security-4728", "Security-4732", "Security-4738", "Security-4741",
    "Security-4742", "Security-4743", "Security-4781",
]

# No separate coverage-expansions needed — the new subcategory docs already
# carry the right coverage.artifacts lists in their registration entries.


def source_block(entry):
    (sid, author, year, title, publisher, url, note, kind, authority, substrates, artifacts) = entry
    # Quote title if it contains a colon+space (YAML mapping-value hazard)
    quoted_title = f"'{title}'" if ": " in title else title
    quoted_note = ""
    # Build APA
    apa = f"{author}. ({year}). {title}. {publisher}. {url}"
    quoted_apa = f"'{apa}'" if ": " in apa else apa
    # Note may contain ":" — safer to block-scalar or quote if needed
    if ": " in note:
        # Use double quotes and escape any existing double quotes
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
    assert text.endswith("\n"), "sources.yaml missing trailing newline"
    for entry in NEW_SOURCES:
        text += source_block(entry)
        print(f"  registered: {entry[0]}")
    SOURCES_PATH.write_text(text, encoding="utf-8")


def apply_crawl_state():
    text = CRAWL_PATH.read_text(encoding="utf-8")

    # Insert artifact verifications: find the last 'seed: audit-sprint-r2' line
    # in the artifacts: block and insert after its entry.
    last_r2_anchor = "    KernelPnP-400:\n      verified-on: '2026-04-23'\n      seed: audit-sprint-r2\n"
    if last_r2_anchor not in text:
        # Fallback: find any earlier r2 anchor
        for candidate_name in ["RecentDocs", "TypedURLs", "RunMRU", "UserAssist", "DAM", "BAM"]:
            alt = f"    {candidate_name}:\n      verified-on: '2026-04-23'\n      seed: audit-sprint-r2\n"
            if alt in text:
                last_r2_anchor = alt
                break
        else:
            raise RuntimeError("could not find an audit-sprint-r2 artifact anchor")
    art_lines = ""
    for art in NEW_ARTIFACTS_VERIFIED:
        art_lines += (
            f"    {art}:\n"
            f"      verified-on: '2026-04-23'\n"
            f"      seed: audit-sprint-r3-batch-a\n"
        )
    text = text.replace(last_r2_anchor, last_r2_anchor + art_lines, 1)
    print(f"  +{len(NEW_ARTIFACTS_VERIFIED)} artifacts in verification_log")

    # Insert source verifications: find the last r2 source anchor and add after it.
    # Pattern: the block just before `frontier_refined:` top-level key.
    sources_anchor = "    nsacyber-event-forwarding-usb-detection:\n      verified-on: '2026-04-23'\n      seed: audit-sprint-r2\n"
    if sources_anchor not in text:
        raise RuntimeError("could not find the last r2 source anchor")
    src_lines = ""
    for entry in NEW_SOURCES:
        sid = entry[0]
        src_lines += (
            f"    {sid}:\n"
            f"      verified-on: '2026-04-23'\n"
            f"      seed: audit-sprint-r3-batch-a\n"
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
    print(f"Sprint r3 partial apply complete (7 of 10).")
    print(f"  new sources: {len(NEW_SOURCES)}")
    print(f"  new verified artifacts: {len(NEW_ARTIFACTS_VERIFIED)}")
    print(f"  deferred (rate-limited): Security-4782, NTDS-dit, ProfileList")
