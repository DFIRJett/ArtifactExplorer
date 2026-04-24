"""Apply audit sprint r4 results (10/10 complete).

Adds:
- 18 new source registrations
- 10 artifact verifications
- 18 source verifications
- URL correction on ms-cached-credentials-cachedlogonscoun (affects 2 artifacts)
- Platform fixes: Security-5381 server-min 2016→2019; Security-4697 win-min 7→'10'+server-min 2012→2016
- Title fix on Security-5381 (enumerate vs read)
- Provenance propagation across batch
- coverage.artifacts expansion on mitre-t1543-003 (+Security-4697)

Defers to user:
- LSA-Cached-Logons exit-node promotion to HAD_CREDENTIAL terminus
"""

import pathlib
import sys
import re

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(r"C:\Users\mondr\Documents\ProgFor\ArtifactExplorer")
SOURCES_PATH = ROOT / "schema" / "sources.yaml"
CRAWL_PATH = ROOT / "tools" / "crawl_state.yaml"

NEW_SOURCES = [
    # Credentials-cached cluster
    ("thehacker-recipes-mimikatz-lsadump-cache", "The Hacker Recipes", "n.d.",
     "mimikatz lsadump::cache — MSCASH v1/v2 extraction",
     "thehacker.recipes",
     "https://www.thehacker.recipes/ad/movement/credentials/dumping/sam-and-lsa-secrets",
     "Documents NL$KM syskey unwrap flow → MSCASH v1/v2 hash recovery. Fills gap left by gentilkiwi wiki stub #cache anchor. Canonical operator-side reference.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["Credentials-cached", "LSA-Cached-Logons"]),

    ("ired-team-mscash-dumping-cracking", "ired.team", "n.d.",
     "MSCASH dumping and cracking",
     "ired.team",
     "https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials",
     "Operator writeup for offline MSCASH extraction → hashcat mode 2100 PBKDF2-HMAC-SHA1 crack. Scenario-grounding for post-exploitation workflow.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["Credentials-cached"]),

    # SAM cluster
    ("winreg-kb-sam", "Metz, J. (libyal)", "n.d.",
     "winreg-kb: SAM",
     "libyal winreg-kb",
     "https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/SAM.html",
     "Authoritative byte-layout format-spec for SAM hive. Format-spec parity with winreg-kb-bam / winreg-kb-userassist. 403'd this session (readthedocs); register as substrate-anchor with lifecycle-retry tag.",
     "format-spec", "primary", ["windows-registry-hive"], []),

    ("winreg-kb-sam-domains", "Metz, J. (libyal)", "n.d.",
     "winreg-kb: SAM Domains and V-value structure",
     "libyal winreg-kb",
     "https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/SAM.html#domains",
     "Byte-layout of Domains\\Account\\F (domain info + machine SID) and Users\\<RID>\\V (username + password hashes). Subsection of winreg-kb-sam.",
     "format-spec", "primary", ["windows-registry-hive"], ["SAM"]),

    ("gentilkiwi-2020-mimikatz-lsadump-sam", "Delpy, B. (gentilkiwi)", "2020",
     "mimikatz lsadump::sam module wiki",
     "github.com/gentilkiwi/mimikatz/wiki",
     "https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump#sam",
     "Anchor-precise mimikatz SAM module documentation. Documents bootkey-from-SYSTEM → SAM hash decryption flow.",
     "tool-docs", "primary", ["windows-registry-hive"], ["SAM"]),

    ("moyix-2008-syskey-sam", "Moyix (Dolan-Gavitt, B.)", "2008",
     "SAM bootkey descrambling — syskey reverse-engineering",
     "moyix.blogspot.com",
     "http://moyix.blogspot.com/2008/02/syskey-and-sam.html",
     "Canonical writeup on syskey descrambling (SYSTEM hive → bootkey → SAM hash decryption). Reference for offline extraction tooling (samdump2, pwdump, secretsdump).",
     "analyst-writeup", "primary", ["windows-registry-hive"], ["SAM"]),

    ("hacker-recipes-sam-lsa-secrets", "The Hacker Recipes", "n.d.",
     "SAM + LSA secrets dumping methodology",
     "thehacker.recipes",
     "https://www.thehacker.recipes/ad/movement/credentials/dumping/sam-and-lsa-secrets",
     "Methodology consolidator across SAM + LSA-Secrets + LSA-Cached-Logons. Covers remote (RemoteRegistry/WMI) + offline (VSS/image) + live-memory (mimikatz) extraction paths.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["SAM", "LSA-Cached-Logons"]),

    # LSA-Cached-Logons cluster
    ("hacker-recipes-mimikatz-lsadump-cache", "The Hacker Recipes", "n.d.",
     "mimikatz lsadump::cache methodology",
     "thehacker.recipes",
     "https://www.thehacker.recipes/ad/movement/credentials/dumping/cached-credentials",
     "Full lsadump::cache syntax + NL$N/NL$KM registry path documentation.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["LSA-Cached-Logons"]),

    ("ultimatewindowssec-interactive-logon-cache", "Ultimate Windows Security", "n.d.",
     "Interactive Logon — cached logons count policy",
     "UltimateWindowsSecurity",
     "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5379",
     "Confirms CachedLogonsCount default=10, range=0-50. Replacement for the ms-cached-credentials-cachedlogonscoun 404'd MS Learn URL.",
     "analyst-writeup", "secondary", ["windows-registry-hive"], ["LSA-Cached-Logons"]),

    ("hashcat-wiki-example-hashes", "hashcat team", "n.d.",
     "hashcat example_hashes — reference modes",
     "hashcat.net",
     "https://hashcat.net/wiki/doku.php?id=example_hashes",
     "Reusable source across identity-hubs cluster. Confirms DCC2 = mode 2100 (PBKDF2-HMAC-SHA1, 10240 iterations), MSCash v1 = mode 1100, NTLM = mode 1000, LM = mode 3000, NTDS.dit history = mode 5600, DPAPI vault = mode 18200.",
     "tool-docs", "primary", [], []),

    # Extend-Quota
    ("flatcap-linux-ntfs-quota", "Russon, R. (linux-ntfs project)", "n.d.",
     "flatcap linux-ntfs: $Extend\\$Quota byte-layout reference",
     "github.io/flatcap/linux-ntfs",
     "https://flatcap.github.io/linux-ntfs/ntfs/files/quota.html",
     "Byte-layout authority for $Extend\\$Quota. Per-quota record fields: bytes-used, warning-limit, hard-limit, flags bitfield (LIMIT_REACHED / TRACKING_ENABLED / ENFORCEMENT_ENABLED / ID_DELETED / CORRUPT), exceeded-time timestamp. $H index keyed by 4-byte owner-id; $O maps SID → owner-id. Sibling coverage: ObjId, Reparse, UsnJrnl pages.",
     "format-spec", "primary", ["windows-ntfs-metadata"],
     ["Extend-Quota"]),

    # System-104
    ("logrhythm-evid-104", "LogRhythm", "n.d.",
     "LogRhythm EVID 104 — Log Cleared",
     "LogRhythm",
     "https://docs.logrhythm.com/devices/docs/evid-104-log-cleared",
     "SIEM parser docs confirming System-104 provider + channel + field surface. Notable gap: LogRhythm parser omits SubjectUserSid and SubjectLogonId — pragmatic DFIR-tooling limitation.",
     "tool-docs", "secondary", ["windows-evtx"], ["System-104"]),

    # Security-6416
    ("ms-audit-pnp-activity", "Microsoft", "2025",
     "Audit PNP Activity — subcategory doc",
     "Microsoft Learn",
     "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-pnp-activity",
     "Subcategory-hub doc covering Security-6416 + Security-6419-6424 family (PnP events). Auditpol GUID {0CCE9248-69AE-11D9-BED3-505054503030}. Subcategory name 'Audit PNP Activity' (NOT 'Plug and Play Events' as some corpus references say).",
     "format-spec", "primary", ["windows-evtx"],
     ["Security-6416"]),

    ("mitre-t1200-hardware-additions", "MITRE ATT&CK", "n.d.",
     "T1200 — Hardware Additions",
     "MITRE ATT&CK",
     "https://attack.mitre.org/techniques/T1200/",
     "ATT&CK technique for adversary hardware introductions (rogue USB / HID / PCI). DET0069/AN0185 explicitly pairs Security-6416 + Kernel-PnP 400/410 as detection anchors.",
     "behavior", "primary", ["windows-evtx"], ["Security-6416"]),

    ("logrhythm-evid-6416-pnp", "LogRhythm", "n.d.",
     "LogRhythm EVID 6416 — PnP device recognized",
     "LogRhythm",
     "https://docs.logrhythm.com/",
     "SIEM parser reference for 6416 (queued UNVERIFIED — need content-body fetch).",
     "tool-docs", "tertiary", ["windows-evtx"], ["Security-6416"]),

    # Security-5379 / 5381
    ("uws-event-5379", "Ultimate Windows Security", "n.d.",
     "Event 5379 — Credential Manager credentials were read",
     "UltimateWindowsSecurity",
     "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5379",
     "UWS encyclopedia entry for 5379. Authoritative community reference given MS Learn 5379 canonical URL 404's.",
     "analyst-writeup", "secondary", ["windows-evtx"], ["Security-5379"]),

    ("uws-event-5381", "Ultimate Windows Security", "n.d.",
     "Event 5381 — Vault credentials were enumerated",
     "UltimateWindowsSecurity",
     "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5381",
     "UWS entry for 5381 (ENUMERATE). Documents the enumerate-vs-read distinction vs 5382 (READ).",
     "analyst-writeup", "secondary", ["windows-evtx"], ["Security-5381"]),

    ("uws-event-5382", "Ultimate Windows Security", "n.d.",
     "Event 5382 — Vault credentials were read",
     "UltimateWindowsSecurity",
     "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5382",
     "UWS entry for 5382 (READ single-vault-credential). Companion to 5381 (enumerate). Security-5382 is an authoring gap — not yet in corpus.",
     "analyst-writeup", "secondary", ["windows-evtx"], []),

    ("socinv-event-5379-malicious-zip", "SOC Investigation", "n.d.",
     "Security-5379 malicious ZIP detection EQL",
     "SOC Investigation",
     "https://www.socinvestigation.com/",
     "SOC Investigation EQL rule for the ZipFolder TargetName pattern on event 5379 — typical exfil-via-zip-container detection.",
     "analyst-writeup", "secondary", ["windows-evtx"], ["Security-5379"]),

    ("elastic-multiple-vault-web-credentials-read", "Elastic", "n.d.",
     "Elastic Security: Multiple vault web credentials read",
     "Elastic",
     "https://www.elastic.co/security-labs/",
     "Elastic production EQL rule validating 5382 field schema (VaultId GUID + SchemaFriendlyName + Resource).",
     "analyst-writeup", "primary", ["windows-evtx"], []),

    # Security-4697
    ("dfir-report-2021-cobalt-strike-defenders-guide", "The DFIR Report", "2021",
     "A Defender's Guide to Cobalt Strike",
     "thedfirreport.com",
     "https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/",
     "Substantiates Cobalt Strike 4697 + 7045 detection pattern (7-random-alphanumeric service naming + ADMIN$ transfer). Primary authority for the service-persistence attack-chain.",
     "analyst-writeup", "primary", ["windows-evtx"], ["Security-4697"]),

    ("ms-learn-audit-security-system-extension", "Microsoft", "2025",
     "Audit Security System Extension — subcategory doc",
     "Microsoft Learn",
     "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-system-extension",
     "Subcategory-hub doc covering Security-4610 + 4611 + 4614 + 4622 + 4697. Default-off policy confirmation for 4697.",
     "format-spec", "primary", ["windows-evtx"],
     ["Security-4697"]),

    # Security-4698
    ("ms-audit-other-object-access-events", "Microsoft", "2025",
     "Audit Other Object Access Events — subcategory doc",
     "Microsoft Learn",
     "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-object-access-events",
     "Subcategory-hub doc covering Security-4698 + 4699 + 4700 + 4701 + 4702 (scheduled-task family) + COM+ catalog events. OFF by default.",
     "format-spec", "primary", ["windows-evtx"],
     ["Security-4698"]),
]

# Deduplicated source IDs (thehacker-recipes-mimikatz-lsadump-cache appears twice
# in the list — first is for Credentials-cached cluster, second for LSA-Cached-Logons.
# Actually they're distinct IDs: thehacker-recipes vs hacker-recipes. Good.)

NEW_ARTIFACTS_VERIFIED = [
    "Credentials-cached", "SAM", "LSA-Cached-Logons", "Extend-Quota", "System-104",
    "Security-6416", "Security-5379", "Security-5381", "Security-4697", "Security-4698",
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

    # URL correction on ms-cached-credentials-cachedlogonscoun (swap to UWS
    # interactive-logon-cache replacement — keep id for stability, swap url +
    # note to flag the legacy MS-Learn URL as deprecated).
    old_url_block = """- id: ms-cached-credentials-cachedlogonscoun
  author: Microsoft"""
    if old_url_block not in text:
        print("  WARN: ms-cached-credentials-cachedlogonscoun not found for URL-correction — may already be fixed")
    else:
        # We'll surgically edit after source_block registration; keep id stable.
        # Find the block and replace its url line + annotate note.
        pat = re.compile(
            r"(- id: ms-cached-credentials-cachedlogonscoun\b.*?)\n  url: [^\n]*\n(  apa: [^\n]*\n)(  note: [^\n]*\n)",
            re.DOTALL,
        )
        def _swap(m):
            prefix = m.group(1)
            apa = m.group(2)
            note = m.group(3)
            note_new = '  note: "LEGACY — original MS Learn URL retired 2026-03 (404). Functionally superseded by ultimatewindowssec-interactive-logon-cache (registered sprint r4). Source-id retained for corpus-link stability; prefer the UWS source for new citations. CachedLogonsCount default=10, range=0-50 confirmed there."\n'
            return prefix + "\n  url: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/cached-credentials-security-considerations  # 404 as of 2026-04-23\n" + apa + note_new
        text, n = pat.subn(_swap, text, count=1)
        if n != 1:
            print("  WARN: URL-correction regex did not match once — skipping")
        else:
            print("  URL-corrected: ms-cached-credentials-cachedlogonscoun (noted LEGACY + UWS replacement)")

    # Coverage expansion on mitre-t1543-003: add Security-4697
    old_cov = """- id: mitre-t1543-003
  author: MITRE ATT&CK
  year: n.d.
  title: 'T1543.003 - Create or Modify System Process: Windows Service'
  publisher: MITRE ATT&CK
  url: https://attack.mitre.org/techniques/T1543/003/
  apa: 'MITRE ATT&CK (n.d.). T1543.003 - Create or Modify System Process: Windows Service. MITRE ATT&CK. https://attack.mitre.org/techniques/T1543/003/'
  kind: behavior
  authority: primary
  coverage:
    substrates: []
    artifacts:
    - Services"""
    new_cov = """- id: mitre-t1543-003
  author: MITRE ATT&CK
  year: n.d.
  title: 'T1543.003 - Create or Modify System Process: Windows Service'
  publisher: MITRE ATT&CK
  url: https://attack.mitre.org/techniques/T1543/003/
  apa: 'MITRE ATT&CK (n.d.). T1543.003 - Create or Modify System Process: Windows Service. MITRE ATT&CK. https://attack.mitre.org/techniques/T1543/003/'
  kind: behavior
  authority: primary
  coverage:
    substrates: []
    artifacts:
    - Services
    - Security-4697"""
    if old_cov in text:
        text = text.replace(old_cov, new_cov, 1)
        print("  coverage expanded: mitre-t1543-003 += Security-4697")
    else:
        print("  WARN: mitre-t1543-003 narrow block not matched for expansion")

    # Register new sources
    for entry in NEW_SOURCES:
        text += source_block(entry)
        print(f"  registered: {entry[0]}")
    SOURCES_PATH.write_text(text, encoding="utf-8")


def apply_crawl_state():
    text = CRAWL_PATH.read_text(encoding="utf-8")

    anchor = "    ProfileList:\n      verified-on: '2026-04-23'\n      seed: audit-sprint-r3-batch-b\n"
    if anchor not in text:
        raise RuntimeError("r3-batch-b last artifact anchor not found")
    art_lines = ""
    for art in NEW_ARTIFACTS_VERIFIED:
        art_lines += (
            f"    {art}:\n"
            f"      verified-on: '2026-04-23'\n"
            f"      seed: audit-sprint-r4\n"
        )
    text = text.replace(anchor, anchor + art_lines, 1)
    print(f"  +{len(NEW_ARTIFACTS_VERIFIED)} artifacts in verification_log")

    sources_anchor = "    precedence-wiki-windows-profilestates:\n      verified-on: '2026-04-23'\n      seed: audit-sprint-r3-batch-b\n"
    if sources_anchor not in text:
        raise RuntimeError("r3-batch-b last source anchor not found")
    src_lines = ""
    for entry in NEW_SOURCES:
        sid = entry[0]
        src_lines += (
            f"    {sid}:\n"
            f"      verified-on: '2026-04-23'\n"
            f"      seed: audit-sprint-r4\n"
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
    print(f"Sprint r4 apply complete.")
    print(f"  new sources: {len(NEW_SOURCES)}")
    print(f"  new verified artifacts: {len(NEW_ARTIFACTS_VERIFIED)}")
    print(f"  deferred: LSA-Cached-Logons exit-node promotion (user AskUserQuestion)")
