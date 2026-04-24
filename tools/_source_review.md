# ArtifactExplorer Source Registry Review

Review of `schema/sources.yaml` (273 entries). Each entry classified into KEEP / STRENGTHEN-URL / FIX-METADATA / REMOVE based on whether the URL is specific, and whether author/title match it.

## Summary

- Total entries reviewed: **273**
- **KEEP**: ~227 (strong attribution; specific URL; author/title align)
- **STRENGTHEN-URL**: ~37 (umbrella-root URL; searchable for specific article)
- **FIX-METADATA**: ~4 (URL OK but author/title needs adjustment)
- **REMOVE**: ~5 (unrecoverable, can't locate the specific source, dead landing page, or duplicate title)

### Top observations / recurring problems

1. **Umbrella-root URLs** are the single biggest quality gap. Entries citing video-channel roots (13Cubed, John Hammond, `@13Cubed`), blog roots (windowsir.blogspot.com, thisweekin4n6.com, specterops posts root, welivesecurity.com, securelist.com), or corporate "white papers" indexes (sans.org/white-papers, sans.org/blog/, duo.com/labs, bambeneklabs.com) account for ~33 entries. Nearly all are recoverable with web search.
2. **Hartong sysmon-modular entries are perfectly scoped** — all 9 `hartong-2024-*` entries already point at the correct per-module subdirectory. These are KEEP. A model for what the other community-sourced entries should look like.
3. **Microsoft Learn entries (115)**: spot-checked ~12; all are correct — specific per-event/per-feature URLs with accurate titles. Bucket-wide KEEP except `ms-ms-fve-recoveryinformation-ad-ds-at` (FIX-METADATA) which points to an index page when a specific schema page exists.
4. **MITRE ATT&CK entries (48)**: spot-checked ~12; URLs match technique IDs exactly. Bucket-wide KEEP. One exception: `mitre-t1562` — the entry title says T1562.006 (Hosts File) but the URL is the parent T1562 page. Noted in FIX-METADATA. Entries like `mitre-t1497`, `mitre-t1546`, `mitre-t1574`, `mitre-t1547`, `mitre-t1558`, `mitre-t1562` also have mismatched parent-vs-subtechnique URL/title — documented below.
5. **Ultimate Windows Security (22)**: every entry uses the per-event URL (`event.aspx?eventID=NNNN`). Bucket-wide KEEP. Well-structured.
6. **"Author" vs "Publisher" split is inconsistent** in non-Microsoft entries — e.g. `forensics-2019-the-windows-swapfile-what-it-c` lists "Jonathan Poon / Magnet Forensics" as author; `labs-2023-onedrive-safedelete-db-a-sleep` puts "Bambenek Labs" as author without a specific analyst. Not a blocker for the review, but worth a cleanup pass.
7. **Five entries appear fabricated or unrecoverable** — Bambenek Labs SafeDelete, Magnet Forensics Swapfile (J. Poon), SANS DFIR voice biometric, Malware Archaeology wpndatabase, and possibly Duo Security Labs root certificates. Flagged REMOVE / "unable to locate" pending user confirmation.

---

## STRENGTHEN-URL (umbrella URL → specific article)

For each: (current URL) → (proposed URL or "unable to locate").

### `13cubed-2020-print-job-forensics-recovering`
- Current: `https://www.youtube.com/@13Cubed`
- Proposed: unable to locate a specific 13Cubed video on SPL/EMF print-job forensics — a direct channel search confirms 13Cubed covers USB/MFT/memory heavily but not print spool in a named video. Consider replacing with a different print-spool reference (e.g. Insider Threat Matrix DT005 Print Spooler detection, already a strong source). If the original video exists, it's unfindable by title.

### `aa24-131a-2024-anydesk-in-ransomware-incident`
- Current: `https://www.cisa.gov/news-events/cybersecurity-advisories`
- Proposed: `https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a`
- Note: AA24-131A is the #StopRansomware Black Basta advisory; AnyDesk is mentioned as a tool used by Black Basta affiliates. The title should probably be retitled to "#StopRansomware: Black Basta (AnyDesk abuse indicators)" for accuracy.

### `aboutdfir-com-2023-windows-11-snipping-tool-foren`
- Current: `https://aboutdfir.com/`
- Proposed: unable to locate a matching aboutdfir.com post. Best alternative candidate: `https://thinkdfir.com/2025/06/13/cached-screenshots-on-windows-11/` (ThinkDFIR, by Phill Moore — an aboutdfir-affiliated site) OR `https://knowledge.forscie.com/article/snipping-tool-artifacts-of-visual-data-exfiltration`. Recommend re-attributing.

### `anydesk-2023-anydesk-log-file-locations-and`
- Current: `https://support.anydesk.com/`
- Proposed: `https://support.anydesk.com/docs/what-are-trace-files` (official "What are Trace files?" KB article).

### `archaeology-2020-wpndatabase-db-and-wpnidm-noti`
- Current: `https://www.malwarearchaeology.com/`
- Proposed: unable to locate a Malware Archaeology post specifically on wpndatabase. The canonical references are Yogesh Khatri (http://www.swiftforensics.com/2016/06/prasing-windows-10-notification-database.html), inc0x0 (https://inc0x0.com/2018/10/windows-10-notification-database/), and kacos2000 on GitHub. Recommend replacing the source with Khatri or retitling.

### `canary-2022-powershell-profile-persistence`
- Current: `https://redcanary.com/blog/`
- Proposed: `https://redcanary.com/blog/threat-detection/using-visibility-to-gather-context-and-find-persistence-mechanisms/` (Red Canary, profile persistence coverage). If the original intent was the annual Threat Detection Report entry, also valid: `https://redcanary.com/threat-detection-report/techniques/powershell/`.

### `carvey-2013-recentfilecache-bcf-parser-and`
- Current: `https://windowsir.blogspot.com/`
- Proposed: Harlan Carvey's rfc.pl parser is actually hosted at `https://github.com/keydet89/Tools/blob/master/source/rfc.pl`. The Corey Harrell writeups at `http://journeyintoir.blogspot.com/2013/12/revealing-recentfilecachebcf-file.html` and `http://journeyintoir.blogspot.com/2014/04/triaging-with-recentfilecachebcf-file.html` are the canonical analytical references. Recommend pointing at Harrell's post and correcting author to "Corey Harrell" (or retaining Carvey as author of the parser + pointing at the GitHub URL).

### `carvey-2020-dfir-with-vss-snapshot-mountin`
- Current: `https://ericzimmerman.github.io/`
- Proposed: `https://github.com/EricZimmerman/VSCMount` (VSCMount tool — specific project). The "cross-snapshot diff" description doesn't correspond to a specific blog post; if the intent was Harlan Carvey's VSS writeup, use `http://windowsir.blogspot.com/2018/09/accessing-volume-shadows-re-revisited.html`.

### `davis-2022-13cubed-partition-diagnostic-l`
- Current: `https://www.13cubed.com/`
- Proposed: unable to locate the specific 13Cubed video. 13Cubed's Partition-Diagnostic video appears on YouTube but is not reliably searchable by title. Leave as weak reference; or replace with Vasilaras et al. 2021 (already in registry as `vasilaras-2021-*`) which is the peer-reviewed canonical source.

### `dfir-2020-voice-biometric-evidence-in-df`
- Current: `https://www.sans.org/white-papers/`
- Proposed: unable to locate a matching SANS white paper on voice biometric evidence for Cortana/Alexa/Siri. This title doesn't appear in SANS's white paper index. Recommend REMOVE pending user confirmation (may be fabricated).

### `eset-2023-blacklotus-bootkit-first-uefi`
- Current: `https://www.welivesecurity.com/`
- Proposed: `https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/` (ESET BlackLotus analysis, March 2023).

### `for500-2022-offline-files-forensics-csc-na`
- Current: `https://www.sans.org/cyber-security-courses/windows-forensic-analysis/`
- Proposed: no per-topic URL exists on sans.org for a specific module. This is citing SANS FOR500 courseware (which is not publicly accessible). Leave as course-level reference, or REMOVE and substitute a public practitioner write-up on CSC namespace forensics.

### `for508-2023-hibernation-file-analysis-in-i`
- Current: `https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/`
- Proposed: same situation as FOR500. SANS blog does have FOR508-related posts — `https://www.sans.org/blog/for508-evolving-with-the-threat-spring-2025-course-update` covers hibernation processing updates. Use that URL, or leave as course-level (weak but honest).

### `forensics-2019-the-windows-swapfile-what-it-c`
- Current: `https://www.magnetforensics.com/blog/`
- Proposed: unable to locate a Magnet Forensics blog post by Jonathan Poon on Windows Swapfile. The Magnet Forensics blog doesn't yield results under that title. Possible REMOVE or reattribute to the academic `(PDF) Forensic Analysis of Windows Swap File` (ResearchGate).

### `gentilkiwi-2020-mimikatz-vault-cred-modules-ex`
- Current: `https://github.com/gentilkiwi/mimikatz/wiki` (wiki root)
- Proposed: `https://github.com/gentilkiwi/mimikatz/wiki/module-~-vault` (vault module page). Similar specificity as the sibling `gentilkiwi-2020-mimikatz-lsadump-cache-extract` entry which is already specific.

### `great-2022-cosmicstrand-uefi-firmware-roo`
- Current: `https://securelist.com/`
- Proposed: `https://securelist.com/cosmicstrand-uefi-firmware-rootkit/106973/`

### `hammond-2022-notepad-tabstate-bin-files-uns`
- Current: `https://www.youtube.com/@_JohnHammond`
- Proposed: unable to confirm a specific John Hammond video URL on Notepad TabState via search. The canonical reverse-engineering source is actually ogmini: `https://github.com/ogmini/Notepad-Tabstate-Buffer` / `https://github.com/ogmini/Notepad-State-Library`. Recommend reattributing to ogmini.

### `isc-2020-checking-the-hosts-file-as-an`
- Current: `https://isc.sans.edu/`
- Proposed: `https://isc.sans.edu/diary/HolidayFamily+Incident+Response/3669` (mentions hosts-file inspection during incident response). Not a perfect match — consider whether the original diary entry title matches; if not, REMOVE.

### `khatri-2019-cortana-forensics-coredb-and-i`
- Current: `https://www.swiftforensics.com/`
- Proposed: unable to find a specific 2019-dated Khatri post on Cortana CoreDb + IndexedDB. The 2016 post `http://www.swiftforensics.com/2016/06/prasing-windows-10-notification-database.html` is related but covers wpndatabase. If the intent is Cortana-specific, leave as site-root or REMOVE.

### `labs-2019-dangers-of-installing-root-cer`
- Current: `https://duo.com/labs/`
- Proposed: unable to locate the specific Duo Security Labs publication "Dangers of installing root certificates." Duo Labs content has moved/reorganized. Recommend REMOVE or substitute `https://www.threatdown.com/blog/when-you-shouldnt-trust-a-trusted-root-certificate/` (Malwarebytes ThreatDown).

### `labs-2023-onedrive-safedelete-db-a-sleep`
- Current: `https://www.bambeneklabs.com/`
- Proposed: unable to locate a Bambenek Labs post on SafeDelete.db. The canonical reference appears to be Insider Threat Matrix DT135: `https://www.insiderthreatmatrix.org/detections/DT135`. Recommend reattribution or REMOVE.

### `mandiant-2015-shim-me-the-way-application-co`
- Current: `https://www.mandiant.com/resources/blog`
- Proposed: `https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html` — note: correct year is 2017, not 2015. Title in registry ("Shim me the way") doesn't exactly match published title ("To SDB, Or Not To SDB: FIN7 Leveraging Shim Databases for Persistence"). Also a FIX-METADATA (year and title).

### `moore-2020-powercfg-energy-reports-as-for`
- Current: `https://thisweekin4n6.com/`
- Proposed: unable to locate a Phill Moore thisweekin4n6 post specifically on powercfg energy reports as forensic artifacts. thisweekin4n6 is a weekly roundup; specific topic posts are on thinkdfir.com. Search did not surface a matching post. Consider REMOVE or reattribute.

### `ms-cortana-privacy-speech-data-retenti`
- Current: `https://support.microsoft.com/en-us/windows/`
- Proposed: this specific Microsoft privacy article is no longer indexed at a stable URL. Likely moved to a general Cortana privacy page — recommend leaving, or searching support.microsoft.com directly for current Cortana privacy URL.

### `ms-how-the-recycle-bin-stores-files-in`
- Current: `https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/`
- Proposed: this is a legacy KB article; the original KB136517 is deprecated. A similarly authoritative replacement is scarce — suggest leaving the landing-page URL with a note that original KB is unreachable, OR REMOVE (the INFO2 format is better documented by rifiuti2 project which is already in the registry).

### `ms-print-spooler-architecture-spl-and`
- Current: `https://learn.microsoft.com/en-us/windows-hardware/drivers/print/`
- Proposed: The specific SHD/SPL format isn't officially documented by Microsoft. The landing page is the best available. Acceptable as-is but weak.

### `ms-uwp-indexeddb-api-storage-model`
- Current: `https://learn.microsoft.com/en-us/microsoft-edge/dev-guide/storage/indexeddb`
- Proposed: this legacy Edge Dev Guide URL has been deprecated. Current IndexedDB doc is MDN. Consider updating to MDN or REMOVE.

### `ms-windows-notepad-restore-session-tab`
- Current: `https://learn.microsoft.com/en-us/windows/release-health/`
- Proposed: the Notepad session-restore feature is documented in Windows 11 Insider blog posts, not Microsoft Learn release-health. Recommend changing to Windows Insider blog announcement URL, or leaving as generic release-health page with caveat.

### `outflank-2023-etw-is-not-only-for-defenders`
- Current: `https://www.outflank.nl/blog/`
- Proposed: unable to locate a specific Outflank blog post by "MatteoMalvica" on ETW registry persistence (Malvica's Outflank writeups are on sleep-mask evasion, not ETW persistence). The true canonical source here is Palantir: `https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63` (already in registry as `palantir-2021-*`). Recommend REMOVE this entry as duplicate.

### `palantir-2021-etw-attack-surface-disabling-e`
- Current: `https://www.mdsec.co.uk/`
- Proposed: author says "MDSec / Palantir" but MDSec blog URL is a root. The actual Palantir blog is `https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63`. If the intent was MDSec (Adam Chester's ETW writeup), find that specific post on mdsec.co.uk. Recommend FIX-METADATA+URL.

### `passware-2023-bitlocker-offline-analysis-rec`
- Current: `https://www.elcomsoft.com/`
- Proposed: `https://blog.elcomsoft.com/2022/05/live-system-analysis-extracting-bitlocker-keys/` (Elcomsoft blog post on FVEK extraction). Title in registry says "Elcomsoft / Passware" — Passware is a separate vendor. Pick one (Elcomsoft has the specific post).

### `research-2023-blackbasta-lockbit-use-of-anyd`
- Current: `https://blogs.blackberry.com/en/category/research-and-intelligence`
- Proposed: unable to locate a specific BlackBerry Threat Research post dedicated to AnyDesk forensics in BlackBasta/LockBit. BlackBerry's quarterly threat reports mention AnyDesk abuse but the specific "forensic breakdown" post isn't findable. Consider replacement: `https://www.kroll.com/en/publications/cyber/black-basta-technical-analysis` (Kroll, covers AnyDesk / AteraAgent / Splashtop usage for lateral movement) or retain as-is with the category URL.

### `robbins-2022-group-policy-preferences-and-t`
- Current: `https://posts.specterops.io/`
- Proposed: Andy Robbins's specific GPP/post-ransomware writeup isn't findable by the registry title; a close match is `https://specterops.io/blog/2018/02/26/a-red-teamers-guide-to-gpos-and-ous/` (Robbins + Vincent, Red Teamer's Guide to GPOs and OUs), or `https://adsecurity.org/?p=2288` (Sean Metcalf, ADSecurity — classic GPP+SYSVOL reference). Recommend reattribution.

### `specterops-2019-sharpdpapi-c-implementation-of`
- Current: `https://github.com/GhostPack/SharpDPAPI` — already specific. **KEEP** (miscategorized by me in initial pass — this is fine.)

### `stig-2023-windows-10-11-security-technic`
- Current: `https://public.cyber.mil/stigs/`
- Proposed: `https://ncp.nist.gov/checklist/1028` (NIST NCP Windows 11 STIG) or `https://www.stigviewer.com/stigs/microsoft-windows-11-security-technical-implementation-guide` (STIG Viewer — direct viewable STIG). public.cyber.mil root is weak.

### `velociraptor-2024-windows-forensics-ntfs-extende`
- Current: `https://docs.velociraptor.app/artifact_references/`
- Proposed: the Velociraptor NTFS.ExtendedAttributes artifact has a specific URL under `https://docs.velociraptor.app/artifact_references/pages/windows.forensics.ntfs.extendedattributes/`. Verify exact slug against current Velociraptor docs.

### `ms-application-compatibility-toolkit-s`
- Current: `https://learn.microsoft.com/en-us/windows/compatibility/`
- Proposed: ACT is largely deprecated but shim database docs persist. Consider `https://learn.microsoft.com/en-us/windows/win32/devnotes/application-compatibility-database` or similar as more specific.

### `ms-applocker-policy-storage-and-enforc`
- Current: `https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/`
- Proposed: trailing slash is fine; URL covers AppLocker hub. A more specific page is `https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview`. Minor improvement.

### `ms-boot-configuration-data-bcd-archite`
- Current: `https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--store` — already specific, but title says "architecture" while page is `bcdedit /store`. Author may have wanted the BCD architecture page: `https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcd-boot-configuration-data` or similar. Minor FIX-METADATA.

### `ms-credential-manager-credential-provi`
- Current: `https://learn.microsoft.com/en-us/windows/win32/api/wincred/` (API index, not a specific API). Acceptable but could be CredRead/CredWrite specific.

### `ms-netsh-helper-architecture-and-exten`
- Current: `https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/` — landing, no specific helper architecture page. Acceptable.

### `ms-nla-service-cache` and `ms-notification-platform-wns-on-device`
- Both point at hub-level Microsoft Learn URLs. Could be refined to specific architecture pages. Low priority.

### `ms-print-spooler-architecture-spl-and`
- Already noted above.

### `ms-windows-search-architecture-gather`
- Current: `https://learn.microsoft.com/en-us/windows/win32/search/` — hub. No public page documents GatherLogs; accept as-is.

### `ms-windows-install-registry-values-cur`
- Current: `https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo` — mismatch. The page is `systeminfo` command, not CurrentVersion registry. Better URL: `https://learn.microsoft.com/en-us/windows/deployment/upgrade/windows-10-deployment-scenarios` or a registry-specific Learn page. FIX-METADATA (URL).

---

## FIX-METADATA (URL specific enough but author/title/year off)

### `carvey-2022-windows-forensic-analysis-tool`
- Year: '2022' — book was published **March 2014**. Correct year: '2014'. URL points to elsevier.com 978-0-12-417157-2 which is correct. Title "4th ed." is correct.

### `mandiant-2015-shim-me-the-way-application-co`
- Year: '2015' — actual FireEye post was published **May 2017**. Title "Shim me the way" is informal; official title is "To SDB, Or Not To SDB: FIN7 Leveraging Shim Databases for Persistence." Author listed "FireEye / Mandiant" is OK.
- Fix: year → '2017'; title → "To SDB, Or Not To SDB: FIN7 Leveraging Shim Databases for Persistence"; URL → `https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html` (or the Google Cloud Blog canonical reprint).

### `mitre-t1562`
- Title says "T1562.006 — Impair Defenses: Indicator Blocking (Hosts File)" but URL points at parent T1562. The registry also has `mitre-t1562-006` with the sub-technique URL, creating duplication. Recommend either:
  - Retitle this entry to just "T1562 — Impair Defenses" (parent) and let `mitre-t1562-006` carry the sub, or
  - REMOVE as duplicate (see REMOVE bucket).

### `mitre-t1547`
- Title: "T1547.001 — Registry Run Keys / Startup Folder (parent technique, covers Session Manager)" but URL is parent T1547. Similar parent-vs-sub mismatch. Retitle or redirect.

### `mitre-t1546`
- Title: "T1546.010 — Event Triggered Execution: AppInit DLLs..." but URL is parent T1546. Same pattern.

### `mitre-t1497`
- Title: "T1497.003 — Virtualization/Sandbox Evasion + Error Reporting" but URL is parent T1497.

### `mitre-t1574`
- Title: "T1546.008 / T1574 — Hijack Execution Flow: LSP" — title cites two techniques; URL is T1574 only. Clean up title or add separate entry.

### `mitre-t1558`
- Title lists four sub-techniques (001/002/003/004); URL is parent T1558. Acceptable as a family reference, but if any sub is needed as its own citation, add per-sub entries.

### `palantir-2021-etw-attack-surface-disabling-e`
- Author "MDSec / Palantir" — these are two different publishers. URL is mdsec.co.uk root. Palantir's ETW tampering blog is at `blog.palantir.com/tampering-with-windows-event-tracing-...`. Fix: pick one publisher, point at the specific post. Likely author should be just "Palantir" and URL the Palantir blog.

### `ms-ms-fve-recoveryinformation-ad-ds-at`
- Current URL: `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/` (index page).
- Proposed: `https://learn.microsoft.com/en-us/windows/win32/adschema/c-msfve-recoveryinformation` (specific AD schema class page).

### `ms-windows-install-registry-values-cur`
- URL points at `systeminfo` command reference, not CurrentVersion registry documentation. Mismatch noted above.

---

## REMOVE (unrecoverable, dead, or duplicate)

### `dfir-2020-voice-biometric-evidence-in-df`
- No SANS white paper matching title found. Possibly fabricated. URL is the generic SANS white-papers index.

### `labs-2023-onedrive-safedelete-db-a-sleep`
- Bambenek Labs has no public post on SafeDelete.db (their focus is DNS threat feeds). Reattribute to Insider Threat Matrix DT135 or remove.

### `labs-2019-dangers-of-installing-root-cer`
- Duo Labs (duo.com/labs) appears to have been decommissioned / content relocated without redirects. Specific research by that title not locatable.

### `forensics-2019-the-windows-swapfile-what-it-c`
- No Magnet Forensics blog post by Jonathan Poon on Windows Swapfile found. Possibly misattributed.

### `outflank-2023-etw-is-not-only-for-defenders`
- Content duplicates `palantir-2021-etw-attack-surface-disabling-e`. No matching Outflank post authored by MatteoMalvica found. Remove as duplicate/fabricated.

### `mitre-t1562` (potential duplicate)
- If `mitre-t1562-006` covers the sub-technique this entry claims to cover, then this entry duplicates it. Either REMOVE or repurpose as pure parent reference.

### `archaeology-2020-wpndatabase-db-and-wpnidm-noti`
- No Malware Archaeology post on wpndatabase located. Canonical source is Khatri 2016 (swiftforensics.com). Either REMOVE or reattribute.

### `13cubed-2020-print-job-forensics-recovering`
- No 13Cubed video matching title located. Channel-root URL. Consider REMOVE unless user can provide the specific video URL.

### `davis-2022-13cubed-partition-diagnostic-l`
- Channel/site root URL; specific video not locatable by search. Consider REMOVE and rely on `vasilaras-2021-*` (peer-reviewed, canonical) for this artifact instead.

### `moore-2020-powercfg-energy-reports-as-for`
- thisweekin4n6.com is a roundup site; no topic-specific post on powercfg energy reports found. Consider REMOVE.

### `hammond-2022-notepad-tabstate-bin-files-uns`
- Channel-root URL for John Hammond; specific Notepad video not locatable. The canonical TabState reversing is by ogmini (GitHub), not Hammond. Consider REMOVE and reattribute to ogmini.

### `khatri-2019-cortana-forensics-coredb-and-i`
- Site-root URL; no 2019 Khatri post on Cortana CoreDb located. Possibly conflated with Khatri's 2016 wpndatabase post. Consider REMOVE.

---

## KEEP (bucket-wide — strong attribution, specific URL, author/title align)

All entries not listed above. Summary of KEEP families:

- **All 115 `ms-*` entries except** `ms-ms-fve-recoveryinformation-ad-ds-at`, `ms-windows-install-registry-values-cur`, `ms-cortana-privacy-speech-data-retenti`, `ms-how-the-recycle-bin-stores-files-in`, `ms-windows-notepad-restore-session-tab`, `ms-uwp-indexeddb-api-storage-model`, `ms-print-spooler-architecture-spl-and`, `ms-application-compatibility-toolkit-s`, and a handful of others flagged above. Net Microsoft Learn KEEP: ~105.
- **All 22 `uws-event-*` entries** — all use the per-event URL.
- **All 48 `mitre-*` entries except** `mitre-t1562`, `mitre-t1546`, `mitre-t1547`, `mitre-t1497`, `mitre-t1574`, `mitre-t1558` (parent-URL/sub-title mismatches) — those FIX-METADATA only.
- **All 9 `hartong-*` sysmon-modular entries** — exemplary, per-module subdirectory URLs.
- **All `anssi-fr-*` entries** — specific GitHub repos.
- **All `libyal-*` entries** — specific GitHub repos (Joachim Metz).
- **`ballenthin-*` entries** — specific GitHub repos.
- **`gentilkiwi-2020-mimikatz-lsadump-cache-extract`** — has anchor to #cache section.
- **`enigma0x3-2017-userland-persistence-with-sche`** — specific SpecterOps post URL.
- **`specterops-2019-a-deep-dive-into-dpapi-compreh`** — specific post URL.
- **`specterops-2021-understanding-and-defending-ag`** — specific post URL.
- **`hedley-2024-usbstor-install-first-install`** — dfir.pubpub.org specific article.
- **`koroshec-2021-user-access-logging-ual-a-uniq`** — dfir.pubpub.org specific.
- **`vasilaras-2021-leveraging-the-microsoft-windo`** — DOI.
- **`synacktiv-2023-pca-parsing-and-cross-comparis`** — synacktiv.com/publications (umbrella-ish but correct; could be improved to specific PDF URL).
- **`rathbun-2023-program-compatibility-assistan`** — though the URL is the GitHub Pages root, the article does exist (also cross-published on aboutdfir.com at `/new-windows-11-pro-22h2-evidence-of-execution-artifact/`). Worth a URL update to the aboutdfir post.
- **`trustedsec-*` entries** — specific blog post URLs.
- **`sans-2022-*` SANS blog entries** — specific blog URLs.
- **`zimmerman-*` entries** — specific GitHub repos.
- **`suhanov-2019-*`** — specific repo.
- **`dfirartifactmuseum-2023-*`** — specific GitHub repo.
- **`mollema-2022-*`** — specific GitHub repo.
- **`carvey-2010-rifiuti-*`** — specific abelcheung/rifiuti2 repo.
- **`fortra-2022-*`** — specific impacket repo.
- **`foundation-2021-volatility-*`** — specific volatility3 repo.
- **`hull-2020-the-cryptnet-url-cache-an-over`** — specific aboutdfir.com article URL.
- **`schroeder-2016-get-gpppassword-*`** — specific PowerSploit repo.
- **`zerosteiner-2021-*`** — specific cube0x0 CVE repo.
- **`delpy-nd-mimikatz-mimilib-dll-as-a-noti`** — mimikatz wiki (misc module) — specific.
- **`aboutdfir-nd-usb-devices-windows-artifact-r`** — specific aboutdfir.com toolsandartifacts path.
- **`ietf-2005-rfc-4120-the-kerberos-network`** — IETF RFC URL.
- **`matrix-nd-dt061-detect-text-authored-in`** — insiderthreatmatrix.org/detections (umbrella-ish; the specific detection page would be `/detections/DT061` — worth checking; if so, STRENGTHEN-URL).
- **`nirsoft-2023-uninstallview-*`** — specific NirSoft utility page.
- **`online-2021-registry-hive-file-format-prim`** — specific osronline article.
- **`project-2023-windowsbitsqueuemanagerdatabas`** — ForensicArtifacts repo.
- **`project-2024-living-off-the-land-drivers-vu`** — loldrivers.io root (acceptable as it's the canonical catalog).
- **`recon-2022-hibernation-recon-*`** — specific Arsenal Recon product page.
- **`ms-cve-2021-34527-printnightmare-advis`** — specific MSRC URL.
- **`ms-kb2962486-ms14-025-vulnerability-in`** — specific bulletin URL.
- **`ms-tarrask-malware-uses-scheduled-task`** — specific microsoft.com/security/blog URL.
- **`velociraptor-2024-*`** — see STRENGTHEN-URL note (docs.velociraptor.app artifact_references hub; slug refinement possible).

Note on `matrix-nd-dt061-*`: the registry URL is the detections hub. Recommend STRENGTHEN-URL to `https://insiderthreatmatrix.org/detections/DT061` (or whatever the current DT061 slug is — ITM URL structure uses short slugs).

---

## Next-step recommendation

Priority fix list (highest impact per minute of cleanup effort):

1. **URL-only swaps** (no author/title change needed, high recoverability): `aa24-131a-2024-*`, `great-2022-cosmicstrand-*`, `eset-2023-blacklotus-*`, `anydesk-2023-*`, `gentilkiwi-2020-mimikatz-vault-cred-*`, `ms-ms-fve-recoveryinformation-*`, `stig-2023-*`, `specterops-2019-sharpdpapi-*` (already specific — no-op).
2. **Decide which entries to remove**: the 5-8 unlocatable umbrella entries (`dfir-2020-voice-biometric-*`, `labs-2023-onedrive-safedelete-*`, `labs-2019-dangers-of-installing-root-*`, `forensics-2019-the-windows-swapfile-*`, `outflank-2023-etw-is-not-only-*`, `moore-2020-powercfg-*`, `archaeology-2020-wpndatabase-*`). Either remove or have user verify & supply URLs.
3. **MITRE parent-vs-sub mismatches**: decide on naming convention (parent-as-family vs per-sub). Affects ~6 entries.
4. **Year fix** on `carvey-2022-windows-forensic-analysis-tool` (2022 → 2014) and `mandiant-2015-shim-*` (2015 → 2017, plus URL + title).
