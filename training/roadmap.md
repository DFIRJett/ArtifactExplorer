# DFIR Training Roadmap — Tier-1 → Tier-3

A phased study plan. Each phase maps to skills in `../skills-index.md`. Track progress in `../progress.md`.

## Phase 1 — Tier-1 Foundations
Goal: identify artifacts and follow a playbook without supervision.

- **Evidence handling:** chain of custody, write-blocking, hashing (`acquiring-disk-image-with-dd-and-dcfldd`)
- **Windows registry basics:** hives, NTUSER.DAT, SYSTEM (`analyzing-windows-registry-for-artifacts`)
- **Event logs:** Security/System/Application, EVTX parsing (`extracting-windows-event-logs-artifacts`)
- **Timeline fundamentals:** MAC times, super-timeline concepts (`performing-timeline-reconstruction-with-plaso`)
- **Triage playbook execution:** `triaging-security-incident-with-ir-playbook`

**Practice:** 3 CTF rooms (TryHackMe DFIR path), 1 sample case walkthrough.

## Phase 2 — Tier-2 Core Forensics
Goal: independently analyze an endpoint or memory image end-to-end.

- **Program execution artifacts:** Amcache, Prefetch, ShellBags, LNK, UserAssist (`analyzing-windows-amcache-artifacts`, `analyzing-windows-shellbag-artifacts`, `analyzing-windows-lnk-files-for-artifacts`)
- **Persistence hunting:** `hunting-for-registry-persistence-mechanisms`, `hunting-for-registry-run-key-persistence`, `analyzing-malware-persistence-with-autoruns`
- **Memory forensics:** `performing-memory-forensics-with-volatility3`, `extracting-credentials-from-memory-dump`
- **Network artifacts:** `performing-network-forensics-with-wireshark`, `analyzing-network-traffic-for-incidents`
- **Browser + email:** `analyzing-browser-forensics-with-hindsight`, `investigating-phishing-email-incident`
- **Timeline assembly:** `building-incident-timeline-with-timesketch`

**Practice:** SANS 13Cubed miniseries, one full DFIR Report case emulation, one Aboutdfir challenge.

## Phase 3 — Tier-3 Advanced
Goal: hunt unknown threats, handle multi-system cases, drive campaign attribution.

- **Advanced memory:** Volatility3 plugins deep dive, rootkit detection (`performing-memory-forensics-with-volatility3-plugins`, `detecting-fileless-malware-techniques`)
- **Fileless & LOLBin hunting:** PowerShell obfuscation (`deobfuscating-powershell-obfuscated-malware`, `analyzing-powershell-empire-artifacts`)
- **Malware reverse engineering:** `reverse-engineering-malware-with-ghidra`, `reverse-engineering-dotnet-malware-with-dnspy`, `analyzing-malware-sandbox-evasion-techniques`
- **Cloud IR at scale:** `performing-cloud-forensics-with-aws-cloudtrail`, `performing-cloud-log-forensics-with-athena`, `performing-cloud-native-forensics-with-falco`
- **Ransomware + supply chain:** `investigating-ransomware-attack-artifacts`, `analyzing-supply-chain-malware-artifacts`
- **IOC pipelines + threat intel integration:** `building-ioc-enrichment-pipeline-with-opencti`, `analyzing-campaign-attribution-evidence`
- **Post-incident discipline:** `conducting-post-incident-lessons-learned`

**Practice:** full Flare-On challenge, one BSides / DEFCON DFIR village CTF, one original case writeup.

## Phase 4 — Specialization tracks (pick one or more)
- **Cloud forensics specialist** — full cloud section of the skills index
- **Malware RE specialist** — full malware analysis section
- **OT/ICS responder** — `implementing-ot-incident-response-playbook` + external SANS ICS content
- **Mobile forensics** — `performing-mobile-device-forensics-with-cellebrite`, `detecting-mobile-malware-behavior`
