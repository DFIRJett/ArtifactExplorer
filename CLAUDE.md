# ArtifactExplorer — DFIR Training Regimen

## Purpose
This project is a personal DFIR (Digital Forensics & Incident Response) training regimen and reference. The user is building tier-3 analyst skills and uses this project to:
- Look up DFIR concepts on demand
- Reference up-to-date artifact information across Windows/Linux/macOS
- Study tier-3 (senior analyst) topics: advanced memory forensics, threat hunting, adversary emulation, timeline analysis
- Find and track external training materials (CTFs, SANS courses, blogs, labs)

## Primary knowledge source
The `cybersecurity-skills` Claude Code plugin is installed and provides 98+ DFIR skills spanning:
- Disk/memory acquisition (dd, dcfldd, LiME, WinPMEM)
- Memory forensics (Volatility3, Rekall)
- Windows artifacts (Registry, Amcache, ShellBags, LNK, Prefetch, Event Logs, Jump Lists)
- Linux/macOS artifacts
- Malware analysis (static, dynamic, sandboxing)
- IR playbooks (cloud, phishing, ransomware, OT, supply chain)
- Timeline/IOC work (Timesketch, log2timeline, MISP, OpenCTI)
- Threat hunting and APT attribution

When the user asks about a DFIR concept, technique, tool, or artifact, **consult the plugin's skills first**. If the skill exists, walk through it. If not, answer from general knowledge and note the gap in `gaps.md`.

## How to interact with the user
- Assume tier-2-going-on-tier-3 baseline — skip entry-level definitions unless asked.
- When covering an artifact, always include: location/path, parser tool, forensic value, known anti-forensic caveats, and at least one hands-on practice hint.
- For concepts, tie back to MITRE ATT&CK techniques when relevant (the plugin skills are already framework-mapped).
- When the user asks "what should I study next?", pick from `training/roadmap.md` and factor in what's already logged in `progress.md`.
- Keep explanations practical and command-forward. This is a working reference, not a textbook.

## Project structure
- `skills-index.md` — curated pointer into the 98 DFIR-relevant plugin skills, grouped by phase (acquisition → analysis → reporting)
- `training/roadmap.md` — structured study plan (beginner → tier-3)
- `training/resources.md` — external links: SANS, Aboutdfir, 13Cubed, DFIR Report, CTFs, labs
- `progress.md` — user-maintained log of skills practiced, CTFs completed, concepts reviewed
- `gaps.md` — topics the user asked about that weren't covered by the plugin

## Guardrails
- Never suggest performing forensic techniques on systems the user doesn't own or isn't authorized to examine.
- When the user describes a "real" incident, ask whether this is a live case or a training exercise before giving specific commands.
