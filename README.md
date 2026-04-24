# DFIRCLI

A personal DFIR training regimen driven by Claude Code + the `cybersecurity-skills` plugin.

## What this is
A reference + training workspace for building tier-3 DFIR analyst skills. The heavy lifting (concept explanations, artifact references, tool walkthroughs) comes from the 98 DFIR skills in the `cybersecurity-skills` plugin. This repo layers structure on top: a study roadmap, progress log, curated skill index, and external training material links.

## Setup

From inside Claude Code, run:

```
/plugin marketplace add mukul975/Anthropic-Cybersecurity-Skills
/plugin install cybersecurity-skills@anthropic-cybersecurity-skills
```

Or, if you already have the repo cloned locally:

```
/plugin marketplace add C:\Users\mondr\Documents\ProgFor\ACS\Anthropic-Cybersecurity-Skills
/plugin install cybersecurity-skills@anthropic-cybersecurity-skills
```

Verify with `/plugin list`.

## How to use it
- Ask Claude anything DFIR-related — it will pull the relevant skill from the plugin automatically.
- "Walk me through analyzing a memory dump with Volatility" → loads `conducting-memory-forensics-with-volatility`.
- "What Windows artifacts show program execution?" → pulls Amcache, Prefetch, ShellBags, UserAssist skills.
- "Plan my study for this week" → Claude reads `training/roadmap.md` and `progress.md`.

## Layout
```
DFIRCLI/
├── CLAUDE.md               # Project instructions for Claude Code
├── skills-index.md         # Curated DFIR skill pointers into the plugin
├── training/
│   ├── roadmap.md          # Tier-1 → tier-3 study plan
│   └── resources.md        # External training materials
├── progress.md             # Your practice log
└── gaps.md                 # Topics not covered by the plugin
```
