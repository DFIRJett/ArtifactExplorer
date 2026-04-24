"""Audit every source-id reference across the corpus that does NOT resolve
against schema/sources.yaml. These are the 'purple strings' that show as
bare IDs in walkthrough notifications instead of full APA citations.

For each orphan, classify by where it appears (artifact provenance, convergence
join-chain, scenario step primary-source, etc.) so the user knows what to fix.
"""
import yaml, glob, os
from collections import defaultdict

ROOT = r'C:\Users\mondr\Documents\ProgFor\ArtifactExplorer'

with open(os.path.join(ROOT, 'schema', 'sources.yaml'), 'r', encoding='utf-8') as f:
    sources = yaml.safe_load(f).get('sources', [])
registered = set(s['id'] for s in sources if s.get('id'))
print('Registered sources: ' + str(len(registered)))

# Track every reference: id -> list of (file_path, citation_context)
references = defaultdict(list)

def parse_md(fp):
    try:
        with open(fp, 'r', encoding='utf-8') as f:
            txt = f.read()
        if not txt.startswith('---'):
            return None
        end = txt.find('---', 3)
        return yaml.safe_load(txt[3:end])
    except Exception:
        return None

# Artifacts — provenance[]
for fp in glob.glob(os.path.join(ROOT, 'artifacts', '**', '*.md'), recursive=True):
    fm = parse_md(fp)
    if not fm: continue
    for sid in (fm.get('provenance') or []):
        references[sid].append((fp, 'artifact.provenance'))

# Convergences — provenance[] + join-chain[].sources[] + join-chain[].primary-source
for fp in glob.glob(os.path.join(ROOT, 'convergences', '*.md')):
    fm = parse_md(fp)
    if not fm: continue
    for sid in (fm.get('provenance') or []):
        references[sid].append((fp, 'convergence.provenance'))
    for jc in (fm.get('join-chain') or []):
        if jc.get('primary-source'):
            references[jc['primary-source']].append((fp, 'convergence.join-chain.primary-source'))
        for sid in (jc.get('sources') or []):
            references[sid].append((fp, 'convergence.join-chain.sources'))

# Scenarios — steps[].primary-source
for fp in glob.glob(os.path.join(ROOT, 'scenarios', '*.md')):
    fm = parse_md(fp)
    if not fm: continue
    for s in (fm.get('steps') or []):
        if s.get('primary-source'):
            references[s['primary-source']].append((fp, 'scenario.step.primary-source'))

# Find orphans
orphans = {sid: refs for sid, refs in references.items() if sid not in registered}

print()
print('=' * 60)
print('TOTAL REFERENCED SOURCE-IDS: ' + str(len(references)))
print('Resolved (in registry):     ' + str(len(references) - len(orphans)))
print('ORPHAN (not in registry):   ' + str(len(orphans)))
print('=' * 60)
print()

if orphans:
    print('ORPHAN SOURCE-IDs — render as bare IDs in viewer instead of APA:')
    print()
    # Sort by how many places reference them
    sorted_orphans = sorted(orphans.items(), key=lambda x: -len(x[1]))
    for sid, refs in sorted_orphans:
        print('  ' + sid + '  (' + str(len(refs)) + ' reference' + ('' if len(refs) == 1 else 's') + ')')
        ctx_counter = defaultdict(int)
        for fp, ctx in refs:
            ctx_counter[ctx] += 1
        for ctx, n in sorted(ctx_counter.items(), key=lambda x: -x[1]):
            print('    - ' + ctx + ' x' + str(n))
        # Show first 3 file paths for context
        seen_files = []
        for fp, ctx in refs:
            short = os.path.relpath(fp, ROOT).replace('\\', '/')
            if short not in seen_files:
                seen_files.append(short)
                if len(seen_files) >= 3: break
        for sf in seen_files:
            print('      ' + sf)
        if len(set(fp for fp, _ in refs)) > len(seen_files):
            print('      ... and ' + str(len(set(fp for fp, _ in refs)) - len(seen_files)) + ' more')
        print()
else:
    print('NO ORPHANS — every source-id referenced in the corpus resolves to the registry.')

# Also: registered but unreferenced (the inverse — sources sitting unused)
unreferenced_registered = registered - set(references.keys())
print()
print('=' * 60)
print('UNREFERENCED REGISTERED SOURCES (in registry but never cited): ' + str(len(unreferenced_registered)))
print('=' * 60)
print('(not surfaced in viewer at all — candidates for removal or for use)')
