"""Scan current orphan artifacts for concept-reference reinclusion candidates."""
import json, re, pathlib, yaml, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

d = json.load(open('viewer/data.json', encoding='utf-8'))
concepts = {c['name'] for c in d.get('concepts-meta', [])}

nodes = d['graph']['nodes']
links = d['graph']['links']
adj = {n['id']: set() for n in nodes}
for l in links:
    s = l['source'] if isinstance(l['source'], str) else l['source']['id']
    t = l['target'] if isinstance(l['target'], str) else l['target']['id']
    if s in adj and t in adj and s != t:
        adj[s].add(t); adj[t].add(s)

comp = {}; cid = 0; sizes = {}
for n in nodes:
    if n['id'] in comp: continue
    q = [n['id']]; comp[n['id']] = cid; cnt = 0
    while q:
        u = q.pop(0); cnt += 1
        for v in adj[u]:
            if v not in comp: comp[v]=cid; q.append(v)
    sizes[cid]=cnt; cid += 1
main = max(sizes, key=lambda c: sizes[c])
orphan_names = [n['name'] for n in nodes if comp[n['id']] != main and n['kind']=='artifact']

patterns = {
    'UserSID': [r'user[-_ ]?sid', r'subject[-_ ]?user[-_ ]?sid', r'target[-_ ]?sid', r'owner[-_ ]?sid', r'\bsid\b'],
    'LogonSessionId': [r'logon[-_ ]?id', r'session[-_ ]?id', r'luid', r'subject[-_ ]?logon'],
    'ProcessId': [r'process[-_ ]?id', r'^pid$', r'client[-_ ]?process[-_ ]?id'],
    'ExecutablePath': [r'image[-_ ]?path', r'new[-_ ]?process[-_ ]?name', r'process[-_ ]?name', r'driver[-_ ]?path', r'binary'],
    'MFTEntryReference': [r'mft[-_ ]?entry', r'file[-_ ]?reference', r'record[-_ ]?number'],
    'IPAddress': [r'ip[-_ ]?address', r'remote[-_ ]?ip', r'source[-_ ]?ip', r'dest[-_ ]?ip', r'remote[-_ ]?address'],
    'URL': [r'\burl\b', r'hostname', r'^host$', r'remote[-_ ]?host'],
    'MachineNetBIOS': [r'machine[-_ ]?name', r'computer[-_ ]?name', r'netbios'],
    'FilesystemVolumeSerial': [r'volume[-_ ]?serial', r'vol[-_ ]?serial', r'drive[-_ ]?serial'],
    'VolumeLabel': [r'volume[-_ ]?label'],
    'DeviceSerial': [r'device[-_ ]?serial', r'serial[-_ ]?number'],
    'TaskName': [r'task[-_ ]?name'],
    'ServiceName': [r'service[-_ ]?name'],
    'Location': [r'^path$', r'^location$', r'file[-_ ]?path', r'full[-_ ]?path'],
    'ExecutableHash': [r'hash', r'sha1', r'sha256', r'md5'],
    'FILETIME100ns': [r'time[-_ ]?created', r'filetime', r'timestamp'],
}

print(f'{len(orphan_names)} orphans total\n')
total_cands = 0
for name in orphan_names:
    matches = list(pathlib.Path('artifacts').glob(f'*/{name}.md'))
    if not matches: continue
    t = matches[0].read_text(encoding='utf-8')
    m = re.search(r'^---\n(.*?)\n---', t, re.DOTALL|re.MULTILINE)
    if not m: continue
    try: fm = yaml.safe_load(m.group(1))
    except: continue
    fields = fm.get('fields') or []
    field_names = []
    for f in fields:
        if isinstance(f, dict):
            fn = f.get('name', '')
            has_ref = bool(f.get('references-data'))
            field_names.append((fn, has_ref))
    cand = []
    for fn, has_ref in field_names:
        if has_ref: continue
        for concept, regs in patterns.items():
            if concept not in concepts: continue
            for r in regs:
                if re.search(r, fn, re.I):
                    cand.append((fn, concept))
                    break
    if cand:
        print(f'{name}: {len(field_names)} fields; candidates:')
        seen = set()
        for fn, c in cand:
            key = (fn, c)
            if key in seen: continue
            seen.add(key)
            print(f'  "{fn}" -> concept:{c}')
        total_cands += 1
    else:
        print(f'{name}: ({len(field_names)} fields, no obvious concept matches)')
print()
print(f'Orphans with concept-ref candidates: {total_cands}/{len(orphan_names)}')
