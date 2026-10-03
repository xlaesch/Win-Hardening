import zipfile, yaml, json, urllib.request, base64, re

ES = 'http://localhost:9200'
import os
PW = os.environ.get('ELASTIC_PASSWORD') or open('.env').read().split('ELASTIC_PASSWORD=')[1].splitlines()[0]
AUTH = base64.b64encode(f'elastic:{PW}'.encode()).decode()

def put(path, body):
    req = urllib.request.Request(f'{ES}{path}', data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json', 'Authorization': f'Basic {AUTH}'}, method='PUT')
    print('PUT', path, urllib.request.urlopen(req, timeout=30).status)

def render(obj, prefix, ds):
    """Replace {{ IngestPipeline "x" }} with <prefix>-<ds>_x everywhere."""
    s = json.dumps(obj)
    s = re.sub(r'\{\{\s*IngestPipeline\s*["\']([^"\']+)["\']\s*\}\}', lambda m: f'{prefix}-{ds}_{m.group(1)}', s)
    return json.loads(s)

jobs = [
    ('packages/system-3.0.0.zip', 'system-3.0.0', 'security', 'logs-system.security'),
    ('packages/windows-3.10.0.zip', 'windows-3.10.0', 'powershell', 'logs-windows.powershell'),
    ('packages/windows-3.10.0.zip', 'windows-3.10.0', 'powershell_operational', 'logs-windows.powershell_operational'),
    ('packages/windows-3.10.0.zip', 'windows-3.10.0', 'sysmon_operational', 'logs-windows.sysmon_operational'),
    ('packages/windows-3.10.0.zip', 'windows-3.10.0', 'windows_defender', 'logs-windows.defender'),
]
for zp, root, ds, prefix in jobs:
    z = zipfile.ZipFile(zp)
    base = f'{root}/data_stream/{ds}/elasticsearch/ingest_pipeline/'
    for n in sorted(z.namelist()):
        if not n.startswith(base) or not n.endswith('.yml'):
            continue
        stem = n[len(base):-4]
        raw = z.read(n).decode('utf-8')
        # Render on raw YAML: JSON-dumped mustache has escaped quotes that break the regex.
        raw = re.sub(r'\{\{\s*IngestPipeline\s*["\']([^"\']+)["\']\s*\}\}', lambda m: f'{prefix}-{ds}_{m.group(1)}', raw)
        docs = [d for d in yaml.safe_load_all(raw) if d and 'processors' in d]
        if not docs:
            continue
        doc = docs[0]
        names = [f'{prefix}-default'] if stem == 'default' else [f'{prefix}-{ds}_{stem}']
        for nm in names:
            put(f'/_ingest/pipeline/{nm}', doc)
