#!/usr/bin/env python3
import os, sys, json, gzip
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = os.environ.get('OPENSSF_OSV_DIR', 'openssf-cache/osv')
OUT = os.environ.get('OPENSSF_INDEX_OUT', 'openssf-index.json.gz')

# Minimal fields

def process_file(p):
    try:
        with open(p, 'r') as fh:
            d = json.load(fh)
        out = []
        for aff in d.get('affected', []):
            pkg = aff.get('package', {})
            eco = (pkg.get('ecosystem') or '').lower()
            name = (pkg.get('name') or '').lower()
            if not eco or not name:
                continue
            out.append((eco, name, {
                'id': d.get('id'),
                'summary': d.get('summary'),
                'versions': aff.get('versions') or [],
                'ranges': aff.get('ranges') or [],
            }))
        return out
    except Exception:
        return []

files = []
for root, _, fns in os.walk(BASE):
    for fn in fns:
        if fn.endswith('.json'):
            files.append(os.path.join(root, fn))

index = {}
workers = min(32, os.cpu_count() or 8)
with ThreadPoolExecutor(max_workers=workers) as ex:
    futs = [ex.submit(process_file, p) for p in files]
    for fut in as_completed(futs):
        for eco, name, entry in fut.result():
            eco_map = index.setdefault(eco, {})
            eco_map.setdefault(name, []).append(entry)

with gzip.open(OUT, 'wt') as gz:
    json.dump(index, gz)

print(f"Wrote index: {OUT} (ecosystems={len(index)})")
