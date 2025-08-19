#!/usr/bin/env python3
import os, json, gzip
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = os.environ.get('OPENSSF_OSV_DIR', 'openssf-cache/osv')
OUT = os.environ.get('OPENSSF_INDEX_OUT', 'openssf-index.json.gz')

# Minimal fields

def read_json_file(path):
    with open(path, 'r', encoding='utf-8') as fh:
        return json.load(fh)


def extract_entries(doc):
    entries = []
    for aff in doc.get('affected', []):
        pkg = aff.get('package', {})
        eco = (pkg.get('ecosystem') or '').lower()
        name = (pkg.get('name') or '').lower()
        if eco and name:
            entries.append((eco, name, {
                'id': doc.get('id'),
                'summary': doc.get('summary'),
                'versions': aff.get('versions') or [],
                'ranges': aff.get('ranges') or [],
            }))
    return entries


def process_file(path):
    try:
        doc = read_json_file(path)
        return extract_entries(doc)
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

with gzip.open(OUT, 'wt', encoding='utf-8') as gz:
    json.dump(index, gz)

print(f"Wrote index: {OUT} (ecosystems={len(index)})")
