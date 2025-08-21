#!/usr/bin/env bash
set -euo pipefail
ROOT="/Users/kendrickcurtis/Documents/GitHub/codacy-trivy"
BASE="$ROOT/openssf-cache/osv"
TEST_DIR="/Users/kendrickcurtis/Documents/GitHub/trivy-test-malware-npm"

if [ ! -d "$BASE" ]; then
  echo "ERROR: OpenSSF cache not found at $BASE" 1>&2
  exit 1
fi

read -r NAME VERSION < <(python3 - <<'PY'
import json, os, re, sys
base = '/Users/kendrickcurtis/Documents/GitHub/codacy-trivy/openssf-cache/osv'
semver_re = re.compile(r'^\d+\.\d+\.\d+(?:[-+].*)?$')

def pick_version(aff):
    vs = aff.get('versions') or []
    for v in vs:
        if v and v not in ('0','0.0.0'):
            return v
    for rng in aff.get('ranges') or []:
        for ev in rng.get('events', []):
            v = (ev.get('introduced') or '').lstrip('v')
            if v and v not in ('0','0.0.0'):
                return v
    return None

for root,_,files in os.walk(base):
    for fn in files:
        if not fn.endswith('.json'):
            continue
        p = os.path.join(root, fn)
        try:
            d = json.load(open(p))
        except Exception:
            continue
        for aff in d.get('affected', []):
            pkg = aff.get('package', {})
            if (pkg.get('ecosystem') or '').lower() != 'npm':
                continue
            name = pkg.get('name')
            if not name:
                continue
            ver = pick_version(aff)
            if ver:
                print(name, ver)
                sys.exit(0)
# fallback if none found
print('sdge-it-tdg-dynamicloadprofiles','1.0.1')
PY
)

echo "Selected npm package: ${NAME}@${VERSION}"
rm -rf "$TEST_DIR" && mkdir -p "$TEST_DIR"
cat > "$TEST_DIR/package.json" <<JSON
{
  "name": "trivy-test-malware-npm",
  "version": "1.0.0",
  "private": true,
  "dependencies": { "${NAME}": "${VERSION}" }
}
JSON

echo "Created: $TEST_DIR/package.json"
cat "$TEST_DIR/package.json"
