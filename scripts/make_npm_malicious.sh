#!/usr/bin/env bash
set -euo pipefail
ROOT="/Users/kendrickcurtis/Documents/GitHub/codacy-trivy"
BASE="$ROOT/openssf-cache/osv"
TEST_DIR="/Users/kendrickcurtis/Documents/GitHub/trivy-test-malware-npm"

if [ ! -d "$BASE" ]; then
  echo "ERROR: OpenSSF cache not found at $BASE" 1>&2
  echo "Run the OpenSSF DB download step first (see README)." 1>&2
  exit 1
fi

# Pick a malicious npm package (name and version) from OSV entries
read -r NAME VERSION < <(python3 - <<'PY'
import json, os, sys
base = '/Users/kendrickcurtis/Documents/GitHub/codacy-trivy/openssf-cache/osv'
for root, _, files in os.walk(base):
    for fn in files:
        if not fn.endswith('.json'):
            continue
        p = os.path.join(root, fn)
        try:
            with open(p, 'r') as fh:
                d = json.load(fh)
        except Exception:
            continue
        for aff in d.get('affected', []):
            pkg = aff.get('package', {})
            if (pkg.get('ecosystem') or '').lower() == 'npm':
                name = pkg.get('name') or ''
                vers = None
                vs = aff.get('versions')
                if isinstance(vs, list) and vs:
                    vers = vs[0]
                else:
                    rng = aff.get('ranges') or []
                    if rng and rng[0].get('events'):
                        ev = rng[0]['events'][0]
                        vers = (ev.get('introduced') or '').lstrip('v') or '0'
                if name:
                    print(name, vers or '0')
                    sys.exit(0)
# Fallback example if none found
print('sdge-it-tdg-dynamicloadprofiles', '1.0.1')
PY
)

echo "Selected npm package: ${NAME}@${VERSION}"

# Create test project and package.json
rm -rf "$TEST_DIR" && mkdir -p "$TEST_DIR"
cat > "$TEST_DIR/package.json" <<JSON
{
  "name": "trivy-test-malware-npm",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "${NAME}": "${VERSION}"
  }
}
JSON

echo "Created: $TEST_DIR/package.json"
cat "$TEST_DIR/package.json"
