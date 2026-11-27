#!/usr/bin/env bash
# Pin the fixture test databases to their current upstream versions by
# rewriting scripts/fixture-dbs.env. Afterwards, rebuild the fixtures image
# (scripts/build_fixture_image.sh) and regenerate the fixtures
# (scripts/regenerate_fixtures.py), and commit all of it together.
set -euo pipefail

cd "$(dirname "$0")/.."
env_file=scripts/fixture-dbs.env

token=$(curl -sf 'https://ghcr.io/token?scope=repository:aquasecurity/trivy-db:pull' |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["token"])')
digest=$(curl -sfI -H "Authorization: Bearer $token" \
  -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
  https://ghcr.io/v2/aquasecurity/trivy-db/manifests/2 |
  tr -d '\r' | awk 'tolower($1) == "docker-content-digest:" { print $2 }')
commit=$(curl -sf https://api.github.com/repos/ossf/malicious-packages/commits/main |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["sha"])')

[[ "$digest" == sha256:* ]] || { echo "Could not resolve the trivy-db digest" >&2; exit 1; }
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo "Could not resolve the OpenSSF commit" >&2; exit 1; }

sed -i.bak \
  -e "s|^TRIVY_DB_DIGEST=.*|TRIVY_DB_DIGEST=$digest|" \
  -e "s|^OPENSSF_MALICIOUS_PACKAGES_COMMIT=.*|OPENSSF_MALICIOUS_PACKAGES_COMMIT=$commit|" \
  "$env_file"
rm -f "$env_file.bak"

echo "TRIVY_DB_DIGEST=$digest"
echo "OPENSSF_MALICIOUS_PACKAGES_COMMIT=$commit"
