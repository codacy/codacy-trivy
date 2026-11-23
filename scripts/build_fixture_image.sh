#!/usr/bin/env bash
# Build codacy-trivy:fixtures, the image the docs/multiple-tests fixtures are
# generated and tested against. It is the normal image, with the databases
# pinned in scripts/fixture-dbs.env instead of the latest ones.
#
# Uses ./trivy when present (as in CI); otherwise runs Trivy from its Docker image.
#
# Usage: scripts/build_fixture_image.sh [TRIVY_VERSION]
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=fixture-dbs.env
source scripts/fixture-dbs.env

trivy_version=${1:-$(sed -n 's/.*github.com\/aquasecurity\/trivy v\([0-9.]*\).*/\1/p' go.mod)}
db_dir=cache-fixtures
openssf_dir=openssf-fixtures

rm -rf "$db_dir" "$openssf_dir"
mkdir -p "$db_dir" "$openssf_dir"

echo "Downloading trivy-db@$TRIVY_DB_DIGEST"
db_ref="ghcr.io/aquasecurity/trivy-db@$TRIVY_DB_DIGEST"
if [[ -x ./trivy ]]; then
  ./trivy --cache-dir "$db_dir" image --download-db-only --db-repository "$db_ref"
else
  docker run --rm -v "$PWD/$db_dir:/cache" "aquasec/trivy:$trivy_version" \
    --cache-dir /cache image --download-db-only --db-repository "$db_ref"
fi

echo "Building the OpenSSF malicious packages index at $OPENSSF_MALICIOUS_PACKAGES_COMMIT"
curl -sfL "https://api.github.com/repos/ossf/malicious-packages/tarball/$OPENSSF_MALICIOUS_PACKAGES_COMMIT" |
  tar -xz --strip-components=1 -C "$openssf_dir"
OPENSSF_OSV_MALICIOUS_DIR="$openssf_dir/osv/malicious" \
  OPENSSF_INDEX_OUT="$openssf_dir/openssf-malicious-packages-index.json.gz" \
  python3 scripts/build_openssf_index.py

docker build -t codacy-trivy:fixtures \
  --build-arg TRIVY_VERSION="$trivy_version" \
  --build-arg DB_CACHE_DIR="$db_dir" \
  --build-arg MALICIOUS_PACKAGES_INDEX="$openssf_dir/openssf-malicious-packages-index.json.gz" \
  .
