#!/usr/bin/env bash
set -euo pipefail

# CONFIG
BASE_DIR="${BASE_DIR:-/Users/kendrickcurtis/Documents/GitHub}"
ITERATIONS="${1:-1}"
BRANCH_IMAGE="${BRANCH_IMAGE:-codacy-trivy:branch}"
MASTER_IMAGE="${MASTER_IMAGE:-codacy-trivy:master}"
EXCLUDE_PATTERN="${EXCLUDE_PATTERN:-^$}"   # regex of repo basenames to skip

# Utilities
timestamp_ms() { perl -MTime::HiRes=time -e 'printf("%.0f\n", time()*1000)'; }

to_bytes() {
  local v="$1"
  v="${v//,/}"
  # shellcheck disable=SC2206
  local parts=($v)
  local num="${parts[0]}"
  local unit="${parts[1]:-B}"
  case "$unit" in
    B|Bytes|byte|bytes|"" ) awk -v n="$num" 'BEGIN{printf("%.0f", n)}' ;;
    kB|KB|KiB )               awk -v n="$num" 'BEGIN{printf("%.0f", n*1024)}' ;;
    MB|MiB )                  awk -v n="$num" 'BEGIN{printf("%.0f", n*1024*1024)}' ;;
    GB|GiB )                  awk -v n="$num" 'BEGIN{printf("%.0f", n*1024*1024*1024)}' ;;
    TB|TiB )                  awk -v n="$num" 'BEGIN{printf("%.0f", n*1024*1024*1024*1024)}' ;;
    * )                       echo 0 ;;
  esac
}

prefetch_trivy_cache_here() {
  # in current directory
  if [ ! -d cache/db ]; then
    echo "[prefetch] Installing Trivy and downloading DB into ./cache ..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b . v0.65.0
    mkdir -p cache
    ./trivy --cache-dir ./cache image --download-db-only >/dev/null
  fi
}

# After building BRANCH, also ensure a prebuilt index exists in workspace for branch image builds
build_branch_image() {
  echo "[build] Building branch image: $BRANCH_IMAGE"
  prefetch_trivy_cache_here
  # Generate prebuilt index (optional if present already)
  python3 scripts/build_openssf_index.py || true
  docker build -t "$BRANCH_IMAGE" --build-arg TRIVY_VERSION=0.65.0 .
}

build_master_image() {
  echo "[build] Building master image: $MASTER_IMAGE"
  local tmp
  tmp="$(mktemp -d)"
  if git rev-parse --verify --quiet origin/master >/dev/null; then
    git worktree add -f "$tmp/wt-master" origin/master >/dev/null 2>&1 || true
  else
    git worktree add -f "$tmp/wt-master" master >/dev/null 2>&1 || true
  fi
  (
    cd "$tmp/wt-master"
    prefetch_trivy_cache_here
    docker build -t "$MASTER_IMAGE" --build-arg TRIVY_VERSION=0.65.0 .
  )
  git worktree remove -f "$tmp/wt-master" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}

make_codacyrc_for_repo() {
  local repo="$1" out="$2"
  local files=()
  while IFS= read -r line; do
    # strip leading ./
    line="${line#./}"
    files+=("$line")
  done < <(cd "$repo" && \
    find . -type f \( \
      -name go.mod -o \
      -name 'package.json' -o -name 'package-lock.json' -o -name yarn.lock -o \
      -name requirements.txt -o -name Pipfile -o -name Pipfile.lock -o \
      -name composer.lock -o -name Gemfile.lock -o -name Cargo.lock -o \
      -name pom.xml -o -name 'build.sbt.lock' -o \
      -name gradle.lockfile -o -name Package.resolved -o -name Package.swift \
    \) )

  if [ "${#files[@]}" -eq 0 ]; then
    files=("go.mod")
  fi

  {
    echo '{'
    echo '  "files": ['
    local first=1
    for f in "${files[@]}"; do
      if [ $first -eq 1 ]; then first=0; else echo ','; fi
      printf '    "%s"' "$f"
    done
    echo
    echo '  ],'
    echo '  "tools": ['
    echo '    { "name": "trivy", "patterns": ['
    echo '        { "patternId": "vulnerability_high" }'
    echo '      ] }'
    echo '  ]'
    echo '}'
  } > "$out"
}

run_one() {
  local image="$1" repo="$2" cfg="$3"
  local name="bench_$(echo "$image" | tr ':/@' '_')_$(basename "$repo")_$$"
  local start end ms max_bytes=0 mem_line curr bytes

  start="$(timestamp_ms)"
  docker run -d --name "$name" -v "$repo:/src" -v "$cfg:/.codacyrc:ro" "$image" >/dev/null

  while docker ps -q --filter "name=$name" >/dev/null 2>&1 && [ -n "$(docker ps -q --filter "name=$name")" ]; do
    mem_line="$(docker stats --no-stream --format '{{.MemUsage}}' "$name" 2>/dev/null | head -1)"
    curr="$(echo "$mem_line" | awk -F'/' '{print $1}' | xargs)"
    if [ -n "$curr" ]; then
      bytes="$(to_bytes "$curr")"
      if [ "$bytes" -gt "$max_bytes" ]; then max_bytes="$bytes"; fi
    fi
    sleep 0.5
  done

  docker wait "$name" >/dev/null 2>&1 || true
  end="$(timestamp_ms)"
  ms=$(( end - start ))
  docker rm -f "$name" >/dev/null 2>&1 || true

  echo "$ms,$max_bytes"
}

bench_repo_image() {
  local image="$1" repo="$2" iter="$3"
  local cfg
  cfg="$(mktemp)"
  make_codacyrc_for_repo "$repo" "$cfg"

  local i ms bytes total=0 min=999999999 max=0 max_mem=0
  for ((i=1; i<=iter; i++)); do
    read -r ms bytes < <(run_one "$image" "$repo" "$cfg")
    total=$(( total + ms ))
    (( ms < min )) && min="$ms"
    (( ms > max )) && max="$ms"
    (( bytes > max_mem )) && max_mem="$bytes"
    echo "  [$image] $(basename "$repo") run $i: ${ms}ms, peak_mem=${bytes}B"
  done
  rm -f "$cfg"
  local avg=$(( total / iter ))
  echo "$avg,$min,$max,$max_mem"
}

main() {
  docker info >/dev/null || { echo "Docker not running"; exit 1; }

  build_branch_image
  build_master_image

  echo "repo,image,avg_ms,min_ms,max_ms,peak_mem_bytes" | tee bench_results.csv

  local count=0
  for repo in "$BASE_DIR"/*; do
    [ -d "$repo" ] || continue
    base="$(basename "$repo")"
    [[ "$base" =~ $EXCLUDE_PATTERN ]] && { echo "[skip] $base"; continue; }

    # Only process first 10 repositories
    ((count++))
    if [ $count -gt 10 ]; then
      echo "[limit] Reached 10 repositories limit, stopping"
      break
    fi

    echo "[bench] Repo: $base (N=$ITERATIONS) [$count/10]"

    read -r avg min max peak < <(bench_repo_image "$MASTER_IMAGE" "$repo" "$ITERATIONS")
    echo "$base,master,$avg,$min,$max,$peak" | tee -a bench_results.csv

    read -r avg min max peak < <(bench_repo_image "$BRANCH_IMAGE" "$repo" "$ITERATIONS")
    echo "$base,branch-base,$avg,$min,$max,$peak" | tee -a bench_results.csv

    cfg2="$(mktemp)"
    make_codacyrc_for_repo "$repo" "$cfg2"
    python3 - "$cfg2" <<'PY'
import json,sys
p=sys.argv[1]
with open(p) as f:
    d=json.load(f)
for t in d.get('tools', []):
    if t.get('name')=='trivy':
        pats=t.setdefault('patterns', [])
        pats.insert(0,{"patternId":"malicious_packages"})
with open(p,'w') as f:
    json.dump(d,f)
PY
    read -r ms bytes < <(run_one "$BRANCH_IMAGE" "$repo" "$cfg2")
    echo "$base,branch-malicious,$ms,$ms,$ms,$bytes" | tee -a bench_results.csv
    rm -f "$cfg2"
  done

  echo "Done. Results in bench_results.csv"
}

main "$@"
