#!/bin/bash
# Build the codacy-trivy binary, suppressing FAISS linker warnings
set -e

export CGO_LDFLAGS="-L/opt/homebrew/Cellar/faiss/1.10.0/lib -lfaiss"
export CGO_CFLAGS="-I/opt/homebrew/Cellar/faiss/1.10.0/include"

GOTOOLCHAIN=auto go build -o codacy-trivy cmd/tool/main.go 2> >(grep -v 'ld: warning: ignoring file .*/faiss/.*' >&2)

echo "Build successful! Binary created: codacy-trivy"
