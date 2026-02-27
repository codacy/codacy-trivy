FROM golang:1.25-alpine AS builder

ARG TRIVY_VERSION=dev
ENV TRIVY_VERSION=$TRIVY_VERSION

WORKDIR /src

COPY go.mod go.mod
COPY go.sum go.sum

RUN go env -w GOEXPERIMENT=jsonv2
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
RUN go mod verify

COPY cmd cmd
COPY internal internal

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
    go build -o bin/codacy-trivy -ldflags="-s -w" ./cmd/tool

COPY docs docs

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
    go run ./cmd/docgen

# Download xeol EOL DB at build time (offline at runtime). Listing serves .tar.xz URLs.
RUN apk add --no-cache curl jq xz && \
    XEOL_DB_URL=$(curl -sSfL https://data.xeol.io/xeol/databases/listing.json | jq -r '.available["1"] | .[-1] | .url') && \
    curl -sSfL "$XEOL_DB_URL" -o /tmp/xeol-db.tar.xz && \
    mkdir -p /src/xeol-db/1 && tar -xJf /tmp/xeol-db.tar.xz -C /src/xeol-db/1 && \
    rm /tmp/xeol-db.tar.xz

# Download Trivy vuln DB at build time so slim image can run EOL scan (runner still needs DB to init).
RUN ORAS_VER=1.1.0 && \
    curl -sSfL "https://github.com/oras-project/oras/releases/download/v${ORAS_VER}/oras_${ORAS_VER}_linux_amd64.tar.gz" -o /tmp/oras.tar.gz && \
    tar -xzf /tmp/oras.tar.gz -C /usr/local/bin oras && rm /tmp/oras.tar.gz && \
    mkdir -p /src/trivy-cache/db && cd /src/trivy-cache/db && \
    oras pull ghcr.io/aquasecurity/trivy-db:2 && \
    (test -f db.tar.gz && tar -xzf db.tar.gz && rm -f db.tar.gz) && \
    (mv 2/* . 2>/dev/null; rmdir 2 2>/dev/null) || true

# Build eoltest for container verification (optional).
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
    go build -o bin/eoltest ./cmd/eoltest

FROM busybox AS full
RUN adduser -u 2004 -D docker
COPY --from=builder --chown=docker:docker /src/bin /dist/bin
COPY --from=builder --chown=docker:docker /src/docs /docs
COPY --chown=docker:docker cache/ /dist/cache/codacy-trivy
COPY --chown=docker:docker openssf-malicious-packages/openssf-malicious-packages-index.json.gz /dist/cache/codacy-trivy/openssf-malicious-packages-index.json.gz
COPY --from=builder --chown=docker:docker /src/xeol-db /dist/cache/xeol/db
ENV XEOL_DB_CACHE_DIR=/dist/cache/xeol/db
CMD [ "/dist/bin/codacy-trivy" ]

# Slim: no host cache/openssf; includes Trivy DB + xeol DB for EOL scan. Use: docker build --target slim -t codacy-trivy:eol .
FROM busybox AS slim
RUN adduser -u 2004 -D docker
COPY --from=builder --chown=docker:docker /src/bin /dist/bin
COPY --from=builder --chown=docker:docker /src/docs /docs
RUN mkdir -p /dist/cache/codacy-trivy
COPY --from=builder --chown=docker:docker /src/trivy-cache/db /dist/cache/codacy-trivy/db
COPY --from=builder --chown=docker:docker /src/xeol-db /dist/cache/xeol/db
ENV XEOL_DB_CACHE_DIR=/dist/cache/xeol/db
CMD [ "/dist/bin/codacy-trivy" ]

FROM full
