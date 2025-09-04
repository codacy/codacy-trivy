FROM golang:1.24-alpine as builder

ARG TRIVY_VERSION=dev
ENV TRIVY_VERSION=$TRIVY_VERSION

WORKDIR /src

COPY go.mod go.mod
COPY go.sum go.sum

RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
RUN go mod verify

COPY cmd cmd
COPY internal internal

# Install C compiler and development tools for CGO
RUN apk add --no-cache build-base
RUN apk add --no-cache binutils

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=1 CC=gcc CXX=g++ go build -o bin/codacy-trivy -ldflags="-s -w" ./cmd/tool

COPY docs docs

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
    go run ./cmd/docgen

# Generate the OpenSSF index during build
COPY scripts/ scripts/
COPY openssf-cache/osv/ openssf-cache/osv/
RUN apk add --no-cache python3 curl sqlite sqlite-dev && \
    python3 scripts/build_openssf_index.py

# Download latest xeol database during build
RUN mkdir -p /dist/cache/xeol && \
    XEOL_DB_URL=$(curl -s https://data.xeol.io/xeol/databases/listing.json | \
        python3 -c "import sys, json; data=json.load(sys.stdin); print(data['available']['1'][-1]['url'])") && \
    curl -sL "$XEOL_DB_URL" | tar -xJ -C /dist/cache/xeol

FROM busybox

RUN adduser -u 2004 -D docker

COPY --from=builder --chown=docker:docker /src/bin /dist/bin
COPY --from=builder --chown=docker:docker /src/docs /docs 
COPY --from=builder --chown=docker:docker /src/openssf-index.json.gz /dist/cache/openssf-index.json.gz
COPY --from=builder --chown=docker:docker /dist/cache/xeol /dist/cache/xeol
COPY --chown=docker:docker cache/ /dist/cache/codacy-trivy

USER docker

CMD [ "/dist/bin/codacy-trivy" ]
