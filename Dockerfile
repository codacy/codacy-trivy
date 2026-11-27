FROM golang:1.26-alpine AS builder

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

FROM busybox

RUN adduser -u 2004 -D docker

COPY --from=builder --chown=docker:docker /src/bin /dist/bin
COPY --from=builder --chown=docker:docker /src/docs /docs 
# Overridden only for the fixture test image (scripts/build_fixture_image.sh).
ARG DB_CACHE_DIR=cache
ARG MALICIOUS_PACKAGES_INDEX=openssf-malicious-packages/openssf-malicious-packages-index.json.gz
COPY --chown=docker:docker ${DB_CACHE_DIR}/ /dist/cache/codacy-trivy
COPY --chown=docker:docker ${MALICIOUS_PACKAGES_INDEX} /dist/cache/codacy-trivy/openssf-malicious-packages-index.json.gz

CMD [ "/dist/bin/codacy-trivy" ]
