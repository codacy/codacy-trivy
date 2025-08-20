FROM golang:1.25-alpine as builder

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

# Generate the OpenSSF index during build
COPY scripts/ scripts/
COPY openssf-cache/ openssf-cache/
RUN apk add --no-cache python3 && \
    python3 scripts/build_openssf_index.py

FROM busybox

RUN adduser -u 2004 -D docker

COPY --from=builder --chown=docker:docker /src/bin /dist/bin
COPY --from=builder --chown=docker:docker /src/docs /docs 
COPY --from=builder --chown=docker:docker /src/openssf-index.json.gz /dist/cache/openssf-index.json.gz
COPY --chown=docker:docker cache/ /dist/cache/codacy-trivy

USER docker

CMD [ "/dist/bin/codacy-trivy" ]
