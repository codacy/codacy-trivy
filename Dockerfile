FROM golang:1.22-alpine as builder

WORKDIR /src

COPY go.mod go.mod
COPY go.sum go.sum

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
COPY --chown=docker:docker cache/ /dist/cache/codacy-trivy

CMD [ "/dist/bin/codacy-trivy" ]
