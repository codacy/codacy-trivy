FROM golang:1.21-alpine as builder

WORKDIR /src

COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download
RUN go mod verify

COPY cmd cmd
COPY internal internal

RUN go build -o bin/codacy-trivy -ldflags="-s -w" ./cmd/tool

COPY docs docs

RUN go run ./cmd/docgen

FROM busybox

RUN adduser -u 2004 -D docker

COPY --from=builder --chown=docker:docker /src/bin /dist/bin
COPY --from=builder --chown=docker:docker /src/docs /docs 
COPY --chown=docker:docker cache/ /dist/cache/codacy-trivy

CMD [ "/dist/bin/codacy-trivy" ]
