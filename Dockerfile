FROM golang:1.21-alpine as builder

WORKDIR /src

COPY . .
RUN go mod download
RUN go mod verify

RUN go build -o bin/codacy-trivy -ldflags="-s -w" ./cmd/tool
RUN go run ./cmd/docgen

FROM busybox

RUN adduser -u 2004 -D docker

COPY --from=builder /src/bin /dist/bin
COPY --from=builder /src/docs /docs 
COPY --chown=docker:docker /docs /docs/
COPY --from=builder /src/cache/ /dist/cache/codacy-trivy

CMD [ "/dist/bin/codacy-trivy" ]
