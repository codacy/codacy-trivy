FROM golang:1.21-alpine as builder

WORKDIR /src

COPY . .
RUN go mod download
RUN go mod verify

RUN go build -o bin/codacy-trivy -ldflags="-s -w" ./cmd/tool
RUN go run ./cmd/docgen

COPY docs/ /docs/

RUN adduser -u 2004 -D docker
RUN chown -R docker:docker /docs

FROM busybox

COPY --from=builder /src/bin /dist/bin
COPY --from=builder /docs /docs
COPY --from=builder /etc/passwd /etc/passwd

CMD [ "/dist/bin/codacy-trivy" ]
