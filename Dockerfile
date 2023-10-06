FROM golang:1.21-alpine as builder

WORKDIR /src

COPY go.mod .
COPY go.sum .
RUN go mod download
RUN go mod verify

COPY cmd/ cmd/
COPY docs/ docs/

RUN go build -o bin/codacy-trivy -ldflags="-s -w" cmd/tool/main.go
RUN go run cmd/docgen/main.go

COPY docs/ /docs/

RUN adduser -u 2004 -D docker
RUN chown -R docker:docker /docs

FROM busybox

COPY --from=builder /src/bin /dist/bin
COPY --from=builder /docs /docs
COPY --from=builder /etc/passwd /etc/passwd

CMD [ "/dist/bin/codacy-trivy" ]
