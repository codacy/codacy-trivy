FROM golang:1.21-alpine as builder

WORKDIR /src

COPY go.mod .
COPY go.sum .
RUN go mod download && go mod verify

COPY cmd/ cmd/
RUN go build -o bin/codacy-trivy -ldflags="-s -w" ./cmd/tool/main.go

COPY docs/ docs/
RUN go run cmd/docgen/main.go

COPY docs/ /docs/
# Copy trivy DB files
COPY cache/db/trivy.db /dist/cache/codacy-trivy/db/
COPY cache/db/metadata.json /dist/cache/codacy-trivy/db/
COPY cache/java-db/trivy-java.db /dist/cache/codacy-trivy/java-db/
COPY cache/java-db/metadata.json /dist/cache/codacy-trivy/java-db/

RUN adduser -u 2004 -D docker
RUN chown -R docker:docker /docs
RUN chown -R docker:docker /dist/cache/codacy-trivy

FROM busybox

COPY --from=builder /src/bin /dist/bin

COPY --from=builder /docs /docs
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /dist/cache/codacy-trivy /dist/cache/codacy-trivy

CMD [ "/dist/bin/codacy-trivy" ]
