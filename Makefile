# Build and test require Go 1.25+ and GOEXPERIMENT=jsonv2 (for Trivy).
# CGO_ENABLED=0 avoids linking system libs (e.g. faiss on macOS).
export GOEXPERIMENT := jsonv2
export GOTOOLCHAIN := auto
export CGO_ENABLED := 0

.PHONY: build test
build:
	go build -o bin/codacy-trivy -ldflags="-s -w" ./cmd/tool

test:
	go test ./...
