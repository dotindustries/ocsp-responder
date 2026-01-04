.PHONY: build test clean docker podman release snapshot lint help

# Variables
BINARY_NAME=ocsp-responder
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Default target
all: build

## build: Build the binary
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) .

## test: Run tests
test:
	go test -v -race -cover ./...

## test-coverage: Run tests with coverage report
test-coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## lint: Run linter
lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

## clean: Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html

## podman: Build container image with Podman (recommended)
podman:
	podman build -t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest .

## podman-run: Run Podman container (requires certs mounted)
podman-run:
	@echo "Usage: podman run -v /path/to/certs:/certs:Z $(BINARY_NAME):latest -issuer /certs/ca.pem -responder /certs/ocsp.pem -key /certs/ocsp-key.pem"

## docker: Build Docker image (use 'make podman' for better caching)
docker:
	docker build -t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest .

## docker-run: Run Docker container (requires certs mounted)
docker-run:
	@echo "Usage: docker run -v /path/to/certs:/certs $(BINARY_NAME):latest -issuer /certs/ca.pem -responder /certs/ocsp.pem -key /certs/ocsp-key.pem"

## snapshot: Create a snapshot release (for testing)
snapshot:
	@which goreleaser > /dev/null || (echo "Installing goreleaser..." && go install github.com/goreleaser/goreleaser@latest)
	goreleaser release --snapshot --clean

## release: Create a release (requires GITHUB_TOKEN)
release:
	@which goreleaser > /dev/null || (echo "Installing goreleaser..." && go install github.com/goreleaser/goreleaser@latest)
	goreleaser release --clean

## release-dry-run: Test release process without publishing
release-dry-run:
	@which goreleaser > /dev/null || (echo "Installing goreleaser..." && go install github.com/goreleaser/goreleaser@latest)
	goreleaser release --snapshot --skip=publish --clean

## install: Install binary to GOPATH/bin
install:
	go install $(LDFLAGS) .

## mod-tidy: Tidy go modules
mod-tidy:
	go mod tidy

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed 's/^/ /'
