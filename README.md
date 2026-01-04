# OCSP Responder

A lightweight, RFC 6960 compliant OCSP responder written in Go. Designed for use with Azure Gateway and compatible with any CA that provides CRL endpoints (including Smallstep step-ca).

## Features

- Fully RFC-6960 compliant OCSP responses
- HTTP GET and POST request support
- Nonce extension support (optional, doesn't break caching)
- **Load certificates from URLs or files** - Fetch issuer cert from PKI endpoints
- Multiple certificate status sources:
  - **URLSource** - Fetch CRL from HTTP(S) endpoints
  - **FileSource** - Read CRL from local files
  - **InMemorySource** - Programmatic status management
- Automatic CRL refresh with configurable intervals
- Health check endpoint for load balancers

## Installation

### From Source

```bash
go install github.com/dot-inc/ocsp-responder@latest
```

Or clone and build:

```bash
git clone https://github.com/dot-inc/ocsp-responder.git
cd ocsp-responder
make build
```

### Container Image

```bash
# Pull from GitHub Container Registry
podman pull ghcr.io/dot-inc/ocsp-responder:latest
# or with Docker
docker pull ghcr.io/dot-inc/ocsp-responder:latest
```

Or build locally (Podman recommended for better caching):

```bash
make podman
# or with Docker
make docker
```

## Usage

### Basic Mode (all certificates return "good")

```bash
./ocsp-responder \
  -issuer ca.pem \
  -responder ocsp.pem \
  -key ocsp-key.pem
```

### With CRL from URL (e.g., step-ca)

```bash
./ocsp-responder \
  -issuer ca.pem \
  -responder ocsp.pem \
  -key ocsp-key.pem \
  -crl-url https://ca.example.com/crl \
  -crl-refresh 5m
```

### With Local CRL File

```bash
./ocsp-responder \
  -issuer ca.pem \
  -responder ocsp.pem \
  -key ocsp-key.pem \
  -crl-file /path/to/crl.der \
  -crl-refresh 5m
```

### Fetch Certificates from URL

The `-issuer` and `-responder` flags accept both file paths and HTTP(S) URLs. This is useful when your certificates are published at a known PKI endpoint:

```bash
# Fetch issuer cert from URL, key from local file
./ocsp-responder \
  -issuer https://pki.example.com/intermediate_ca.crt \
  -responder https://pki.example.com/intermediate_ca.crt \
  -key /certs/intermediate_ca_key \
  -crl-url https://ca.example.com/crl

# Skip TLS verification (testing only!)
./ocsp-responder \
  -issuer https://pki.staging.example.com/ca.crt \
  -responder https://pki.staging.example.com/ca.crt \
  -key /certs/ocsp.key \
  -insecure-skip-verify
```

> **Note**: The `-key` flag only accepts file paths (not URLs) for security reasons. Private keys should not be fetched over the network.

### Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8080` | Address to listen on |
| `-issuer` | (required) | Path or URL to issuer certificate (PEM) |
| `-responder` | (required) | Path or URL to responder certificate (PEM) |
| `-key` | (required) | Path to responder private key file (PEM) |
| `-interval` | `24h` | OCSP response validity interval |
| `-crl-url` | | URL to fetch CRL from |
| `-crl-file` | | Path to local CRL file |
| `-crl-refresh` | `5m` | CRL refresh interval |
| `-ca-cert` | | Path or URL to CA certificate for TLS verification (CRL URL) |
| `-insecure-skip-verify` | `false` | Skip TLS verification (testing only) |

## Certificate Status Sources

The responder supports three types of certificate status sources:

### URLSource

Fetches CRL from an HTTP(S) endpoint and caches it locally. Automatically refreshes at the configured interval.

```go
source, err := ocsp.NewURLSource(ocsp.URLSourceConfig{
    URL:                "https://ca.example.com/crl",
    RefreshInterval:    5 * time.Minute,
    Timeout:            30 * time.Second,
    RootCAs:            certPool,        // optional
    InsecureSkipVerify: false,           // optional
})
if err != nil {
    log.Fatal(err)
}
defer source.Close()
```

### FileSource

Reads CRL from a local file and watches for changes. Useful when the CRL is synced via other means.

```go
source, err := ocsp.NewFileSource(ocsp.FileSourceConfig{
    Path:            "/path/to/crl.der",
    RefreshInterval: 5 * time.Minute,
})
if err != nil {
    log.Fatal(err)
}
defer source.Close()
```

### InMemorySource

Programmatically manage certificate status. Useful for testing or custom integrations.

```go
source := ocsp.NewInMemorySource()

// Mark a certificate as revoked
source.SetStatus(serialNumber, &ocsp.CertStatus{
    Status:    "revoked",
    RevokedAt: time.Now(),
    Reason:    ocsp.KeyCompromise,
})
```

## API Endpoints

### OCSP Endpoint

- **POST /** - Submit OCSP request in body
- **GET /{base64-encoded-request}** - Submit URL-encoded OCSP request

### Health Check

- **GET /health** - Returns JSON health status with CRL statistics

```json
{
  "status": "healthy",
  "crl": {
    "revoked_count": 5,
    "last_update": "2024-01-15T10:30:00Z",
    "next_update": "2024-01-16T10:30:00Z"
  }
}
```

## Integration with Smallstep step-ca

To use with [step-ca](https://smallstep.com/docs/step-ca), point the `-crl-url` to your step-ca CRL endpoint:

```bash
./ocsp-responder \
  -issuer /path/to/step-ca/certs/root_ca.crt \
  -responder /path/to/ocsp-responder.crt \
  -key /path/to/ocsp-responder.key \
  -crl-url https://your-step-ca:9000/crl
```

Or fetch the issuer certificate directly from your PKI URL:

```bash
./ocsp-responder \
  -issuer https://pki.example.com/intermediate_ca.crt \
  -responder /path/to/ocsp-responder.crt \
  -key /path/to/ocsp-responder.key \
  -crl-url https://your-step-ca:9000/crl \
  -insecure-skip-verify
```

Make sure CRL is enabled in your step-ca configuration (`ca.json`):

```json
{
  "crl": {
    "enabled": true
  }
}
```

## Container Usage

Run with Podman (recommended):

```bash
podman run -p 8080:8080 \
  -v /path/to/certs:/certs:ro,Z \
  ghcr.io/dot-inc/ocsp-responder:latest \
  -issuer /certs/ca.pem \
  -responder /certs/ocsp.pem \
  -key /certs/ocsp-key.pem \
  -crl-url https://ca.example.com/crl
```

Or with Docker:

```bash
docker run -p 8080:8080 \
  -v /path/to/certs:/certs:ro \
  ghcr.io/dot-inc/ocsp-responder:latest \
  -issuer /certs/ca.pem \
  -responder /certs/ocsp.pem \
  -key /certs/ocsp-key.pem \
  -crl-url https://ca.example.com/crl
```

## Development

### Prerequisites

- Go 1.24+
- Podman or Docker (optional, for container builds)
- [goreleaser](https://goreleaser.com/) (for releases)

### Common Commands

```bash
# Build binary
make build

# Run tests
make test

# Run tests with coverage report
make test-coverage

# Run linter
make lint

# Build container image (Podman - recommended)
make podman

# Build container image (Docker)
make docker

# Test release process (no publish)
make release-dry-run

# Show all available commands
make help
```

### Creating a Release

Releases are automated via GitHub Actions. To create a release:

1. Tag the commit:
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

2. GitHub Actions will automatically:
   - Build binaries for Linux, macOS, and Windows (amd64/arm64)
   - Create GitHub release with artifacts
   - Build and push container image to GitHub Container Registry (using Podman)

For local testing:

```bash
make snapshot  # Creates snapshot release in dist/
```

## License

MIT
