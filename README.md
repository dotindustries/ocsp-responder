# OCSP Responder

A lightweight, RFC 6960 compliant OCSP responder written in Go. Designed for use with Azure Gateway and compatible with any CA that provides CRL endpoints (including Smallstep step-ca).

## Features

- fully RFC-6960 compliant OCSP responses
- HTTP GET and POST request support
- Nonce extension support (optional, doesn't break caching)
- Multiple certificate status sources:
  - **URLSource** - Fetch CRL from HTTP(S) endpoints
  - **FileSource** - Read CRL from local files
  - **InMemorySource** - Programmatic status management
- Automatic CRL refresh with configurable intervals
- Health check endpoint for load balancers

## Installation

```bash
go install github.com/dot-inc/ocsp-responder@latest
```

Or build from source:

```bash
go build -o ocsp-responder .
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

### Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8080` | Address to listen on |
| `-issuer` | (required) | Path to issuer certificate (PEM) |
| `-responder` | (required) | Path to responder certificate (PEM) |
| `-key` | (required) | Path to responder private key (PEM) |
| `-interval` | `24h` | OCSP response validity interval |
| `-crl-url` | | URL to fetch CRL from |
| `-crl-file` | | Path to local CRL file |
| `-crl-refresh` | `5m` | CRL refresh interval |
| `-ca-cert` | | CA certificate for TLS verification |
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

Make sure CRL is enabled in your step-ca configuration (`ca.json`):

```json
{
  "crl": {
    "enabled": true
  }
}
```

## Testing

Run the test suite:

```bash
go test ./... -v -cover
```

## License

MIT
