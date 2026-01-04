package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dot-inc/ocsp-responder/ocsp"
)

// SourceConfig holds configuration for creating a certificate status source
type SourceConfig struct {
	CRLURL          string
	CRLFile         string
	CRLRefresh      time.Duration
	CACertFile      string
	InsecureSkipTLS bool
}

// createSource creates a certificate status source based on the configuration.
// Returns the source, a close function (may be nil), and any error.
func createSource(cfg SourceConfig) (ocsp.Source, func() error, error) {
	switch {
	case cfg.CRLURL != "":
		log.Printf("Using URL source: %s", cfg.CRLURL)

		urlCfg := ocsp.URLSourceConfig{
			URL:                cfg.CRLURL,
			RefreshInterval:    cfg.CRLRefresh,
			InsecureSkipVerify: cfg.InsecureSkipTLS,
		}

		// Load CA certificate if provided
		if cfg.CACertFile != "" {
			caCert, err := os.ReadFile(cfg.CACertFile)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read CA certificate: %w", err)
			}
			urlCfg.RootCAs = x509.NewCertPool()
			if !urlCfg.RootCAs.AppendCertsFromPEM(caCert) {
				return nil, nil, fmt.Errorf("failed to parse CA certificate")
			}
		}

		source, err := ocsp.NewURLSource(urlCfg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create URL source: %w", err)
		}
		return source, source.Close, nil

	case cfg.CRLFile != "":
		log.Printf("Using file source: %s", cfg.CRLFile)

		source, err := ocsp.NewFileSource(ocsp.FileSourceConfig{
			Path:            cfg.CRLFile,
			RefreshInterval: cfg.CRLRefresh,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create file source: %w", err)
		}
		return source, source.Close, nil

	default:
		log.Printf("Using in-memory source (all certificates return 'good')")
		return ocsp.NewInMemorySource(), nil, nil
	}
}

func main() {
	var (
		addr          = flag.String("addr", ":8080", "Address to listen on")
		issuerFile    = flag.String("issuer", "", "Path to issuer certificate (PEM)")
		responderFile = flag.String("responder", "", "Path to responder certificate (PEM)")
		keyFile       = flag.String("key", "", "Path to responder private key (PEM)")
		interval      = flag.Duration("interval", 24*time.Hour, "OCSP response validity interval")

		// CRL source options
		crlURL          = flag.String("crl-url", "", "URL to fetch CRL from (e.g., https://ca.example.com/crl)")
		crlFile         = flag.String("crl-file", "", "Path to local CRL file")
		crlRefresh      = flag.Duration("crl-refresh", 5*time.Minute, "CRL refresh interval")
		caCertFile      = flag.String("ca-cert", "", "CA certificate for TLS verification (optional)")
		insecureSkipTLS = flag.Bool("insecure-skip-verify", false, "Skip TLS verification (testing only)")
	)
	flag.Parse()

	// Check required flags
	if *issuerFile == "" || *responderFile == "" || *keyFile == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -issuer <cert> -responder <cert> -key <key> [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Basic mode (all certificates return 'good'):\n")
		fmt.Fprintf(os.Stderr, "  %s -issuer ca.pem -responder ocsp.pem -key ocsp-key.pem\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # With CRL from step-ca or any CA:\n")
		fmt.Fprintf(os.Stderr, "  %s -issuer ca.pem -responder ocsp.pem -key ocsp-key.pem -crl-url https://ca.example.com/crl\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # With local CRL file:\n")
		fmt.Fprintf(os.Stderr, "  %s -issuer ca.pem -responder ocsp.pem -key ocsp-key.pem -crl-file /path/to/crl.der\n", os.Args[0])
		os.Exit(1)
	}

	// Create signer from files
	signer, err := ocsp.NewSignerFromFile(*issuerFile, *responderFile, *keyFile, *interval)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	// Create certificate status source
	source, closeSource, err := createSource(SourceConfig{
		CRLURL:          *crlURL,
		CRLFile:         *crlFile,
		CRLRefresh:      *crlRefresh,
		CACertFile:      *caCertFile,
		InsecureSkipTLS: *insecureSkipTLS,
	})
	if err != nil {
		log.Fatalf("Failed to create source: %v", err)
	}
	if closeSource != nil {
		defer closeSource()
	}

	// Create responder
	responder := ocsp.NewResponder(source, signer)

	// Set up HTTP routes
	mux := http.NewServeMux()

	// Health check endpoint for Azure Gateway
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := map[string]interface{}{
			"status": "healthy",
		}

		// Include CRL stats if using CRL source
		if source != nil {
			stats := source.Stats()
			response["crl"] = map[string]interface{}{
				"revoked_count": stats.RevokedCount,
				"last_update":   stats.LastUpdate.Format(time.RFC3339),
				"next_update":   stats.NextUpdate.Format(time.RFC3339),
			}
		}

		json.NewEncoder(w).Encode(response)
	})

	// OCSP endpoint - handles all other paths
	mux.Handle("/", responder)

	log.Printf("Starting OCSP responder on %s", *addr)
	log.Printf("  Issuer cert: %s", *issuerFile)
	log.Printf("  Responder cert: %s", *responderFile)
	log.Printf("  Response interval: %s", *interval)
	if *crlURL != "" {
		log.Printf("  CRL URL: %s", *crlURL)
		log.Printf("  CRL refresh: %s", *crlRefresh)
	} else if *crlFile != "" {
		log.Printf("  CRL file: %s", *crlFile)
		log.Printf("  CRL refresh: %s", *crlRefresh)
	}

	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
