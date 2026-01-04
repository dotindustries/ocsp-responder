package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dot-inc/ocsp-responder/ocsp"
)

func main() {
	var (
		addr          = flag.String("addr", ":8080", "Address to listen on")
		issuerFile    = flag.String("issuer", "", "Path to issuer certificate (PEM)")
		responderFile = flag.String("responder", "", "Path to responder certificate (PEM)")
		keyFile       = flag.String("key", "", "Path to responder private key (PEM)")
		interval      = flag.Duration("interval", 24*time.Hour, "OCSP response validity interval")
	)
	flag.Parse()

	// Check required flags
	if *issuerFile == "" || *responderFile == "" || *keyFile == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -issuer <cert> -responder <cert> -key <key>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Create signer from files
	signer, err := ocsp.NewSignerFromFile(*issuerFile, *responderFile, *keyFile, *interval)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	// Create in-memory source (all certs default to "good")
	source := ocsp.NewInMemorySource()

	// Create responder
	responder := ocsp.NewResponder(source, signer)

	// Set up HTTP routes
	mux := http.NewServeMux()

	// Health check endpoint for Azure Gateway
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// OCSP endpoint - handles all other paths
	mux.Handle("/", responder)

	log.Printf("Starting OCSP responder on %s", *addr)
	log.Printf("  Issuer cert: %s", *issuerFile)
	log.Printf("  Responder cert: %s", *responderFile)
	log.Printf("  Response interval: %s", *interval)

	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
