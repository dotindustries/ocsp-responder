package ocsp

import (
	"crypto/x509"
	"encoding/base64"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	maxRequestSize  = 10 * 1024 // 10KB max request size
	ocspContentType = "application/ocsp-response"
)

// CertStatus represents the status of a certificate
type CertStatus struct {
	Status    string    // "good", "revoked", "unknown"
	RevokedAt time.Time // only used if Status is "revoked"
	Reason    int       // revocation reason code
}

// Source is an interface for looking up certificate status
type Source interface {
	Response(serial *big.Int) (*CertStatus, error)
}

// InMemorySource is a simple in-memory certificate status store
type InMemorySource struct {
	mu       sync.RWMutex
	statuses map[string]*CertStatus
}

// NewInMemorySource creates a new in-memory source
func NewInMemorySource() *InMemorySource {
	return &InMemorySource{
		statuses: make(map[string]*CertStatus),
	}
}

// SetStatus sets the status for a certificate serial number
func (s *InMemorySource) SetStatus(serial *big.Int, status *CertStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses[serial.String()] = status
}

// Response returns the status for a certificate serial number
func (s *InMemorySource) Response(serial *big.Int) (*CertStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status, ok := s.statuses[serial.String()]
	if !ok {
		// Default to "good" if not found (you may want to change this to "unknown")
		return &CertStatus{Status: "good"}, nil
	}
	return status, nil
}

// Responder is an HTTP handler for OCSP requests
type Responder struct {
	source Source
	signer *StandardSigner
}

// NewResponder creates a new OCSP responder
func NewResponder(source Source, signer Signer) *Responder {
	return &Responder{
		source: source,
		signer: signer.(*StandardSigner),
	}
}

// ServeHTTP handles OCSP requests via GET and POST
func (r *Responder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var requestBytes []byte
	var err error

	switch req.Method {
	case http.MethodGet:
		requestBytes, err = r.parseGetRequest(req)
	case http.MethodPost:
		requestBytes, err = r.parsePostRequest(req)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		log.Printf("Error parsing request: %v", err)
		r.writeError(w, ocsp.Malformed)
		return
	}

	response, err := r.handleRequest(requestBytes)
	if err != nil {
		log.Printf("Error handling request: %v", err)
		r.writeError(w, ocsp.InternalError)
		return
	}

	w.Header().Set("Content-Type", ocspContentType)
	w.Header().Set("Cache-Control", "max-age=3600, public, no-transform, must-revalidate")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

func (r *Responder) parseGetRequest(req *http.Request) ([]byte, error) {
	// OCSP GET requests have the base64-encoded request in the URL path
	path := req.URL.Path

	// Remove leading slash and any prefix path
	path = strings.TrimPrefix(path, "/")

	// URL-decode the path
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return nil, err
	}

	// Base64 decode
	return base64.StdEncoding.DecodeString(decoded)
}

func (r *Responder) parsePostRequest(req *http.Request) ([]byte, error) {
	if req.ContentLength > maxRequestSize {
		return nil, io.ErrShortBuffer
	}

	return io.ReadAll(io.LimitReader(req.Body, maxRequestSize))
}

func (r *Responder) handleRequest(requestBytes []byte) ([]byte, error) {
	// Parse the OCSP request
	ocspReq, err := ocsp.ParseRequest(requestBytes)
	if err != nil {
		return nil, err
	}

	// Look up the certificate status
	status, err := r.source.Response(ocspReq.SerialNumber)
	if err != nil {
		return nil, err
	}

	// Create sign request with minimal certificate info
	signReq := SignRequest{
		Certificate:    r.createMinimalCert(ocspReq.SerialNumber),
		Status:         status.Status,
		Reason:         status.Reason,
		RevokedAt:      status.RevokedAt,
		SkipValidation: true, // We only have serial, can't verify signature
	}

	return r.signer.Sign(signReq)
}

// createMinimalCert creates a minimal certificate for OCSP signing
// The OCSP response only needs the serial number and issuer info
func (r *Responder) createMinimalCert(serial *big.Int) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:       serial,
		RawIssuer:          r.signer.Issuer().RawSubject,
		SignatureAlgorithm: r.signer.Issuer().SignatureAlgorithm,
		Signature:          r.signer.Issuer().Signature,
	}
}

func (r *Responder) writeError(w http.ResponseWriter, status ocsp.ResponseStatus) {
	// Create a minimal error response
	w.Header().Set("Content-Type", ocspContentType)
	w.WriteHeader(http.StatusOK) // OCSP uses 200 OK even for errors
	w.Write([]byte{0x30, 0x03, 0x0a, 0x01, byte(status)})
}
