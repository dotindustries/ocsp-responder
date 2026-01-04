package ocsp

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ErrMalformedRequest indicates the OCSP request could not be parsed
var ErrMalformedRequest = errors.New("malformed OCSP request")

// ocspRequest is used to parse the raw OCSP request for extensions
// RFC 6960 Section 4.1.1
type ocspRequest struct {
	TBSRequest tbsRequest
}

type tbsRequest struct {
	Version       int             `asn1:"optional,explicit,default:0,tag:0"`
	RequestorName asn1.RawValue   `asn1:"optional,explicit,tag:1"`
	RequestList   []asn1.RawValue // We don't need to parse these
	Extensions    []pkixExtension `asn1:"optional,explicit,tag:2"`
}

type pkixExtension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// extractNonce extracts the nonce extension from an OCSP request if present
func extractNonce(requestBytes []byte) []byte {
	var req ocspRequest
	rest, err := asn1.Unmarshal(requestBytes, &req)
	if err != nil || len(rest) > 0 {
		return nil
	}

	for _, ext := range req.TBSRequest.Extensions {
		if ext.Id.Equal(OIDOCSPNonce) {
			// The nonce value is an OCTET STRING, but may be double-wrapped
			// Try to unwrap if it's an OCTET STRING
			var nonce []byte
			if _, err := asn1.Unmarshal(ext.Value, &nonce); err == nil {
				return nonce
			}
			// If unwrap fails, return raw value
			return ext.Value
		}
	}
	return nil
}

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
	Stats() CRLStats
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

	result, err := r.handleRequest(requestBytes)
	if err != nil {
		log.Printf("Error handling request: %v", err)
		if errors.Is(err, ErrMalformedRequest) {
			r.writeError(w, ocsp.Malformed)
		} else {
			r.writeError(w, ocsp.InternalError)
		}
		return
	}

	w.Header().Set("Content-Type", ocspContentType)

	// RFC 6960 Section 4.4.1: Responses with nonce should not be cached
	if result.hasNonce {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	} else {
		w.Header().Set("Cache-Control", "max-age=3600, public, no-transform, must-revalidate")
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result.response)
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

// handleResult contains the OCSP response and metadata
type handleResult struct {
	response []byte
	hasNonce bool
}

func (r *Responder) handleRequest(requestBytes []byte) (*handleResult, error) {
	// Parse the OCSP request
	ocspReq, err := ocsp.ParseRequest(requestBytes)
	if err != nil {
		return nil, errors.Join(ErrMalformedRequest, err)
	}

	// Extract nonce if present (RFC 6960 Section 4.4.1)
	nonce := extractNonce(requestBytes)

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
		Nonce:          nonce,
	}

	response, err := r.signer.Sign(signReq)
	if err != nil {
		return nil, err
	}

	return &handleResult{
		response: response,
		hasNonce: len(nonce) > 0,
	}, nil
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
	_, _ = w.Write([]byte{0x30, 0x03, 0x0a, 0x01, byte(status)})
}
