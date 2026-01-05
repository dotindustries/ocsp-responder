package ocsp

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OIDOCSPNonce is the OID for the OCSP nonce extension (RFC 6960 Section 4.4.1)
var OIDOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// StatusCode maps string statuses to OCSP int statuses
var StatusCode = map[string]int{
	"good":    ocsp.Good,
	"revoked": ocsp.Revoked,
	"unknown": ocsp.Unknown,
}

// SignRequest represents the desired contents of an OCSP response
type SignRequest struct {
	Certificate    *x509.Certificate
	Status         string
	Reason         int
	RevokedAt      time.Time
	IssuerHash     crypto.Hash
	SkipValidation bool   // Skip issuer validation (for responder mode)
	Nonce          []byte // Optional nonce from request (RFC 6960 Section 4.4.1)
}

// Signer represents a signer of OCSP responses
type Signer interface {
	Sign(req SignRequest) ([]byte, error)
}

// StandardSigner is the default OCSP signer implementation
type StandardSigner struct {
	issuer    *x509.Certificate
	responder *x509.Certificate
	key       crypto.Signer
	interval  time.Duration
}

// NewSignerFromFile reads certs and key from PEM files (backward compatible)
func NewSignerFromFile(issuerFile, responderFile, keyFile string, interval time.Duration) (Signer, error) {
	issuerBytes, err := os.ReadFile(issuerFile)
	if err != nil {
		return nil, err
	}

	responderBytes, err := os.ReadFile(responderFile)
	if err != nil {
		return nil, err
	}

	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	issuerCert, err := ParseCertificatePEM(issuerBytes)
	if err != nil {
		return nil, err
	}

	responderCert, err := ParseCertificatePEM(responderBytes)
	if err != nil {
		return nil, err
	}

	key, err := ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return nil, err
	}

	return NewSigner(issuerCert, responderCert, key, interval)
}

// NewSignerFromPaths loads certs from file paths or URLs, and key from file only.
// For -issuer and -responder: paths starting with http:// or https:// are fetched via HTTP GET.
// For -key: only file paths are supported (private keys should not be fetched over network).
// If keyPassword is non-empty, it will be used to decrypt an encrypted private key.
func NewSignerFromPaths(issuerPath, responderPath, keyFile, keyPassword string, interval time.Duration, insecureSkipVerify bool) (Signer, error) {
	// Load issuer certificate (file or URL)
	issuerBytes, err := LoadPEM(issuerPath, insecureSkipVerify)
	if err != nil {
		return nil, fmt.Errorf("failed to load issuer certificate: %w", err)
	}

	// Load responder certificate (file or URL)
	responderBytes, err := LoadPEM(responderPath, insecureSkipVerify)
	if err != nil {
		return nil, fmt.Errorf("failed to load responder certificate: %w", err)
	}

	// Load key from file only (not URLs for security)
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read responder key file: %w", err)
	}

	issuerCert, err := ParseCertificatePEM(issuerBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer certificate: %w", err)
	}

	responderCert, err := ParseCertificatePEM(responderBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse responder certificate: %w", err)
	}

	key, err := ParsePrivateKeyPEMWithPassword(keyBytes, keyPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to parse responder key: %w", err)
	}

	return NewSigner(issuerCert, responderCert, key, interval)
}

// NewSigner constructs a new StandardSigner
func NewSigner(issuer, responder *x509.Certificate, key crypto.Signer, interval time.Duration) (Signer, error) {
	return &StandardSigner{
		issuer:    issuer,
		responder: responder,
		key:       key,
		interval:  interval,
	}, nil
}

// Issuer returns the issuer certificate
func (s *StandardSigner) Issuer() *x509.Certificate {
	return s.issuer
}

// Sign creates an OCSP response for the given request
func (s *StandardSigner) Sign(req SignRequest) ([]byte, error) {
	if req.Certificate == nil {
		return nil, errors.New("certificate is required")
	}

	// Verify the certificate was issued by our issuer (unless skipped)
	if !req.SkipValidation {
		err := req.Certificate.CheckSignatureFrom(s.issuer)
		if err != nil {
			return nil, errors.New("certificate not issued by configured issuer")
		}
	}

	thisUpdate := time.Now().Truncate(time.Minute)
	nextUpdate := thisUpdate.Add(s.interval)

	status, ok := StatusCode[req.Status]
	if !ok {
		return nil, errors.New("invalid status")
	}

	// Include responder cert unless it's the same as issuer
	var certificate *x509.Certificate
	if s.issuer != s.responder {
		certificate = s.responder
	}

	template := ocsp.Response{
		Status:       status,
		SerialNumber: req.Certificate.SerialNumber,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
		Certificate:  certificate,
		IssuerHash:   crypto.SHA256,
	}

	if status == ocsp.Revoked {
		template.RevokedAt = req.RevokedAt
		template.RevocationReason = req.Reason
	}

	// RFC 6960 Section 4.4.1: Include nonce extension if present in request
	if len(req.Nonce) > 0 {
		nonceExt := pkix.Extension{
			Id:    OIDOCSPNonce,
			Value: req.Nonce,
		}
		template.ExtraExtensions = append(template.ExtraExtensions, nonceExt)
	}

	return ocsp.CreateResponse(s.issuer, s.responder, template, s.key)
}
