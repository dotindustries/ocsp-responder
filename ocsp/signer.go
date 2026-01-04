package ocsp

import (
	"crypto"
	"crypto/x509"
	"errors"
	"os"
	"time"

	"golang.org/x/crypto/ocsp"
)

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
	SkipValidation bool // Skip issuer validation (for responder mode)
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

// NewSignerFromFile reads certs and key from PEM files
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

	return ocsp.CreateResponse(s.issuer, s.responder, template, s.key)
}
