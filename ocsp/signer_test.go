package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestNewSigner(t *testing.T) {
	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create test PKI: %v", err)
	}

	signer, err := NewSigner(pki.IssuerCert, pki.ResponderCert, pki.ResponderKey, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	if signer == nil {
		t.Fatal("Signer is nil")
	}
}

func TestSignerSign_GoodStatus(t *testing.T) {
	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create test PKI: %v", err)
	}

	signer, err := NewSigner(pki.IssuerCert, pki.ResponderCert, pki.ResponderKey, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	req := SignRequest{
		Certificate: pki.EndEntityCert,
		Status:      "good",
	}

	responseBytes, err := signer.Sign(req)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Parse and verify the response
	response, err := ocsp.ParseResponse(responseBytes, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}

	// RFC 6960 Section 4.2.1: Check response status
	if response.Status != ocsp.Good {
		t.Errorf("Expected status Good, got %d", response.Status)
	}

	// RFC 6960 Section 4.2.2.1: Check serial number matches
	if response.SerialNumber.Cmp(pki.EndEntityCert.SerialNumber) != 0 {
		t.Errorf("Serial number mismatch: got %s, want %s",
			response.SerialNumber, pki.EndEntityCert.SerialNumber)
	}

	// RFC 6960 Section 4.2.2.1: thisUpdate must be present
	if response.ThisUpdate.IsZero() {
		t.Error("thisUpdate is zero")
	}

	// RFC 6960 Section 4.2.2.1: nextUpdate should be present
	if response.NextUpdate.IsZero() {
		t.Error("nextUpdate is zero")
	}

	// Verify nextUpdate is after thisUpdate
	if !response.NextUpdate.After(response.ThisUpdate) {
		t.Error("nextUpdate should be after thisUpdate")
	}
}

func TestSignerSign_RevokedStatus(t *testing.T) {
	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create test PKI: %v", err)
	}

	signer, err := NewSigner(pki.IssuerCert, pki.ResponderCert, pki.ResponderKey, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	revokedAt := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
	req := SignRequest{
		Certificate: pki.RevokedCert,
		Status:      "revoked",
		Reason:      ocsp.KeyCompromise,
		RevokedAt:   revokedAt,
	}

	responseBytes, err := signer.Sign(req)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	response, err := ocsp.ParseResponse(responseBytes, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}

	// RFC 6960 Section 4.2.1: Check revoked status
	if response.Status != ocsp.Revoked {
		t.Errorf("Expected status Revoked, got %d", response.Status)
	}

	// RFC 6960 Section 4.2.2.1: revocationTime must be present for revoked certs
	if response.RevokedAt.IsZero() {
		t.Error("RevokedAt is zero for revoked certificate")
	}

	// RFC 6960 Section 4.2.2.1: revocationReason should match
	if response.RevocationReason != ocsp.KeyCompromise {
		t.Errorf("Expected revocation reason %d, got %d", ocsp.KeyCompromise, response.RevocationReason)
	}
}

func TestSignerSign_UnknownStatus(t *testing.T) {
	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create test PKI: %v", err)
	}

	signer, err := NewSigner(pki.IssuerCert, pki.ResponderCert, pki.ResponderKey, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	req := SignRequest{
		Certificate:    pki.EndEntityCert,
		Status:         "unknown",
		SkipValidation: true,
	}

	responseBytes, err := signer.Sign(req)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	response, err := ocsp.ParseResponse(responseBytes, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}

	// RFC 6960 Section 4.2.1: Check unknown status
	if response.Status != ocsp.Unknown {
		t.Errorf("Expected status Unknown, got %d", response.Status)
	}
}

func TestSignerSign_InvalidStatus(t *testing.T) {
	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create test PKI: %v", err)
	}

	signer, err := NewSigner(pki.IssuerCert, pki.ResponderCert, pki.ResponderKey, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	req := SignRequest{
		Certificate: pki.EndEntityCert,
		Status:      "invalid",
	}

	_, err = signer.Sign(req)
	if err == nil {
		t.Error("Expected error for invalid status")
	}
}

func TestSignerSign_NilCertificate(t *testing.T) {
	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create test PKI: %v", err)
	}

	signer, err := NewSigner(pki.IssuerCert, pki.ResponderCert, pki.ResponderKey, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	req := SignRequest{
		Certificate: nil,
		Status:      "good",
	}

	_, err = signer.Sign(req)
	if err == nil {
		t.Error("Expected error for nil certificate")
	}
}

func TestSignerSign_ResponseInterval(t *testing.T) {
	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create test PKI: %v", err)
	}

	interval := 2 * time.Hour
	signer, err := NewSigner(pki.IssuerCert, pki.ResponderCert, pki.ResponderKey, interval)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	req := SignRequest{
		Certificate: pki.EndEntityCert,
		Status:      "good",
	}

	responseBytes, err := signer.Sign(req)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	response, err := ocsp.ParseResponse(responseBytes, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}

	// Check that nextUpdate - thisUpdate is approximately the interval
	diff := response.NextUpdate.Sub(response.ThisUpdate)
	if diff < interval-time.Minute || diff > interval+time.Minute {
		t.Errorf("Response interval mismatch: got %v, want ~%v", diff, interval)
	}
}

func TestSignerSign_IssuerHash(t *testing.T) {
	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create test PKI: %v", err)
	}

	signer, err := NewSigner(pki.IssuerCert, pki.ResponderCert, pki.ResponderKey, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	req := SignRequest{
		Certificate: pki.EndEntityCert,
		Status:      "good",
		IssuerHash:  crypto.SHA256,
	}

	responseBytes, err := signer.Sign(req)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify the response can be parsed
	_, err = ocsp.ParseResponse(responseBytes, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}
}

func TestSignerSign_SameIssuerAndResponder(t *testing.T) {
	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create test PKI: %v", err)
	}

	// Use issuer as both issuer and responder (self-signed OCSP)
	signer, err := NewSigner(pki.IssuerCert, pki.IssuerCert, pki.IssuerKey, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	req := SignRequest{
		Certificate: pki.EndEntityCert,
		Status:      "good",
	}

	responseBytes, err := signer.Sign(req)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	response, err := ocsp.ParseResponse(responseBytes, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}

	// When issuer == responder, Certificate should be nil in response
	if response.Certificate != nil {
		t.Error("Expected nil Certificate when issuer is responder")
	}
}

func TestSignerIssuer(t *testing.T) {
	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create test PKI: %v", err)
	}

	signer, err := NewSigner(pki.IssuerCert, pki.ResponderCert, pki.ResponderKey, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	stdSigner := signer.(*StandardSigner)
	if stdSigner.Issuer() != pki.IssuerCert {
		t.Error("Issuer() returned wrong certificate")
	}
}

func TestSignerSign_WrongIssuer(t *testing.T) {
	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create test PKI: %v", err)
	}

	signer, err := NewSigner(pki.IssuerCert, pki.ResponderCert, pki.ResponderKey, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Create a self-signed certificate (not signed by the issuer)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "self-signed"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	selfSignedDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	selfSignedCert, _ := x509.ParseCertificate(selfSignedDER)

	// Try to sign with wrong issuer (SkipValidation = false)
	req := SignRequest{
		Certificate:    selfSignedCert,
		Status:         "good",
		SkipValidation: false,
	}

	_, err = signer.Sign(req)
	if err == nil {
		t.Error("Expected error for certificate not signed by issuer")
	}
}
