package ocsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testFiles holds paths to temporary test files
type testFiles struct {
	dir           string
	issuerFile    string
	responderFile string
	keyFile       string
}

// createTestFiles creates temporary PEM files for testing
func createTestFiles(t *testing.T) *testFiles {
	t.Helper()

	dir, err := os.MkdirTemp("", "ocsp-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Generate issuer key and cert
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuerCert, _ := x509.ParseCertificate(issuerDER)

	// Generate responder key and cert
	responderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	responderTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "OCSP Responder"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	responderDER, _ := x509.CreateCertificate(rand.Reader, responderTemplate, issuerCert, &responderKey.PublicKey, issuerKey)

	// Write issuer cert
	issuerFile := filepath.Join(dir, "issuer.pem")
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
	if err := os.WriteFile(issuerFile, issuerPEM, 0644); err != nil {
		t.Fatalf("Failed to write issuer file: %v", err)
	}

	// Write responder cert
	responderFile := filepath.Join(dir, "responder.pem")
	responderPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: responderDER})
	if err := os.WriteFile(responderFile, responderPEM, 0644); err != nil {
		t.Fatalf("Failed to write responder file: %v", err)
	}

	// Write responder key
	keyFile := filepath.Join(dir, "responder-key.pem")
	keyDER, _ := x509.MarshalPKCS8PrivateKey(responderKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	return &testFiles{
		dir:           dir,
		issuerFile:    issuerFile,
		responderFile: responderFile,
		keyFile:       keyFile,
	}
}

func (tf *testFiles) cleanup() {
	_ = os.RemoveAll(tf.dir)
}

func TestNewSignerFromFile_Valid(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	signer, err := NewSignerFromFile(files.issuerFile, files.responderFile, files.keyFile, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signer from files: %v", err)
	}

	if signer == nil {
		t.Fatal("Signer is nil")
	}

	// Verify the signer works
	stdSigner := signer.(*StandardSigner)
	if stdSigner.Issuer().Subject.CommonName != "Test CA" {
		t.Errorf("Wrong issuer CN: %s", stdSigner.Issuer().Subject.CommonName)
	}
}

func TestNewSignerFromFile_MissingIssuer(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	_, err := NewSignerFromFile("/nonexistent/issuer.pem", files.responderFile, files.keyFile, time.Hour)
	if err == nil {
		t.Error("Expected error for missing issuer file")
	}
}

func TestNewSignerFromFile_MissingResponder(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	_, err := NewSignerFromFile(files.issuerFile, "/nonexistent/responder.pem", files.keyFile, time.Hour)
	if err == nil {
		t.Error("Expected error for missing responder file")
	}
}

func TestNewSignerFromFile_MissingKey(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	_, err := NewSignerFromFile(files.issuerFile, files.responderFile, "/nonexistent/key.pem", time.Hour)
	if err == nil {
		t.Error("Expected error for missing key file")
	}
}

func TestNewSignerFromFile_InvalidIssuer(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	// Write invalid data to issuer file
	if err := os.WriteFile(files.issuerFile, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("Failed to write issuer file: %v", err)
	}

	_, err := NewSignerFromFile(files.issuerFile, files.responderFile, files.keyFile, time.Hour)
	if err == nil {
		t.Error("Expected error for invalid issuer file")
	}
}

func TestNewSignerFromFile_InvalidResponder(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	// Write invalid data to responder file
	if err := os.WriteFile(files.responderFile, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("Failed to write responder file: %v", err)
	}

	_, err := NewSignerFromFile(files.issuerFile, files.responderFile, files.keyFile, time.Hour)
	if err == nil {
		t.Error("Expected error for invalid responder file")
	}
}

func TestNewSignerFromFile_InvalidKey(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	// Write invalid data to key file
	if err := os.WriteFile(files.keyFile, []byte("not a key"), 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	_, err := NewSignerFromFile(files.issuerFile, files.responderFile, files.keyFile, time.Hour)
	if err == nil {
		t.Error("Expected error for invalid key file")
	}
}

func TestNewSignerFromFile_SignResponse(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	signer, err := NewSignerFromFile(files.issuerFile, files.responderFile, files.keyFile, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Create a minimal certificate for OCSP response (skip validation since
	// we don't have access to the issuer key to create a properly signed cert)
	stdSigner := signer.(*StandardSigner)
	testCert := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		RawIssuer:    stdSigner.Issuer().RawSubject,
	}

	// Sign an OCSP response with SkipValidation
	req := SignRequest{
		Certificate:    testCert,
		Status:         "good",
		SkipValidation: true,
	}

	response, err := signer.Sign(req)
	if err != nil {
		t.Fatalf("Failed to sign response: %v", err)
	}

	if len(response) == 0 {
		t.Error("Empty response")
	}
}
