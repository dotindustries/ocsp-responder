package ocsp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParseCertificatePEM_Valid(t *testing.T) {
	// Generate a test certificate
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("Failed to parse valid certificate: %v", err)
	}
	if cert.Subject.CommonName != "Test" {
		t.Errorf("Wrong CN: got %s, want Test", cert.Subject.CommonName)
	}
}

func TestParseCertificatePEM_InvalidPEM(t *testing.T) {
	_, err := ParseCertificatePEM([]byte("not a pem block"))
	if err == nil {
		t.Error("Expected error for invalid PEM")
	}
}

func TestParseCertificatePEM_WrongType(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("fake data"),
	})

	_, err := ParseCertificatePEM(block)
	if err == nil {
		t.Error("Expected error for wrong PEM type")
	}
}

func TestParseCertificatePEM_InvalidCert(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not a valid certificate"),
	})

	_, err := ParseCertificatePEM(block)
	if err == nil {
		t.Error("Expected error for invalid certificate data")
	}
}

func TestParsePrivateKeyPEM_RSA_PKCS1(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	parsed, err := ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("Failed to parse RSA PKCS1 key: %v", err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Error("Expected RSA private key")
	}
}

func TestParsePrivateKeyPEM_EC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	parsed, err := ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("Failed to parse EC key: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Error("Expected ECDSA private key")
	}
}

func TestParsePrivateKeyPEM_PKCS8_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	parsed, err := ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("Failed to parse PKCS8 RSA key: %v", err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Error("Expected RSA private key")
	}
}

func TestParsePrivateKeyPEM_PKCS8_EC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	parsed, err := ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("Failed to parse PKCS8 EC key: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Error("Expected ECDSA private key")
	}
}

func TestParsePrivateKeyPEM_PKCS8_Ed25519(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	parsed, err := ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("Failed to parse PKCS8 Ed25519 key: %v", err)
	}
	if _, ok := parsed.(ed25519.PrivateKey); !ok {
		t.Error("Expected Ed25519 private key")
	}
}

func TestParsePrivateKeyPEM_InvalidPEM(t *testing.T) {
	_, err := ParsePrivateKeyPEM([]byte("not a pem block"))
	if err == nil {
		t.Error("Expected error for invalid PEM")
	}
}

func TestParsePrivateKeyPEM_UnsupportedType(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "UNKNOWN KEY TYPE",
		Bytes: []byte("fake data"),
	})

	_, err := ParsePrivateKeyPEM(block)
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
}

func TestParsePrivateKeyPEM_InvalidRSAKey(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("not a valid key"),
	})

	_, err := ParsePrivateKeyPEM(block)
	if err == nil {
		t.Error("Expected error for invalid RSA key")
	}
}

func TestParsePrivateKeyPEM_InvalidECKey(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("not a valid key"),
	})

	_, err := ParsePrivateKeyPEM(block)
	if err == nil {
		t.Error("Expected error for invalid EC key")
	}
}

func TestParsePrivateKeyPEM_InvalidPKCS8Key(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("not a valid key"),
	})

	_, err := ParsePrivateKeyPEM(block)
	if err == nil {
		t.Error("Expected error for invalid PKCS8 key")
	}
}

func TestParsePrivateKeyPEMWithPassword_EncryptedEC(t *testing.T) {
	// Generate an EC key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)

	// Encrypt the PEM block with a password
	password := []byte("testpassword123")
	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but needed for testing legacy format
	encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", keyDER, password, x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("Failed to encrypt PEM block: %v", err)
	}

	encryptedPEM := pem.EncodeToMemory(encryptedBlock)

	// Test successful decryption with correct password
	parsed, err := ParsePrivateKeyPEMWithPassword(encryptedPEM, "testpassword123")
	if err != nil {
		t.Fatalf("Failed to parse encrypted EC key: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Error("Expected ECDSA private key")
	}
}

func TestParsePrivateKeyPEMWithPassword_WrongPassword(t *testing.T) {
	// Generate an EC key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)

	// Encrypt the PEM block with a password
	password := []byte("correctpassword")
	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but needed for testing legacy format
	encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", keyDER, password, x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("Failed to encrypt PEM block: %v", err)
	}

	encryptedPEM := pem.EncodeToMemory(encryptedBlock)

	// Test with wrong password
	_, err = ParsePrivateKeyPEMWithPassword(encryptedPEM, "wrongpassword")
	if err == nil {
		t.Error("Expected error for wrong password")
	}
}

func TestParsePrivateKeyPEMWithPassword_EncryptedNoPassword(t *testing.T) {
	// Generate an EC key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)

	// Encrypt the PEM block with a password
	password := []byte("testpassword")
	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but needed for testing legacy format
	encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", keyDER, password, x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("Failed to encrypt PEM block: %v", err)
	}

	encryptedPEM := pem.EncodeToMemory(encryptedBlock)

	// Test without providing password
	_, err = ParsePrivateKeyPEMWithPassword(encryptedPEM, "")
	if err == nil {
		t.Error("Expected error when no password provided for encrypted key")
	}
	if err.Error() != "private key is encrypted but no password provided (use -key-password)" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestParsePrivateKeyPEMWithPassword_UnencryptedWithPassword(t *testing.T) {
	// Generate an EC key (unencrypted)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	// Providing a password for unencrypted key should still work (password is ignored)
	parsed, err := ParsePrivateKeyPEMWithPassword(keyPEM, "unnecessarypassword")
	if err != nil {
		t.Fatalf("Failed to parse unencrypted key with password: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Error("Expected ECDSA private key")
	}
}

func TestParsePrivateKeyPEMWithPassword_EncryptedRSA(t *testing.T) {
	// Generate an RSA key
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyDER := x509.MarshalPKCS1PrivateKey(key)

	// Encrypt the PEM block with a password
	password := []byte("rsapassword")
	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but needed for testing legacy format
	encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", keyDER, password, x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("Failed to encrypt PEM block: %v", err)
	}

	encryptedPEM := pem.EncodeToMemory(encryptedBlock)

	// Test successful decryption
	parsed, err := ParsePrivateKeyPEMWithPassword(encryptedPEM, "rsapassword")
	if err != nil {
		t.Fatalf("Failed to parse encrypted RSA key: %v", err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Error("Expected RSA private key")
	}
}
