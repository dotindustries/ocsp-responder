package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ParseCertificatePEM parses a PEM-encoded certificate
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM block is not a certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

// ParsePrivateKeyPEM parses a PEM-encoded private key (unencrypted)
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	return ParsePrivateKeyPEMWithPassword(data, "")
}

// ParsePrivateKeyPEMWithPassword parses a PEM-encoded private key, decrypting if necessary
func ParsePrivateKeyPEMWithPassword(data []byte, password string) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	keyBytes := block.Bytes

	// Check if the key is encrypted (legacy PEM encryption)
	//nolint:staticcheck // x509.IsEncryptedPEMBlock is deprecated but needed for legacy format
	if x509.IsEncryptedPEMBlock(block) {
		if password == "" {
			return nil, errors.New("private key is encrypted but no password provided (use -key-password)")
		}
		var err error
		//nolint:staticcheck // x509.DecryptPEMBlock is deprecated but needed for legacy format
		keyBytes, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		return key, nil

	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		return key, nil

	case "PRIVATE KEY":
		// PKCS#8 format (may be encrypted with PBES2, not legacy PEM encryption)
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		case ed25519.PrivateKey:
			return k, nil
		default:
			return nil, errors.New("unsupported private key type in PKCS#8 container")
		}

	case "ENCRYPTED PRIVATE KEY":
		// PKCS#8 encrypted format - requires different handling
		return nil, errors.New("PKCS#8 encrypted keys (ENCRYPTED PRIVATE KEY) are not yet supported; use legacy PEM encryption or unencrypted keys")

	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}
