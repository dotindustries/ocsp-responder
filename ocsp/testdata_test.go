package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// testPKI holds test certificates and keys
type testPKI struct {
	IssuerCert     *x509.Certificate
	IssuerKey      crypto.Signer
	ResponderCert  *x509.Certificate
	ResponderKey   crypto.Signer
	EndEntityCert  *x509.Certificate
	EndEntityKey   crypto.Signer
	RevokedCert    *x509.Certificate
	RevokedKey     crypto.Signer
}

// newTestPKI creates a complete test PKI for OCSP testing
func newTestPKI() (*testPKI, error) {
	// Generate issuer (CA) key pair
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create issuer certificate
	issuerSerial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	issuerTemplate := &x509.Certificate{
		SerialNumber: issuerSerial,
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	issuerCert, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return nil, err
	}

	// Generate OCSP responder key pair
	responderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create OCSP responder certificate (signed by issuer)
	responderSerial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	responderTemplate := &x509.Certificate{
		SerialNumber: responderSerial,
		Subject: pkix.Name{
			CommonName:   "OCSP Responder",
			Organization: []string{"Test Org"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}

	responderDER, err := x509.CreateCertificate(rand.Reader, responderTemplate, issuerCert, &responderKey.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	responderCert, err := x509.ParseCertificate(responderDER)
	if err != nil {
		return nil, err
	}

	// Generate end-entity key pair
	eeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create end-entity certificate (signed by issuer)
	eeSerial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	eeTemplate := &x509.Certificate{
		SerialNumber: eeSerial,
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"test.example.com"},
	}

	eeDER, err := x509.CreateCertificate(rand.Reader, eeTemplate, issuerCert, &eeKey.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	eeCert, err := x509.ParseCertificate(eeDER)
	if err != nil {
		return nil, err
	}

	// Generate revoked certificate key pair
	revokedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create revoked certificate (signed by issuer)
	revokedSerial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	revokedTemplate := &x509.Certificate{
		SerialNumber: revokedSerial,
		Subject: pkix.Name{
			CommonName:   "revoked.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"revoked.example.com"},
	}

	revokedDER, err := x509.CreateCertificate(rand.Reader, revokedTemplate, issuerCert, &revokedKey.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	revokedCert, err := x509.ParseCertificate(revokedDER)
	if err != nil {
		return nil, err
	}

	return &testPKI{
		IssuerCert:    issuerCert,
		IssuerKey:     issuerKey,
		ResponderCert: responderCert,
		ResponderKey:  responderKey,
		EndEntityCert: eeCert,
		EndEntityKey:  eeKey,
		RevokedCert:   revokedCert,
		RevokedKey:    revokedKey,
	}, nil
}
