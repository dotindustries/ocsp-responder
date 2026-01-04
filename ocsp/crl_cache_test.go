package ocsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// createTestCRL creates a test CRL with the given revoked serials
func createTestCRL(t *testing.T, revokedSerials []*big.Int) []byte {
	t.Helper()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	revokedEntries := make([]x509.RevocationListEntry, len(revokedSerials))
	for i, serial := range revokedSerials {
		revokedEntries[i] = x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Hour),
			ReasonCode:     1,
		}
	}

	crlTemplate := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: revokedEntries,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		t.Fatalf("Failed to create CRL: %v", err)
	}

	return crlDER
}

// =============================================================================
// crlCache Tests
// =============================================================================

func TestCRLCache_Response_Good(t *testing.T) {
	revokedSerial := big.NewInt(12345)
	crlData := createTestCRL(t, []*big.Int{revokedSerial})

	cache, err := newCRLCache(crlCacheConfig{
		fetcher:         newStaticFetcher(crlData),
		refreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Check non-revoked cert
	status, err := cache.Response(big.NewInt(99999))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if status.Status != "good" {
		t.Errorf("Expected 'good', got '%s'", status.Status)
	}
}

func TestCRLCache_Response_Revoked(t *testing.T) {
	revokedSerial := big.NewInt(12345)
	crlData := createTestCRL(t, []*big.Int{revokedSerial})

	cache, err := newCRLCache(crlCacheConfig{
		fetcher:         newStaticFetcher(crlData),
		refreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	status, err := cache.Response(revokedSerial)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if status.Status != "revoked" {
		t.Errorf("Expected 'revoked', got '%s'", status.Status)
	}
	if status.Reason != 1 {
		t.Errorf("Expected reason 1, got %d", status.Reason)
	}
}

func TestCRLCache_MultipleRevoked(t *testing.T) {
	revokedSerials := []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)}
	crlData := createTestCRL(t, revokedSerials)

	cache, err := newCRLCache(crlCacheConfig{
		fetcher:         newStaticFetcher(crlData),
		refreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	for _, serial := range revokedSerials {
		if !cache.IsRevoked(serial) {
			t.Errorf("Expected serial %s to be revoked", serial)
		}
	}

	if cache.IsRevoked(big.NewInt(999)) {
		t.Error("Expected serial 999 to NOT be revoked")
	}
}

func TestCRLCache_Stats(t *testing.T) {
	revokedSerials := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	crlData := createTestCRL(t, revokedSerials)

	cache, err := newCRLCache(crlCacheConfig{
		fetcher:         newStaticFetcher(crlData),
		refreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	stats := cache.Stats()
	if stats.RevokedCount != 3 {
		t.Errorf("Expected 3 revoked, got %d", stats.RevokedCount)
	}
	if stats.LastUpdate.IsZero() {
		t.Error("LastUpdate should not be zero")
	}
}

func TestCRLCache_GetRevokedCerts(t *testing.T) {
	revokedSerials := []*big.Int{big.NewInt(10), big.NewInt(20)}
	crlData := createTestCRL(t, revokedSerials)

	cache, err := newCRLCache(crlCacheConfig{
		fetcher:         newStaticFetcher(crlData),
		refreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	certs := cache.GetRevokedCerts()
	if len(certs) != 2 {
		t.Errorf("Expected 2 revoked certs, got %d", len(certs))
	}
}

func TestCRLCache_EmptyCRL(t *testing.T) {
	crlData := createTestCRL(t, nil)

	cache, err := newCRLCache(crlCacheConfig{
		fetcher:         newStaticFetcher(crlData),
		refreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	status, _ := cache.Response(big.NewInt(12345))
	if status.Status != "good" {
		t.Errorf("Expected 'good', got '%s'", status.Status)
	}

	if cache.Stats().RevokedCount != 0 {
		t.Errorf("Expected 0 revoked, got %d", cache.Stats().RevokedCount)
	}
}

func TestCRLCache_NilFetcher(t *testing.T) {
	_, err := newCRLCache(crlCacheConfig{
		fetcher: nil,
	})
	if err == nil {
		t.Error("Expected error for nil fetcher")
	}
}

func TestCRLCache_InvalidCRL(t *testing.T) {
	_, err := newCRLCache(crlCacheConfig{
		fetcher:         newStaticFetcher([]byte("not a valid CRL")),
		refreshInterval: time.Hour,
	})
	if err == nil {
		t.Error("Expected error for invalid CRL data")
	}
}

func TestCRLCache_DefaultRefreshInterval(t *testing.T) {
	crlData := createTestCRL(t, nil)

	cache, err := newCRLCache(crlCacheConfig{
		fetcher: newStaticFetcher(crlData),
	})
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	if cache.refreshInterval != 5*time.Minute {
		t.Errorf("Expected default 5m, got %v", cache.refreshInterval)
	}
}

func TestCRLCache_Refresh(t *testing.T) {
	callCount := 0
	var crlData []byte

	// Custom fetcher that returns different data on each call
	fetcher := &dynamicFetcher{
		fetchFunc: func() ([]byte, error) {
			callCount++
			if callCount == 1 {
				crlData = createTestCRL(t, nil) // Empty CRL
			} else {
				crlData = createTestCRL(t, []*big.Int{big.NewInt(999)}) // One revoked
			}
			return crlData, nil
		},
	}

	cache, err := newCRLCache(crlCacheConfig{
		fetcher:         fetcher,
		refreshInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Initially not revoked
	if cache.IsRevoked(big.NewInt(999)) {
		t.Error("Should not be revoked initially")
	}

	// Wait for refresh
	time.Sleep(100 * time.Millisecond)

	// Now should be revoked
	if !cache.IsRevoked(big.NewInt(999)) {
		t.Error("Should be revoked after refresh")
	}
}

func TestCRLCache_FetcherError(t *testing.T) {
	_, err := newCRLCache(crlCacheConfig{
		fetcher: &errorFetcher{err: fmt.Errorf("fetch failed")},
	})
	if err == nil {
		t.Error("Expected error when fetcher fails")
	}
}

// =============================================================================
// staticFetcher Tests
// =============================================================================

func TestStaticFetcher_Success(t *testing.T) {
	data := []byte("test data")
	fetcher := newStaticFetcher(data)

	result, err := fetcher.Fetch()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if string(result) != string(data) {
		t.Errorf("Data mismatch")
	}
}

func TestStaticFetcher_NilData(t *testing.T) {
	fetcher := newStaticFetcher(nil)
	_, err := fetcher.Fetch()
	if err == nil {
		t.Error("Expected error for nil data")
	}
}

// =============================================================================
// Test Helpers
// =============================================================================

// dynamicFetcher is a test helper that calls a function to get CRL data
type dynamicFetcher struct {
	fetchFunc func() ([]byte, error)
}

func (f *dynamicFetcher) Fetch() ([]byte, error) {
	return f.fetchFunc()
}

// errorFetcher is a test helper that always returns an error
type errorFetcher struct {
	err error
}

func (f *errorFetcher) Fetch() ([]byte, error) {
	return nil, f.err
}
