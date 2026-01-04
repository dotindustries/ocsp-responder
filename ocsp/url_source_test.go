package ocsp

import (
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestURLSource_Success(t *testing.T) {
	crlData := createTestCRL(t, []*big.Int{big.NewInt(123)})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crlData)
	}))
	defer server.Close()

	source, err := NewURLSource(URLSourceConfig{
		URL:             server.URL,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create source: %v", err)
	}
	defer source.Close()

	if source.Stats().RevokedCount != 1 {
		t.Errorf("Expected 1 revoked, got %d", source.Stats().RevokedCount)
	}
}

func TestURLSource_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := NewURLSource(URLSourceConfig{
		URL:             server.URL,
		RefreshInterval: time.Hour,
	})
	if err == nil {
		t.Error("Expected error for server error")
	}
}

func TestURLSource_ConnectionError(t *testing.T) {
	_, err := NewURLSource(URLSourceConfig{
		URL:             "http://localhost:99999",
		RefreshInterval: time.Hour,
	})
	if err == nil {
		t.Error("Expected error for connection failure")
	}
}

func TestURLSource_EmptyURL(t *testing.T) {
	_, err := NewURLSource(URLSourceConfig{
		URL: "",
	})
	if err == nil {
		t.Error("Expected error for empty URL")
	}
}

func TestURLSource_Revoked(t *testing.T) {
	revokedSerial := big.NewInt(42)
	crlData := createTestCRL(t, []*big.Int{revokedSerial})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crlData)
	}))
	defer server.Close()

	source, err := NewURLSource(URLSourceConfig{
		URL:             server.URL,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create source: %v", err)
	}
	defer source.Close()

	if !source.IsRevoked(revokedSerial) {
		t.Error("Expected serial 42 to be revoked")
	}
}

func TestURLSource_Response(t *testing.T) {
	revokedSerial := big.NewInt(555)
	crlData := createTestCRL(t, []*big.Int{revokedSerial})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crlData)
	}))
	defer server.Close()

	source, err := NewURLSource(URLSourceConfig{
		URL:             server.URL,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create source: %v", err)
	}
	defer source.Close()

	// Check revoked
	status, err := source.Response(revokedSerial)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if status.Status != "revoked" {
		t.Errorf("Expected 'revoked', got '%s'", status.Status)
	}

	// Check good
	status, err = source.Response(big.NewInt(999))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if status.Status != "good" {
		t.Errorf("Expected 'good', got '%s'", status.Status)
	}
}
