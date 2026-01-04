package ocsp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestIsURL(t *testing.T) {
	tests := []struct {
		path  string
		isURL bool
	}{
		{"http://example.com/cert.pem", true},
		{"https://example.com/cert.pem", true},
		{"HTTP://example.com/cert.pem", false}, // case sensitive
		{"/path/to/cert.pem", false},
		{"./cert.pem", false},
		{"cert.pem", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got := isURL(tc.path); got != tc.isURL {
				t.Errorf("isURL(%q) = %v, want %v", tc.path, got, tc.isURL)
			}
		})
	}
}

func TestLoadPEM_File(t *testing.T) {
	dir := t.TempDir()
	testData := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
	testFile := filepath.Join(dir, "test.pem")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	data, err := LoadPEM(testFile, false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if string(data) != string(testData) {
		t.Errorf("Data mismatch: got %q, want %q", string(data), string(testData))
	}
}

func TestLoadPEM_FileNotFound(t *testing.T) {
	_, err := LoadPEM("/nonexistent/path/to/cert.pem", false)
	if err == nil {
		t.Error("Expected error for missing file")
	}
}

func TestLoadPEM_URL(t *testing.T) {
	testData := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(testData)
	}))
	defer server.Close()

	data, err := LoadPEM(server.URL+"/cert.pem", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if string(data) != string(testData) {
		t.Errorf("Data mismatch: got %q, want %q", string(data), string(testData))
	}
}

func TestLoadPEM_URL_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := LoadPEM(server.URL+"/cert.pem", false)
	if err == nil {
		t.Error("Expected error for server error")
	}
}

func TestLoadPEM_URL_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := LoadPEM(server.URL+"/cert.pem", false)
	if err == nil {
		t.Error("Expected error for 404")
	}
}

func TestLoadPEM_URL_ConnectionError(t *testing.T) {
	_, err := LoadPEM("http://localhost:99999/cert.pem", false)
	if err == nil {
		t.Error("Expected error for connection failure")
	}
}

func TestNewSignerFromPaths_Files(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	signer, err := NewSignerFromPaths(files.issuerFile, files.responderFile, files.keyFile, 0, false)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	if signer == nil {
		t.Fatal("Signer is nil")
	}
}

func TestNewSignerFromPaths_IssuerFromURL(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	// Read the issuer file and serve it via HTTP
	issuerData, err := os.ReadFile(files.issuerFile)
	if err != nil {
		t.Fatalf("Failed to read issuer file: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(issuerData)
	}))
	defer server.Close()

	// Load issuer from URL, responder and key from files
	signer, err := NewSignerFromPaths(server.URL+"/issuer.pem", files.responderFile, files.keyFile, 0, false)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	if signer == nil {
		t.Fatal("Signer is nil")
	}
}

func TestNewSignerFromPaths_BothCertsFromURL(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	// Read both cert files
	issuerData, err := os.ReadFile(files.issuerFile)
	if err != nil {
		t.Fatalf("Failed to read issuer file: %v", err)
	}
	responderData, err := os.ReadFile(files.responderFile)
	if err != nil {
		t.Fatalf("Failed to read responder file: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/issuer.pem" {
			_, _ = w.Write(issuerData)
		} else {
			_, _ = w.Write(responderData)
		}
	}))
	defer server.Close()

	// Load both certs from URL, key from file
	signer, err := NewSignerFromPaths(server.URL+"/issuer.pem", server.URL+"/responder.pem", files.keyFile, 0, false)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	if signer == nil {
		t.Fatal("Signer is nil")
	}
}

func TestNewSignerFromPaths_InvalidIssuerURL(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := NewSignerFromPaths(server.URL+"/issuer.pem", files.responderFile, files.keyFile, 0, false)
	if err == nil {
		t.Error("Expected error for 404 on issuer URL")
	}
}

func TestNewSignerFromPaths_InvalidCertData(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not a valid certificate"))
	}))
	defer server.Close()

	_, err := NewSignerFromPaths(server.URL+"/issuer.pem", files.responderFile, files.keyFile, 0, false)
	if err == nil {
		t.Error("Expected error for invalid certificate data")
	}
}

func TestNewSignerFromPaths_MissingKeyFile(t *testing.T) {
	files := createTestFiles(t)
	defer files.cleanup()

	_, err := NewSignerFromPaths(files.issuerFile, files.responderFile, "/nonexistent/key.pem", 0, false)
	if err == nil {
		t.Error("Expected error for missing key file")
	}
}
