package ocsp

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileSource_Success(t *testing.T) {
	crlData := createTestCRL(t, []*big.Int{big.NewInt(456)})

	dir := t.TempDir()
	crlPath := filepath.Join(dir, "test.crl")
	if err := os.WriteFile(crlPath, crlData, 0644); err != nil {
		t.Fatalf("Failed to write CRL file: %v", err)
	}

	source, err := NewFileSource(FileSourceConfig{
		Path:            crlPath,
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

func TestFileSource_FileNotFound(t *testing.T) {
	_, err := NewFileSource(FileSourceConfig{
		Path:            "/nonexistent/path/to/crl",
		RefreshInterval: time.Hour,
	})
	if err == nil {
		t.Error("Expected error for missing file")
	}
}

func TestFileSource_EmptyPath(t *testing.T) {
	_, err := NewFileSource(FileSourceConfig{
		Path: "",
	})
	if err == nil {
		t.Error("Expected error for empty path")
	}
}

func TestFileSource_Revoked(t *testing.T) {
	revokedSerial := big.NewInt(789)
	crlData := createTestCRL(t, []*big.Int{revokedSerial})

	dir := t.TempDir()
	crlPath := filepath.Join(dir, "test.crl")
	os.WriteFile(crlPath, crlData, 0644)

	source, err := NewFileSource(FileSourceConfig{
		Path:            crlPath,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create source: %v", err)
	}
	defer source.Close()

	if !source.IsRevoked(revokedSerial) {
		t.Error("Expected serial 789 to be revoked")
	}
}

func TestFileSource_Response(t *testing.T) {
	revokedSerial := big.NewInt(321)
	crlData := createTestCRL(t, []*big.Int{revokedSerial})

	dir := t.TempDir()
	crlPath := filepath.Join(dir, "test.crl")
	os.WriteFile(crlPath, crlData, 0644)

	source, err := NewFileSource(FileSourceConfig{
		Path:            crlPath,
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

func TestFileSource_MultipleRevoked(t *testing.T) {
	revokedSerials := []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)}
	crlData := createTestCRL(t, revokedSerials)

	dir := t.TempDir()
	crlPath := filepath.Join(dir, "test.crl")
	os.WriteFile(crlPath, crlData, 0644)

	source, err := NewFileSource(FileSourceConfig{
		Path:            crlPath,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create source: %v", err)
	}
	defer source.Close()

	for _, serial := range revokedSerials {
		if !source.IsRevoked(serial) {
			t.Errorf("Expected serial %s to be revoked", serial)
		}
	}

	if source.IsRevoked(big.NewInt(999)) {
		t.Error("Expected serial 999 to NOT be revoked")
	}
}
