package ocsp

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func setupTestResponder(t *testing.T) (*Responder, *testPKI, *InMemorySource) {
	t.Helper()

	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create test PKI: %v", err)
	}

	signer, err := NewSigner(pki.IssuerCert, pki.ResponderCert, pki.ResponderKey, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	source := NewInMemorySource()
	responder := NewResponder(source, signer)

	return responder, pki, source
}

// RFC 6960 Section 4.1.1: OCSP requests via HTTP POST
func TestResponder_POST(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	// Create OCSP request
	ocspReq, err := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{
		Hash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("Failed to create OCSP request: %v", err)
	}

	// RFC 6960 Appendix A.1: HTTP POST with application/ocsp-request content type
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	req.Header.Set("Content-Type", "application/ocsp-request")

	w := httptest.NewRecorder()
	responder.ServeHTTP(w, req)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	// RFC 6960 Appendix A.1: Successful response should be 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// RFC 6960 Appendix A.1: Response content type must be application/ocsp-response
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/ocsp-response" {
		t.Errorf("Expected Content-Type application/ocsp-response, got %s", contentType)
	}

	// Parse and verify the response
	body, _ := io.ReadAll(resp.Body)
	ocspResp, err := ocsp.ParseResponse(body, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}

	if ocspResp.Status != ocsp.Good {
		t.Errorf("Expected Good status, got %d", ocspResp.Status)
	}
}

// RFC 6960 Appendix A.1: OCSP requests via HTTP GET
func TestResponder_GET(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	// Create OCSP request
	ocspReq, err := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{
		Hash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("Failed to create OCSP request: %v", err)
	}

	// RFC 6960 Appendix A.1: GET request with base64-encoded request in URL path
	encoded := base64.StdEncoding.EncodeToString(ocspReq)
	urlEncoded := url.PathEscape(encoded)

	req := httptest.NewRequest(http.MethodGet, "/"+urlEncoded, nil)

	w := httptest.NewRecorder()
	responder.ServeHTTP(w, req)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/ocsp-response" {
		t.Errorf("Expected Content-Type application/ocsp-response, got %s", contentType)
	}

	body, _ := io.ReadAll(resp.Body)
	ocspResp, err := ocsp.ParseResponse(body, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}

	if ocspResp.Status != ocsp.Good {
		t.Errorf("Expected Good status, got %d", ocspResp.Status)
	}
}

// RFC 6960 Section 2.3: Certificate status - good
func TestResponder_StatusGood(t *testing.T) {
	responder, pki, source := setupTestResponder(t)

	// Explicitly set status to good
	source.SetStatus(pki.EndEntityCert.SerialNumber, &CertStatus{Status: "good"})

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	ocspResp, err := ocsp.ParseResponse(body, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if ocspResp.Status != ocsp.Good {
		t.Errorf("Expected Good status, got %d", ocspResp.Status)
	}
}

// RFC 6960 Section 2.3: Certificate status - revoked
func TestResponder_StatusRevoked(t *testing.T) {
	responder, pki, source := setupTestResponder(t)

	revokedAt := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
	source.SetStatus(pki.EndEntityCert.SerialNumber, &CertStatus{
		Status:    "revoked",
		RevokedAt: revokedAt,
		Reason:    ocsp.KeyCompromise,
	})

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	ocspResp, err := ocsp.ParseResponse(body, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if ocspResp.Status != ocsp.Revoked {
		t.Errorf("Expected Revoked status, got %d", ocspResp.Status)
	}

	if ocspResp.RevocationReason != ocsp.KeyCompromise {
		t.Errorf("Expected KeyCompromise reason, got %d", ocspResp.RevocationReason)
	}
}

// RFC 6960 Section 2.3: Certificate status - unknown
func TestResponder_StatusUnknown(t *testing.T) {
	responder, pki, source := setupTestResponder(t)

	source.SetStatus(pki.EndEntityCert.SerialNumber, &CertStatus{Status: "unknown"})

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	ocspResp, err := ocsp.ParseResponse(body, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if ocspResp.Status != ocsp.Unknown {
		t.Errorf("Expected Unknown status, got %d", ocspResp.Status)
	}
}

// RFC 6960 Appendix A.1: Method not allowed
func TestResponder_MethodNotAllowed(t *testing.T) {
	responder, _, _ := setupTestResponder(t)

	req := httptest.NewRequest(http.MethodPut, "/", nil)
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

// RFC 6960 Section 2.3: Malformed request error
func TestResponder_MalformedRequest(t *testing.T) {
	responder, _, _ := setupTestResponder(t)

	// Send garbage data
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("not a valid ocsp request")))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	// RFC 6960: Even errors should return 200 OK with error in OCSP response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for OCSP error, got %d", resp.StatusCode)
	}

	// Check content type
	if resp.Header.Get("Content-Type") != "application/ocsp-response" {
		t.Errorf("Expected application/ocsp-response content type")
	}
}

// RFC 6960 Appendix A.1: Cache-Control header
func TestResponder_CacheHeaders(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	resp := w.Result()
	cacheControl := resp.Header.Get("Cache-Control")

	if cacheControl == "" {
		t.Error("Expected Cache-Control header to be set")
	}

	// Check for expected cache directives
	if !bytes.Contains([]byte(cacheControl), []byte("max-age")) {
		t.Error("Expected max-age in Cache-Control header")
	}
}

// Test InMemorySource
func TestInMemorySource(t *testing.T) {
	source := NewInMemorySource()

	serial := big.NewInt(12345)

	// Test default response (not found = good)
	status, err := source.Response(serial)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if status.Status != "good" {
		t.Errorf("Expected default status 'good', got '%s'", status.Status)
	}

	// Test setting and retrieving status
	source.SetStatus(serial, &CertStatus{
		Status:    "revoked",
		RevokedAt: time.Now(),
		Reason:    ocsp.KeyCompromise,
	})

	status, err = source.Response(serial)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if status.Status != "revoked" {
		t.Errorf("Expected status 'revoked', got '%s'", status.Status)
	}
}

// Test concurrent access to InMemorySource
func TestInMemorySource_Concurrent(t *testing.T) {
	source := NewInMemorySource()

	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			serial := big.NewInt(int64(i))
			source.SetStatus(serial, &CertStatus{Status: "good"})
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			serial := big.NewInt(int64(i))
			_, _ = source.Response(serial)
		}
		done <- true
	}()

	<-done
	<-done
}

// RFC 6960: Test all revocation reasons
func TestResponder_AllRevocationReasons(t *testing.T) {
	reasons := []struct {
		name   string
		reason int
	}{
		{"Unspecified", ocsp.Unspecified},
		{"KeyCompromise", ocsp.KeyCompromise},
		{"CACompromise", ocsp.CACompromise},
		{"AffiliationChanged", ocsp.AffiliationChanged},
		{"Superseded", ocsp.Superseded},
		{"CessationOfOperation", ocsp.CessationOfOperation},
		{"CertificateHold", ocsp.CertificateHold},
		{"RemoveFromCRL", ocsp.RemoveFromCRL},
		{"PrivilegeWithdrawn", ocsp.PrivilegeWithdrawn},
		{"AACompromise", ocsp.AACompromise},
	}

	for _, tc := range reasons {
		t.Run(tc.name, func(t *testing.T) {
			responder, pki, source := setupTestResponder(t)

			source.SetStatus(pki.EndEntityCert.SerialNumber, &CertStatus{
				Status:    "revoked",
				RevokedAt: time.Now(),
				Reason:    tc.reason,
			})

			ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
			w := httptest.NewRecorder()

			responder.ServeHTTP(w, req)

			body, _ := io.ReadAll(w.Result().Body)
			ocspResp, err := ocsp.ParseResponse(body, pki.IssuerCert)
			if err != nil {
				t.Fatalf("Failed to parse response: %v", err)
			}

			if ocspResp.RevocationReason != tc.reason {
				t.Errorf("Expected reason %d, got %d", tc.reason, ocspResp.RevocationReason)
			}
		})
	}
}

// Test GET request with invalid base64
func TestResponder_GET_InvalidBase64(t *testing.T) {
	responder, _, _ := setupTestResponder(t)

	// Invalid base64 (contains invalid characters)
	req := httptest.NewRequest(http.MethodGet, "/not-valid-base64!!!", nil)
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	// Should return 200 with OCSP error response (Malformed)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	if w.Header().Get("Content-Type") != "application/ocsp-response" {
		t.Error("Expected OCSP response content type")
	}
}

// Test GET request with valid base64 but invalid OCSP request
func TestResponder_GET_InvalidOCSPRequest(t *testing.T) {
	responder, _, _ := setupTestResponder(t)

	// Valid base64, but not a valid OCSP request
	encoded := base64.StdEncoding.EncodeToString([]byte("not an ocsp request"))
	req := httptest.NewRequest(http.MethodGet, "/"+url.PathEscape(encoded), nil)
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

// ErrorSource is a Source that always returns an error
type ErrorSource struct {
	err error
}

func (e *ErrorSource) Response(serial *big.Int) (*CertStatus, error) {
	return nil, e.err
}

func (e *ErrorSource) Stats() CRLStats {
	return CRLStats{}
}

// Test source returning an error
func TestResponder_SourceError(t *testing.T) {
	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create test PKI: %v", err)
	}

	signer, _ := NewSigner(pki.IssuerCert, pki.ResponderCert, pki.ResponderKey, time.Hour)

	// Use error source
	source := &ErrorSource{err: io.ErrUnexpectedEOF}
	responder := NewResponder(source, signer)

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	// Should return 200 with OCSP InternalError
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Check it's an OCSP response
	if w.Header().Get("Content-Type") != "application/ocsp-response" {
		t.Error("Expected OCSP response content type")
	}

	// Check the response contains InternalError (status 2)
	body := w.Body.Bytes()
	if len(body) < 5 || body[4] != 2 {
		t.Error("Expected InternalError status in response")
	}
}

// Test extractNonce with various edge cases
func TestExtractNonce_EdgeCases(t *testing.T) {
	// Empty input
	if nonce := extractNonce(nil); nonce != nil {
		t.Error("Expected nil for empty input")
	}

	// Invalid ASN.1
	if nonce := extractNonce([]byte("not asn1")); nonce != nil {
		t.Error("Expected nil for invalid ASN.1")
	}

	// Valid ASN.1 but wrong structure
	if nonce := extractNonce([]byte{0x30, 0x00}); nonce != nil {
		t.Error("Expected nil for empty sequence")
	}
}

// Test empty POST body
func TestResponder_POST_EmptyBody(t *testing.T) {
	responder, _, _ := setupTestResponder(t)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte{}))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	// Should return 200 with OCSP error
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}
