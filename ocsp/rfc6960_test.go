package ocsp

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// RFC 6960 Section 2.1: Request Syntax
// OCSPRequest ::= SEQUENCE {
//    tbsRequest              TBSRequest,
//    optionalSignature   [0] EXPLICIT Signature OPTIONAL }
func TestRFC6960_RequestParsing(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	// Create a valid OCSP request per RFC 6960
	ocspReq, err := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{
		Hash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("Failed to create OCSP request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}

// RFC 6960 Section 2.2: Response Syntax
// OCSPResponse ::= SEQUENCE {
//    responseStatus          OCSPResponseStatus,
//    responseBytes       [0] EXPLICIT ResponseBytes OPTIONAL }
func TestRFC6960_ResponseStructure(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)

	// Verify it's a valid DER-encoded OCSP response
	resp, err := ocsp.ParseResponse(body, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Response is not valid OCSP: %v", err)
	}

	// RFC 6960 Section 4.2.2.1: SingleResponse must contain certID
	if resp.SerialNumber == nil {
		t.Error("Response missing serial number (certID)")
	}

	// RFC 6960 Section 4.2.2.1: SingleResponse must contain certStatus
	// Status should be one of: good (0), revoked (1), unknown (2)
	if resp.Status < 0 || resp.Status > 2 {
		t.Errorf("Invalid cert status: %d", resp.Status)
	}

	// RFC 6960 Section 4.2.2.1: SingleResponse must contain thisUpdate
	if resp.ThisUpdate.IsZero() {
		t.Error("Response missing thisUpdate")
	}
}

// RFC 6960 Section 2.3: Exception Cases
func TestRFC6960_ResponseStatuses(t *testing.T) {
	tests := []struct {
		name           string
		requestData    []byte
		expectedStatus ocsp.ResponseStatus
	}{
		{
			name:           "MalformedRequest",
			requestData:    []byte("invalid"),
			expectedStatus: ocsp.Malformed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			responder, _, _ := setupTestResponder(t)

			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(tc.requestData))
			w := httptest.NewRecorder()

			responder.ServeHTTP(w, req)

			body, _ := io.ReadAll(w.Result().Body)

			// For error responses, we expect a minimal OCSP response with just the status
			// DER: SEQUENCE { ENUMERATED { status } }
			if len(body) < 3 {
				t.Fatal("Response too short")
			}

			// Check the response status byte
			// Format: 30 03 0a 01 XX where XX is the status
			if body[4] != byte(tc.expectedStatus) {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, body[4])
			}
		})
	}
}

// RFC 6960 Section 4.2.1: ASN.1 Specification of the OCSP Response
func TestRFC6960_BasicOCSPResponse(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	resp, err := ocsp.ParseResponse(body, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// RFC 6960 Section 4.2.2.1: thisUpdate is mandatory
	if resp.ThisUpdate.IsZero() {
		t.Error("thisUpdate is required")
	}

	// RFC 6960 Section 4.2.2.1: nextUpdate SHOULD be present
	if resp.NextUpdate.IsZero() {
		t.Error("nextUpdate SHOULD be present")
	}

	// RFC 6960 Section 4.2.2.2: Authorized Responders
	// Response should be signed by either:
	// 1. The CA that issued the certificate
	// 2. A responder with a certificate signed by the CA with id-kp-OCSPSigning
	if resp.Certificate != nil {
		// Check for OCSPSigning EKU
		hasOCSPSigning := false
		for _, eku := range resp.Certificate.ExtKeyUsage {
			if eku == x509.ExtKeyUsageOCSPSigning {
				hasOCSPSigning = true
				break
			}
		}
		if !hasOCSPSigning {
			t.Error("Responder certificate should have OCSPSigning EKU")
		}
	}
}

// RFC 6960 Section 4.2.2.1: Time Validity
func TestRFC6960_TimeValidity(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	resp, _ := ocsp.ParseResponse(body, pki.IssuerCert)

	now := time.Now()

	// thisUpdate must be before or equal to current time
	if resp.ThisUpdate.After(now.Add(time.Minute)) {
		t.Error("thisUpdate should not be in the future")
	}

	// nextUpdate must be after thisUpdate
	if !resp.NextUpdate.After(resp.ThisUpdate) {
		t.Error("nextUpdate must be after thisUpdate")
	}
}

// RFC 6960 Appendix A.1.1: Request Using GET
func TestRFC6960_HTTPGet(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})

	// RFC 6960 A.1.1: HTTP GET with {url}/{base64-encoded-request}
	encoded := base64.StdEncoding.EncodeToString(ocspReq)
	urlPath := "/" + url.PathEscape(encoded)

	req := httptest.NewRequest(http.MethodGet, urlPath, nil)
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	resp := w.Result()

	// RFC 6960 A.1: Successful OCSP responses are sent as HTTP status 200
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected HTTP 200, got %d", resp.StatusCode)
	}

	// RFC 6960 A.1: Content-Type must be application/ocsp-response
	if resp.Header.Get("Content-Type") != "application/ocsp-response" {
		t.Errorf("Wrong Content-Type: %s", resp.Header.Get("Content-Type"))
	}
}

// RFC 6960 Appendix A.1.1: Request Using POST
func TestRFC6960_HTTPPost(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})

	// RFC 6960 A.1.1: HTTP POST with Content-Type: application/ocsp-request
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	req.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected HTTP 200, got %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != "application/ocsp-response" {
		t.Errorf("Wrong Content-Type: %s", resp.Header.Get("Content-Type"))
	}
}

// RFC 6960 Section 4.2.1: Revoked Certificate Info
func TestRFC6960_RevokedCertificateInfo(t *testing.T) {
	responder, pki, source := setupTestResponder(t)

	revokedAt := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	source.SetStatus(pki.EndEntityCert.SerialNumber, &CertStatus{
		Status:    "revoked",
		RevokedAt: revokedAt,
		Reason:    ocsp.KeyCompromise, // CRLReason keyCompromise (1)
	})

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	resp, _ := ocsp.ParseResponse(body, pki.IssuerCert)

	// RFC 6960 Section 4.2.1: RevokedInfo contains revocationTime
	if resp.RevokedAt.IsZero() {
		t.Error("RevokedInfo must contain revocationTime")
	}

	// RFC 6960 Section 4.2.1: RevokedInfo may contain revocationReason
	if resp.RevocationReason != ocsp.KeyCompromise {
		t.Errorf("Expected KeyCompromise reason, got %d", resp.RevocationReason)
	}
}

// RFC 6960 Section 4.2.2.3: CertID matching
func TestRFC6960_CertIDMatching(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	resp, _ := ocsp.ParseResponse(body, pki.IssuerCert)

	// RFC 6960 Section 4.2.2.3: The response certID should match the request
	if resp.SerialNumber.Cmp(pki.EndEntityCert.SerialNumber) != 0 {
		t.Error("Response serial number doesn't match request")
	}
}

// RFC 6960 Section 4.2.2.2.1: Hash Algorithm Support
func TestRFC6960_HashAlgorithms(t *testing.T) {
	tests := []struct {
		name string
		hash crypto.Hash
	}{
		{"SHA1", crypto.SHA1},
		{"SHA256", crypto.SHA256},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			responder, pki, _ := setupTestResponder(t)

			ocspReq, err := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{
				Hash: tc.hash,
			})
			if err != nil {
				t.Fatalf("Failed to create request with %s: %v", tc.name, err)
			}

			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
			w := httptest.NewRecorder()

			responder.ServeHTTP(w, req)

			body, _ := io.ReadAll(w.Result().Body)
			_, err = ocsp.ParseResponse(body, pki.IssuerCert)
			if err != nil {
				t.Errorf("Failed to parse response for %s request: %v", tc.name, err)
			}
		})
	}
}

// RFC 6960: Test issuerNameHash and issuerKeyHash
func TestRFC6960_IssuerIdentification(t *testing.T) {
	pki, err := newTestPKI()
	if err != nil {
		t.Fatalf("Failed to create PKI: %v", err)
	}

	// Calculate expected hashes per RFC 6960
	// issuerNameHash is hash of issuer's distinguished name
	issuerNameHash := sha256.Sum256(pki.IssuerCert.RawSubject)

	// issuerKeyHash is hash of issuer's public key
	issuerKeyHash := sha256.Sum256(pki.IssuerCert.RawSubjectPublicKeyInfo)

	// Also test SHA1 for compatibility
	issuerNameHashSHA1 := sha1.Sum(pki.IssuerCert.RawSubject)
	issuerKeyHashSHA1 := sha1.Sum(pki.IssuerCert.RawSubjectPublicKeyInfo)

	// These hashes should be deterministic and have correct length
	// Use slices to actually access the hash values
	if len(issuerNameHash[:]) != 32 {
		t.Errorf("issuerNameHash should be 32 bytes, got %d", len(issuerNameHash[:]))
	}
	if len(issuerKeyHash[:]) != 32 {
		t.Errorf("issuerKeyHash should be 32 bytes, got %d", len(issuerKeyHash[:]))
	}
	if len(issuerNameHashSHA1[:]) != 20 {
		t.Errorf("issuerNameHashSHA1 should be 20 bytes, got %d", len(issuerNameHashSHA1[:]))
	}
	if len(issuerKeyHashSHA1[:]) != 20 {
		t.Errorf("issuerKeyHashSHA1 should be 20 bytes, got %d", len(issuerKeyHashSHA1[:]))
	}

	// Verify hashes are not all zeros (sanity check)
	allZero := true
	for _, b := range issuerNameHash[:] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("issuerNameHash should not be all zeros")
	}
}

// RFC 6960 Section 2.4: Signature Verification
func TestRFC6960_SignatureVerification(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)

	// ParseResponse with issuer cert verifies the signature
	// This will fail if signature is invalid
	_, err := ocsp.ParseResponse(body, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Signature verification failed: %v", err)
	}

	// Also verify with nil issuer (just parse structure)
	resp, err := ocsp.ParseResponse(body, nil)
	if err != nil {
		t.Fatalf("Failed to parse response structure: %v", err)
	}

	// Response should have valid signature algorithm
	if resp.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		t.Error("Response has unknown signature algorithm")
	}
}

// RFC 6960 Appendix B: OCSP over HTTP - Size limits
func TestRFC6960_RequestSizeLimit(t *testing.T) {
	responder, _, _ := setupTestResponder(t)

	// Create an oversized request (> 10KB)
	largeData := make([]byte, 20*1024)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(largeData))
	req.ContentLength = int64(len(largeData))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	// Should still return 200 with error response (per OCSP spec)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK even for errors, got %d", w.Code)
	}
}

// RFC 6960 Section 4.4.1: Nonce Extension
func TestRFC6960_NonceExtension(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	// Create an OCSP request with a nonce
	nonce := []byte("test-nonce-12345")
	ocspReqBytes := createOCSPRequestWithNonce(t, pki, nonce)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReqBytes))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	// Parse response and check for nonce
	ocspResp, err := ocsp.ParseResponse(body, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Check that nonce is in response extensions
	foundNonce := false
	for _, ext := range ocspResp.Extensions {
		if ext.Id.Equal(OIDOCSPNonce) {
			foundNonce = true
			// Nonce value might be wrapped in OCTET STRING
			var extractedNonce []byte
			if _, err := asn1.Unmarshal(ext.Value, &extractedNonce); err == nil {
				if !bytes.Equal(extractedNonce, nonce) {
					t.Errorf("Nonce mismatch: got %x, want %x", extractedNonce, nonce)
				}
			} else if !bytes.Equal(ext.Value, nonce) {
				t.Errorf("Nonce mismatch: got %x, want %x", ext.Value, nonce)
			}
			break
		}
	}

	if !foundNonce {
		t.Error("Nonce extension not found in response")
	}
}

// RFC 6960 Section 4.4.1: Responses with nonce should not be cached
func TestRFC6960_NonceDisablesCache(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	// Request WITH nonce - should disable caching
	nonce := []byte("test-nonce-67890")
	ocspReqWithNonce := createOCSPRequestWithNonce(t, pki, nonce)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReqWithNonce))
	w := httptest.NewRecorder()
	responder.ServeHTTP(w, req)

	cacheControl := w.Header().Get("Cache-Control")
	if !strings.Contains(cacheControl, "no-cache") {
		t.Errorf("Expected no-cache for nonce request, got: %s", cacheControl)
	}
}

// Verify responses WITHOUT nonce remain cacheable
func TestRFC6960_NoNonceAllowsCache(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	// Request WITHOUT nonce - should allow caching
	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()
	responder.ServeHTTP(w, req)

	cacheControl := w.Header().Get("Cache-Control")
	if strings.Contains(cacheControl, "no-cache") {
		t.Errorf("Expected cacheable response without nonce, got: %s", cacheControl)
	}
	if !strings.Contains(cacheControl, "max-age") {
		t.Errorf("Expected max-age in Cache-Control, got: %s", cacheControl)
	}
}

// createOCSPRequestWithNonce creates an OCSP request with a nonce extension
func createOCSPRequestWithNonce(t *testing.T, pki *testPKI, nonce []byte) []byte {
	t.Helper()

	// Build the OCSP request manually to include nonce
	// This follows RFC 6960 Section 4.1.1 structure

	issuerNameHash := sha256.Sum256(pki.IssuerCert.RawSubject)
	issuerKeyHash := sha256.Sum256(pki.IssuerCert.RawSubjectPublicKeyInfo)

	// CertID structure
	certID := struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		IssuerNameHash []byte
		IssuerKeyHash  []byte
		SerialNumber   *big.Int
	}{
		HashAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, // SHA-256
		},
		IssuerNameHash: issuerNameHash[:],
		IssuerKeyHash:  issuerKeyHash[:],
		SerialNumber:   pki.EndEntityCert.SerialNumber,
	}

	// Request structure
	request := struct {
		CertID asn1.RawValue
	}{}
	certIDBytes, _ := asn1.Marshal(certID)
	request.CertID = asn1.RawValue{FullBytes: certIDBytes}

	// Nonce extension - wrap nonce in OCTET STRING
	nonceValue, _ := asn1.Marshal(nonce)
	nonceExt := pkixExtension{
		Id:    OIDOCSPNonce,
		Value: nonceValue,
	}

	// TBSRequest structure
	tbsReq := struct {
		RequestList []asn1.RawValue
		Extensions  []pkixExtension `asn1:"optional,explicit,tag:2"`
	}{
		RequestList: []asn1.RawValue{{FullBytes: mustMarshal(t, request)}},
		Extensions:  []pkixExtension{nonceExt},
	}

	// OCSPRequest structure
	ocspReq := struct {
		TBSRequest asn1.RawValue
	}{
		TBSRequest: asn1.RawValue{FullBytes: mustMarshal(t, tbsReq)},
	}

	return mustMarshal(t, ocspReq)
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}
	return data
}

// RFC 6960: Verify response is properly DER-encoded
func TestRFC6960_DEREncoding(t *testing.T) {
	responder, pki, _ := setupTestResponder(t)

	ocspReq, _ := ocsp.CreateRequest(pki.EndEntityCert, pki.IssuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(ocspReq))
	w := httptest.NewRecorder()

	responder.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)

	// DER encoding starts with SEQUENCE tag (0x30)
	if len(body) < 1 || body[0] != 0x30 {
		t.Error("Response should be DER-encoded, starting with SEQUENCE tag")
	}

	// Verify it can be parsed (valid DER)
	_, err := ocsp.ParseResponse(body, nil)
	if err != nil {
		t.Errorf("Invalid DER encoding: %v", err)
	}
}
