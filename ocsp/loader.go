package ocsp

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// isURL returns true if the path looks like an HTTP(S) URL
func isURL(path string) bool {
	return strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://")
}

// LoadPEM loads PEM data from a file path or URL.
// If path starts with http:// or https://, it fetches via HTTP GET.
// Otherwise, it reads from the local filesystem.
func LoadPEM(path string, insecureSkipVerify bool) ([]byte, error) {
	if isURL(path) {
		return loadPEMFromURL(path, insecureSkipVerify)
	}
	return loadPEMFromFile(path)
}

// loadPEMFromFile reads PEM data from a local file
func loadPEMFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return data, nil
}

// loadPEMFromURL fetches PEM data from an HTTP(S) URL
func loadPEMFromURL(url string, insecureSkipVerify bool) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecureSkipVerify,
			},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from URL %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d fetching %s: %s", resp.StatusCode, url, resp.Status)
	}

	// Limit response size to prevent memory exhaustion (10MB should be plenty for certs)
	const maxSize = 10 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response from %s: %w", url, err)
	}

	return data, nil
}
