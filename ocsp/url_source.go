package ocsp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"
)

// URLSource provides certificate status by fetching and caching a CRL from an HTTP(S) URL
type URLSource struct {
	*crlCache
}

// URLSourceConfig holds configuration for URLSource
type URLSourceConfig struct {
	URL                string
	RefreshInterval    time.Duration // default: 5 minutes
	Timeout            time.Duration // default: 30 seconds
	RootCAs            *x509.CertPool
	InsecureSkipVerify bool
}

// NewURLSource creates a new URL-based certificate status source
func NewURLSource(cfg URLSourceConfig) (*URLSource, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("URL is required")
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	tlsConfig := &tls.Config{
		RootCAs:            cfg.RootCAs,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	fetcher := &httpFetcher{
		url:    cfg.URL,
		client: client,
	}

	cache, err := newCRLCache(crlCacheConfig{
		fetcher:         fetcher,
		refreshInterval: cfg.RefreshInterval,
	})
	if err != nil {
		return nil, err
	}

	return &URLSource{crlCache: cache}, nil
}

// httpFetcher fetches CRL data from an HTTP(S) URL
type httpFetcher struct {
	url    string
	client *http.Client
}

// Fetch retrieves CRL data from the configured URL
func (f *httpFetcher) Fetch() ([]byte, error) {
	resp, err := f.client.Get(f.url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return io.ReadAll(resp.Body)
}
