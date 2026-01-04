package ocsp

import (
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"
)

// CRLStats contains statistics about the CRL cache
type CRLStats struct {
	RevokedCount int
	LastUpdate   time.Time
	NextUpdate   time.Time
}

// RevokedCertEntry holds revocation details for a certificate
type RevokedCertEntry struct {
	SerialNumber *big.Int
	RevokedAt    time.Time
	ReasonCode   int
}

// crlFetcher is an interface for fetching CRL data from various sources
type crlFetcher interface {
	Fetch() ([]byte, error)
}

// crlCache provides certificate status by maintaining a cached CRL
// This is the internal implementation used by URLSource and FileSource
type crlCache struct {
	fetcher         crlFetcher
	refreshInterval time.Duration

	mu           sync.RWMutex
	revokedCerts map[string]*RevokedCertEntry
	lastUpdate   time.Time
	crl          *x509.RevocationList

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// crlCacheConfig holds configuration for the CRL cache
type crlCacheConfig struct {
	fetcher         crlFetcher
	refreshInterval time.Duration // default: 5 minutes
}

// newCRLCache creates a new CRL cache
func newCRLCache(cfg crlCacheConfig) (*crlCache, error) {
	if cfg.fetcher == nil {
		return nil, fmt.Errorf("CRL fetcher is required")
	}

	if cfg.refreshInterval == 0 {
		cfg.refreshInterval = 5 * time.Minute
	}

	c := &crlCache{
		fetcher:         cfg.fetcher,
		refreshInterval: cfg.refreshInterval,
		revokedCerts:    make(map[string]*RevokedCertEntry),
		stopCh:          make(chan struct{}),
	}

	// Initial CRL fetch
	if err := c.refresh(); err != nil {
		return nil, fmt.Errorf("initial CRL fetch failed: %w", err)
	}

	// Start background refresh
	c.wg.Add(1)
	go c.refreshLoop()

	return c, nil
}

// Response returns the certificate status by checking the cached CRL
func (c *crlCache) Response(serial *big.Int) (*CertStatus, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.revokedCerts[serial.String()]
	if !exists {
		return &CertStatus{Status: "good"}, nil
	}

	return &CertStatus{
		Status:    "revoked",
		RevokedAt: entry.RevokedAt,
		Reason:    entry.ReasonCode,
	}, nil
}

// refresh fetches the CRL and updates the cache
func (c *crlCache) refresh() error {
	data, err := c.fetcher.Fetch()
	if err != nil {
		return fmt.Errorf("failed to fetch CRL: %w", err)
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Build new revocation map
	newRevokedCerts := make(map[string]*RevokedCertEntry, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		newRevokedCerts[entry.SerialNumber.String()] = &RevokedCertEntry{
			SerialNumber: entry.SerialNumber,
			RevokedAt:    entry.RevocationTime,
			ReasonCode:   entry.ReasonCode,
		}
	}

	// Update cache
	c.mu.Lock()
	c.revokedCerts = newRevokedCerts
	c.crl = crl
	c.lastUpdate = time.Now()
	c.mu.Unlock()

	log.Printf("CRL refreshed: %d revoked certificates", len(newRevokedCerts))
	return nil
}

// refreshLoop periodically refreshes the CRL
func (c *crlCache) refreshLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.refresh(); err != nil {
				log.Printf("CRL refresh error: %v", err)
			}
		case <-c.stopCh:
			return
		}
	}
}

// Close stops the background refresh and cleans up
func (c *crlCache) Close() error {
	close(c.stopCh)
	c.wg.Wait()
	return nil
}

// Stats returns statistics about the CRL cache
func (c *crlCache) Stats() CRLStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var nextUpdate time.Time
	if c.crl != nil {
		nextUpdate = c.crl.NextUpdate
	}

	return CRLStats{
		RevokedCount: len(c.revokedCerts),
		LastUpdate:   c.lastUpdate,
		NextUpdate:   nextUpdate,
	}
}

// IsRevoked checks if a specific certificate is revoked
func (c *crlCache) IsRevoked(serial *big.Int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, exists := c.revokedCerts[serial.String()]
	return exists
}

// GetRevokedCerts returns all revoked certificate serials
func (c *crlCache) GetRevokedCerts() []*big.Int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	serials := make([]*big.Int, 0, len(c.revokedCerts))
	for _, entry := range c.revokedCerts {
		serials = append(serials, entry.SerialNumber)
	}
	return serials
}

// =============================================================================
// Static CRL Fetcher - uses pre-loaded CRL data (for testing)
// =============================================================================

// staticFetcher returns pre-loaded CRL data (used for testing)
type staticFetcher struct {
	data []byte
}

// newStaticFetcher creates a fetcher with static CRL data
func newStaticFetcher(data []byte) *staticFetcher {
	return &staticFetcher{data: data}
}

// Fetch returns the static CRL data
func (f *staticFetcher) Fetch() ([]byte, error) {
	if f.data == nil {
		return nil, fmt.Errorf("no CRL data")
	}
	return f.data, nil
}
