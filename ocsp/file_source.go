package ocsp

import (
	"fmt"
	"os"
	"time"
)

// FileSource provides certificate status by reading and caching a CRL from a local file
type FileSource struct {
	*crlCache
}

// FileSourceConfig holds configuration for FileSource
type FileSourceConfig struct {
	Path            string
	RefreshInterval time.Duration // default: 5 minutes
}

// NewFileSource creates a new file-based certificate status source
func NewFileSource(cfg FileSourceConfig) (*FileSource, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("path is required")
	}

	fetcher := &fileFetcher{path: cfg.Path}

	cache, err := newCRLCache(crlCacheConfig{
		fetcher:         fetcher,
		refreshInterval: cfg.RefreshInterval,
	})
	if err != nil {
		return nil, err
	}

	return &FileSource{crlCache: cache}, nil
}

// fileFetcher reads CRL data from a local file
type fileFetcher struct {
	path string
}

// Fetch reads CRL data from the configured file
func (f *fileFetcher) Fetch() ([]byte, error) {
	return os.ReadFile(f.path)
}
