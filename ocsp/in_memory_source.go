package ocsp

import (
	"math/big"
	"sync"
	"time"
)

// InMemorySource is a simple in-memory certificate status store
type InMemorySource struct {
	mu       sync.RWMutex
	statuses map[string]*CertStatus
}

// NewInMemorySource creates a new in-memory source
func NewInMemorySource() *InMemorySource {
	return &InMemorySource{
		statuses: make(map[string]*CertStatus),
	}
}

// SetStatus sets the status for a certificate serial number
func (s *InMemorySource) SetStatus(serial *big.Int, status *CertStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses[serial.String()] = status
}

// Response returns the status for a certificate serial number
func (s *InMemorySource) Response(serial *big.Int) (*CertStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status, ok := s.statuses[serial.String()]
	if !ok {
		// Default to "good" if not found (you may want to change this to "unknown")
		return &CertStatus{Status: "good"}, nil
	}
	return status, nil
}

// Stats returns statistics about the in-memory source
func (s *InMemorySource) Stats() CRLStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Count revoked certificates
	revokedCount := 0
	for _, status := range s.statuses {
		if status.Status == "revoked" {
			revokedCount++
		}
	}

	return CRLStats{
		RevokedCount: revokedCount,
		LastUpdate:   time.Now(),
		NextUpdate:   time.Time{}, // No scheduled update for in-memory source
	}
}
