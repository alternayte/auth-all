package authall

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// DefaultConsistencyBound is the maximum time between a committed change and
// its effect on every instance.
//
// With no cache, every request reads the credential and the user from the
// store, so the effective bound is zero.
const DefaultConsistencyBound = 5 * time.Second

// principalCache keeps resolved principals for a bounded time.
//
// The entry time can never exceed the consistency bound, so a disabled user, a
// changed role, and a revoked credential take effect inside the bound on every
// instance.
type principalCache struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]cacheEntry
}

// cacheEntry is one cached principal with its deadline.
type cacheEntry struct {
	principal *Principal
	expires   time.Time
}

// newPrincipalCache returns a cache with one entry time.
func newPrincipalCache(ttl time.Duration, now func() time.Time) *principalCache {
	return &principalCache{ttl: ttl, now: now, entries: map[string]cacheEntry{}}
}

// key returns the cache key of one credential. The cache holds a digest, so it
// holds no usable credential.
func cacheKey(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(sum[:])
}

// get returns the cached principal of one credential.
func (c *principalCache) get(credential string) (*Principal, bool) {
	if c == nil {
		return nil, false
	}
	key := cacheKey(credential)
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !now.Before(entry.expires) {
		delete(c.entries, key)
		return nil, false
	}
	return entry.principal, true
}

// put stores one principal until the bound ends.
func (c *principalCache) put(credential string, p *Principal) {
	if c == nil || p == nil {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	// A full cache drops the ended entries, so the map cannot grow without a
	// bound.
	if len(c.entries) > 4096 {
		for key, entry := range c.entries {
			if !now.Before(entry.expires) {
				delete(c.entries, key)
			}
		}
	}
	c.entries[cacheKey(credential)] = cacheEntry{principal: p, expires: now.Add(c.ttl)}
}
