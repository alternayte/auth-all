package testsupport

import (
	"sync"
	"time"
)

// Clock is a controllable clock for deterministic expiry tests.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock returns a clock that starts at the current time. A test moves it
// with Advance, so expiry behavior stays deterministic while cookie lifetimes
// stay valid for the HTTP client.
func NewClock() *Clock {
	return &Clock{now: time.Now().UTC().Truncate(time.Second)}
}

// NewClockAt returns a clock that starts at a fixed time.
func NewClockAt(start time.Time) *Clock { return &Clock{now: start.UTC()} }

// Now returns the current clock value.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
