package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryLimiter(t *testing.T) {
	m := NewMemory(2, time.Minute)
	base := time.Now()
	m.now = func() time.Time { return base }
	key := Key{Operation: OpSignIn, IP: "10.0.0.1", Email: "user@example.com"}
	for i := 0; i < 2; i++ {
		ok, err := m.Allow(context.Background(), key)
		if err != nil || !ok {
			t.Fatalf("attempt %d was refused", i)
		}
	}
	if ok, _ := m.Allow(context.Background(), key); ok {
		t.Fatalf("the limit was not enforced")
	}
	// A different key has its own budget.
	other := key
	other.IP = "10.0.0.2"
	if ok, _ := m.Allow(context.Background(), other); !ok {
		t.Fatalf("a different key shares the budget")
	}
	// The window resets.
	m.now = func() time.Time { return base.Add(2 * time.Minute) }
	if ok, _ := m.Allow(context.Background(), key); !ok {
		t.Fatalf("the window did not reset")
	}
}
