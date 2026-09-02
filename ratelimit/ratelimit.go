// Package ratelimit defines the rate-limit integration point of Auth-All.
// Auth-All does not require a specific backend.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Operation names a sensitive flow.
type Operation string

// Sensitive operations.
const (
	OpSignIn           Operation = "sign-in"
	OpSignUp           Operation = "sign-up"
	OpPasswordForgot   Operation = "password-forgot"
	OpEmailVerify      Operation = "email-verification-send"
	OpMagicLinkRequest Operation = "magic-link-request"
	OpPasswordChange   Operation = "password-change"
	OpEmailChange      Operation = "email-change"
	OpUserDelete       Operation = "user-delete"
	OpTOTP             Operation = "totp"
)

// Key identifies one rate-limited attempt. Fields are set when relevant.
type Key struct {
	Operation Operation
	IP        string
	Email     string
	UserID    string
	Provider  string
}

// Limiter decides whether one attempt can proceed.
type Limiter interface {
	Allow(ctx context.Context, key Key) (bool, error)
}

// LimiterFunc adapts a function to the Limiter interface.
type LimiterFunc func(ctx context.Context, key Key) (bool, error)

// Allow implements Limiter.
func (f LimiterFunc) Allow(ctx context.Context, k Key) (bool, error) { return f(ctx, k) }

// Memory is an in-process fixed-window limiter.
//
// Memory is for local development and tests only. It is not sufficient for a
// distributed production deployment because each process keeps its own counters.
type Memory struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	count int
	start time.Time
}

// NewMemory returns an in-process limiter that allows limit attempts per window.
func NewMemory(limit int, window time.Duration) *Memory {
	return &Memory{limit: limit, window: window, now: time.Now, buckets: map[string]*bucket{}}
}

// Allow implements Limiter.
func (m *Memory) Allow(_ context.Context, k Key) (bool, error) {
	id := string(k.Operation) + "|" + k.IP + "|" + k.Email + "|" + k.UserID + "|" + k.Provider
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.buckets[id]
	if !ok || now.Sub(b.start) >= m.window {
		m.buckets[id] = &bucket{count: 1, start: now}
		return true, nil
	}
	if b.count >= m.limit {
		return false, nil
	}
	b.count++
	return true, nil
}
