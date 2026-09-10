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

// Scope names the subject that one rule counts.
type Scope string

// Supported scopes.
const (
	// ScopeIP counts the attempts of one client address. An IPv6 address
	// counts per /64 block.
	ScopeIP Scope = "ip"
	// ScopeEmail counts the attempts for one email address. The store keeps a
	// digest of the address and never the address.
	ScopeEmail Scope = "email"
)

// Rule is one limit of one operation.
type Rule struct {
	// Operation names the flow that the rule counts.
	Operation Operation
	// Scope names the counted subject.
	Scope Scope
	// Limit is the number of accepted attempts in one window.
	Limit int
	// Window is the length of the counting window.
	Window time.Duration
}

// Decision is the answer of a Decider.
type Decision struct {
	// Allowed reports whether the attempt can proceed.
	Allowed bool
	// RetryAfter is the time until the next attempt can succeed. It is zero
	// when the attempt is allowed.
	RetryAfter time.Duration
}

// Decider is an optional limiter interface that names a retry time.
//
// A limiter that implements it drives the Retry-After header of a refused
// request. A limiter that implements Limiter only keeps the v1 behavior, and
// Auth-All sends Retry-After: 60.
type Decider interface {
	Limiter
	// Decide counts one attempt and returns the decision.
	Decide(ctx context.Context, key Key) (Decision, error)
}

// DefaultSignInRules returns the default rules of the sign-in flow. They allow
// 5 attempts for each email in 15 minutes, and 20 attempts for each client
// address in 1 minute.
func DefaultSignInRules() []Rule {
	return []Rule{
		{Operation: OpSignIn, Scope: ScopeEmail, Limit: 5, Window: 15 * time.Minute},
		{Operation: OpSignIn, Scope: ScopeIP, Limit: 20, Window: time.Minute},
	}
}
