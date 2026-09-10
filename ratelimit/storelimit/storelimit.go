// Package storelimit is a rate limiter that keeps its counters in the
// Auth-All database. Two instances therefore share one count.
//
// The limiter fails closed. It uses the database that sign-in uses, so a
// database failure fails sign-in anyway, and a fail-open limiter would only
// remove the bound at the worst moment.
package storelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// Version of the migration unit of the counter table.
const unitVersion = "20260910000003"

// Owner names the owner of the counter table.
const Owner = "ratelimit"

// Limiter counts the attempts of every rule in the store.
type Limiter struct {
	counter store.RateLimitCounter
	rules   []ratelimit.Rule
	now     func() time.Time
}

// Option configures the limiter.
type Option func(*Limiter)

// WithClock replaces the clock. A test uses it.
func WithClock(now func() time.Time) Option {
	return func(l *Limiter) { l.now = now }
}

// New returns a limiter that keeps the counters of the rules in s.
//
// The store must implement store.RateLimitCounter. Every first-party SQL store
// does.
func New(s store.Store, rules []ratelimit.Rule, opts ...Option) (*Limiter, error) {
	counter, ok := s.(store.RateLimitCounter)
	if !ok {
		return nil, fmt.Errorf("authall/storelimit: the store keeps no rate-limit counter. " +
			"Use a first-party store, or use another limiter")
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("authall/storelimit: at least one rule is required")
	}
	for _, r := range rules {
		if r.Operation == "" {
			return nil, fmt.Errorf("authall/storelimit: a rule names no operation")
		}
		if r.Scope != ratelimit.ScopeIP && r.Scope != ratelimit.ScopeEmail {
			return nil, fmt.Errorf("authall/storelimit: the rule of %q has the unsupported scope %q",
				r.Operation, r.Scope)
		}
		if r.Limit < 1 {
			return nil, fmt.Errorf("authall/storelimit: the rule of %q has the limit %d", r.Operation, r.Limit)
		}
		if r.Window <= 0 {
			return nil, fmt.Errorf("authall/storelimit: the rule of %q has no window", r.Operation)
		}
	}
	l := &Limiter{counter: counter, rules: rules, now: time.Now}
	for _, o := range opts {
		o(l)
	}
	return l, nil
}

// Allow implements ratelimit.Limiter.
func (l *Limiter) Allow(ctx context.Context, k ratelimit.Key) (bool, error) {
	d, err := l.Decide(ctx, k)
	return d.Allowed, err
}

// Decide implements ratelimit.Decider. Every rule of the operation counts the
// attempt, and the request fails when any rule is over its limit.
func (l *Limiter) Decide(ctx context.Context, k ratelimit.Key) (ratelimit.Decision, error) {
	now := l.now().UTC()
	decision := ratelimit.Decision{Allowed: true}
	for _, rule := range l.rules {
		if rule.Operation != k.Operation {
			continue
		}
		subject := Subject(rule.Scope, k)
		if subject == "" {
			// The attempt carries no subject of this scope, so the rule has
			// nothing to count.
			continue
		}
		key := string(rule.Operation) + "|" + string(rule.Scope) + "|" + subject
		count, start, err := l.counter.CountAttempt(ctx, key, rule.Window, now)
		if err != nil {
			return ratelimit.Decision{}, err
		}
		if count <= rule.Limit {
			continue
		}
		retry := start.Add(rule.Window).Sub(now)
		if retry < 0 {
			retry = 0
		}
		decision.Allowed = false
		if retry > decision.RetryAfter {
			decision.RetryAfter = retry
		}
	}
	return decision, nil
}

// Cleanup removes every counter whose window ended before the given time.
func (l *Limiter) Cleanup(ctx context.Context, before time.Time) (int, error) {
	return l.counter.CleanupRateLimits(ctx, before.UTC())
}

// Subject returns the counted subject of one key in one scope. It returns an
// empty value when the key carries no subject of the scope.
func Subject(scope ratelimit.Scope, k ratelimit.Key) string {
	switch scope {
	case ratelimit.ScopeEmail:
		address := strings.ToLower(strings.TrimSpace(k.Email))
		if address == "" {
			return ""
		}
		// The counter table holds a digest, so it holds no personal data.
		return digest(address)
	case ratelimit.ScopeIP:
		return IPKey(k.IP)
	}
	return ""
}

// IPKey returns the counted address of one client address.
//
// An IPv6 address counts per /64 block, because one customer owns a whole
// block. An IPv4-mapped address counts as the IPv4 address.
func IPKey(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return digest(value)
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Is4() {
		return addr.String()
	}
	block, err := addr.Prefix(64)
	if err != nil {
		return addr.String()
	}
	return block.String()
}

// digest returns the SHA-256 hex digest of a value.
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Table returns the counter table for the physical schema options.
func Table(o schema.Options) schema.Table {
	return schema.Table{
		Name: schema.TableNames(o).RateLimits,
		Columns: []schema.Column{
			// The key holds the operation, the scope, and the digest of the
			// subject. It never holds an email address.
			{Name: "key", Type: schema.TypeText, PrimaryKey: true},
			{Name: "window_start", Type: schema.TypeTimestamp},
			{Name: "count", Type: schema.TypeInt},
		},
	}
}

// SchemaTables implements the schema contribution of a limiter.
func (l *Limiter) SchemaTables(o schema.Options) []schema.Table {
	return []schema.Table{Table(o)}
}

// SchemaUnits implements the schema contribution of a limiter.
func (l *Limiter) SchemaUnits(o schema.Options) ([]schema.Unit, error) { return Units(o) }

// Units returns the migration units of the counter table.
func Units(o schema.Options) ([]schema.Unit, error) {
	u, err := schema.TableUnit(unitVersion, Owner, "authall_rate_limits",
		[]schema.Dialect{schema.Postgres, schema.SQLite}, []schema.Table{Table(o)})
	if err != nil {
		return nil, err
	}
	return []schema.Unit{u}, nil
}
