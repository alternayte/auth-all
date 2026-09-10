package store

import (
	"context"
	"time"

	"github.com/alternayte/auth-all/schema"
)

// The interfaces in this file are optional. A store that does not implement one
// keeps the v1 behavior, and the caller that needs the capability reports a
// clear error. A new method on Store would break every third-party adapter, so
// every later capability arrives here.

// SchemaConfigurable accepts the physical schema options of the host. Auth-All
// calls it during construction when the host uses a table prefix or another
// identifier type.
type SchemaConfigurable interface {
	// UseSchema sets the physical names and types. It reports an error when the
	// store cannot serve the options.
	UseSchema(o schema.Options) error
}

// CatalogInspector reads the state of the database from the catalog of the
// engine. A host that applies the exported migrations with its own tool writes
// no Auth-All record, so the catalog is the only source of truth.
type CatalogInspector interface {
	// TableColumns returns the column names of one table. It returns false when
	// the table is absent.
	TableColumns(ctx context.Context, table string) ([]string, bool, error)
}

// SessionUserReader reads a session and its user in one round trip. A store
// that does not implement it costs one more round trip for each request.
type SessionUserReader interface {
	// SessionWithUser returns the session of a token hash and its user. It
	// returns ErrNotFound when no session matches.
	SessionWithUser(ctx context.Context, tokenHash string) (*Session, *User, error)
}

// RateLimitCounter keeps the rate-limit counters of the store-backed limiter.
// One statement counts one attempt, so the count is atomic across instances.
type RateLimitCounter interface {
	// CountAttempt adds one attempt to the counter of key and returns the new
	// count and the start of the window. It starts a new window when the
	// running window ended before now minus window.
	CountAttempt(ctx context.Context, key string, window time.Duration, now time.Time) (count int, windowStart time.Time, err error)
	// CleanupRateLimits removes every counter whose window ended before the
	// given time. It returns the number of removed rows.
	CleanupRateLimits(ctx context.Context, before time.Time) (int, error)
}
