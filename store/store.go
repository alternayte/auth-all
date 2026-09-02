// Package store defines the storage boundary of Auth-All. The application owns
// the database. An adapter implements these capability-oriented interfaces.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/alternayte/auth-all/schema"
)

// Sentinel storage errors.
var (
	// ErrNotFound reports that the requested row does not exist.
	ErrNotFound = errors.New("authall/store: not found")
	// ErrConflict reports that a uniqueness constraint rejected the write.
	ErrConflict = errors.New("authall/store: conflict")
)

// User is one Auth-All user.
type User struct {
	ID              string
	Email           string
	EmailNormalized string
	EmailVerifiedAt *time.Time
	DisplayName     string
	ImageURL        string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Credential is the password credential of one user.
type Credential struct {
	UserID       string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Account is one external provider identity owned by a user.
type Account struct {
	ID                string
	UserID            string
	Provider          string
	ProviderAccountID string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Session is one database-backed opaque session. TokenHash never holds a
// plaintext token.
type Session struct {
	ID         string
	UserID     string
	TokenHash  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
}

// Token is one one-time token. TokenHash never holds a plaintext token.
type Token struct {
	ID         string
	UserID     *string
	Kind       string
	Identifier string
	TokenHash  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// TOTP is the time-based one-time password enrolment of one user.
//
// Secret holds the base32 shared secret. Auth-All does not encrypt it, because
// Auth-All holds no application key, and a key that the library invents lives
// in the same database as the secret. An application that needs encryption at
// rest applies it at the column or at the volume.
type TOTP struct {
	UserID string
	Secret string
	// ConfirmedAt is nil until the user proves one code. An unconfirmed
	// enrolment never authenticates a sign-in.
	ConfirmedAt *time.Time
	// LastStep is the last accepted time step. The sign-in gate refuses a step
	// that is not greater than this value, which stops a replay of one code
	// inside its own window.
	LastStep  int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// OAuthState is one pending OAuth authorization request.
type OAuthState struct {
	ID         string
	StateHash  string
	Provider   string
	Verifier   string
	Nonce      string
	RedirectTo string
	LinkUserID *string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// UserStore holds users and password credentials.
type UserStore interface {
	// Create inserts a user. It returns ErrConflict when the normalized email
	// is already taken.
	Create(ctx context.Context, u *User) error
	GetByID(ctx context.Context, id string) (*User, error)
	GetByNormalizedEmail(ctx context.Context, normalized string) (*User, error)
	// Update writes the mutable user fields.
	Update(ctx context.Context, u *User) error
	// Delete removes a user and every owned row.
	Delete(ctx context.Context, id string) error

	GetCredential(ctx context.Context, userID string) (*Credential, error)
	// SetCredential inserts or replaces the password credential of a user.
	SetCredential(ctx context.Context, c *Credential) error
	DeleteCredential(ctx context.Context, userID string) error
}

// AccountStore holds external provider identities.
type AccountStore interface {
	// Create inserts an account. It returns ErrConflict when the provider
	// identity is already linked to a user.
	Create(ctx context.Context, a *Account) error
	GetByProviderAccount(ctx context.Context, provider, providerAccountID string) (*Account, error)
	ListByUser(ctx context.Context, userID string) ([]Account, error)
	// Delete removes one link. It returns ErrNotFound when no link exists.
	Delete(ctx context.Context, userID, provider string) error
}

// SessionStore holds database-backed sessions.
type SessionStore interface {
	Create(ctx context.Context, s *Session) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	// ListByUser returns every session of one user, and the newest comes
	// first. It returns an empty result for a user without a session.
	ListByUser(ctx context.Context, userID string) ([]Session, error)
	// Touch updates last_seen_at. It returns ErrNotFound when the session no
	// longer exists, so a revoked session cannot be resurrected.
	Touch(ctx context.Context, id string, at time.Time) error
	Delete(ctx context.Context, id string) error
	DeleteByUser(ctx context.Context, userID string) (int, error)
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// TokenStore holds one-time tokens.
type TokenStore interface {
	Create(ctx context.Context, t *Token) error
	// Consume atomically marks one unconsumed and unexpired token as consumed
	// and returns it. Two concurrent calls for the same token must produce at
	// most one success. It returns ErrNotFound otherwise.
	Consume(ctx context.Context, kind, tokenHash string, now time.Time) (*Token, error)
	// Get returns a token without consuming it.
	Get(ctx context.Context, kind, tokenHash string) (*Token, error)
	// DeleteByIdentifier removes every outstanding token of one kind for one
	// identifier.
	DeleteByIdentifier(ctx context.Context, kind, identifier string) error
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// TOTPStore holds the TOTP enrolment of each user.
type TOTPStore interface {
	// Get returns the enrolment of one user. It returns ErrNotFound when the
	// user holds no secret.
	Get(ctx context.Context, userID string) (*TOTP, error)
	// Upsert writes the enrolment of one user and replaces any existing row.
	// A replacement clears the confirmation and the last step, because a new
	// secret starts a new enrolment.
	Upsert(ctx context.Context, t *TOTP) error
	// Confirm marks the enrolment of one user as proven. It returns
	// ErrNotFound when the user holds no secret.
	Confirm(ctx context.Context, userID string, at time.Time) error
	// AdvanceStep records step when it is greater than the stored step, and
	// reports whether the write happened.
	//
	// The comparison and the write are one atomic operation. Two concurrent
	// calls that carry the same step must produce at most one true, because a
	// read followed by a later write would let an attacker replay one stolen
	// code across parallel requests.
	//
	// It returns ErrNotFound when the user holds no secret.
	AdvanceStep(ctx context.Context, userID string, step int64) (bool, error)
	// Delete removes the enrolment of one user. It returns ErrNotFound when
	// the user holds no secret.
	Delete(ctx context.Context, userID string) error
}

// OAuthStateStore holds pending OAuth authorization requests.
type OAuthStateStore interface {
	Create(ctx context.Context, s *OAuthState) error
	// Consume atomically marks one unconsumed and unexpired state as consumed
	// and returns it.
	Consume(ctx context.Context, stateHash string, now time.Time) (*OAuthState, error)
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// Migrator applies the effective schema. It never runs automatically.
type Migrator interface {
	// Dialect reports the SQL flavor of the adapter.
	Dialect() schema.Dialect
	// Plan returns the statements that are not applied yet.
	Plan(ctx context.Context, s *schema.Schema) ([]schema.Statement, error)
	// Apply runs the pending statements and records them.
	Apply(ctx context.Context, s *schema.Schema) ([]schema.Statement, error)
	// Check returns an actionable error when the database schema is missing or
	// outdated.
	Check(ctx context.Context, s *schema.Schema) error
}

// Store is the storage boundary of Auth-All.
type Store interface {
	Users() UserStore
	Accounts() AccountStore
	Sessions() SessionStore
	Tokens() TokenStore
	OAuthStates() OAuthStateStore
	TOTP() TOTPStore

	// Transaction runs fn inside one database transaction. The Store passed to
	// fn performs every operation inside that transaction.
	Transaction(ctx context.Context, fn func(Store) error) error

	// Migrator returns the schema migrator of the adapter.
	Migrator() Migrator

	// Close releases adapter resources. It does not close a database handle
	// owned by the application.
	Close() error
}
