package store

import (
	"context"
	"time"
)

// The rows of the passkeys plugin. The plugin owns the tables. An adapter that
// implements PasskeyStore can host the plugin, and an adapter that does not
// keeps working for every other capability.

// Passkey is one WebAuthn credential of one user.
type Passkey struct {
	ID     string
	UserID string
	// CredentialID is the base64url form of the credential ID without padding.
	// It is unique, because an authenticator never reuses one.
	CredentialID string
	// Name is the label that the user gave the passkey.
	Name string
	// Credential is the JSON form of the verified credential record: the
	// public key, the sign count, the flags, and the attestation values. It
	// holds no secret.
	Credential string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// Passkey challenge kinds.
const (
	PasskeyChallengeRegistration = "registration"
	PasskeyChallengeSignIn       = "sign-in"
)

// PasskeyChallenge is the server side state of one WebAuthn ceremony. The
// client holds the plaintext ceremony handle, and the row holds its digest.
type PasskeyChallenge struct {
	// ID is the SHA-256 hex digest of the ceremony handle.
	ID string
	// Kind is PasskeyChallengeRegistration or PasskeyChallengeSignIn.
	Kind string
	// UserID names the user of a registration. A sign-in holds nil.
	UserID *string
	// SessionData is the JSON form of the ceremony state that the WebAuthn
	// library verifies the response against.
	SessionData string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ConsumedAt  *time.Time
}

// PasskeyStore holds the passkeys and the ceremony state of the passkeys
// plugin.
type PasskeyStore interface {
	// CreatePasskey inserts one passkey. It returns ErrConflict when the
	// credential ID exists already.
	CreatePasskey(ctx context.Context, p *Passkey) error
	// PasskeyByCredentialID returns the passkey of one credential ID. It
	// returns ErrNotFound when no passkey matches.
	PasskeyByCredentialID(ctx context.Context, credentialID string) (*Passkey, error)
	// ListPasskeys returns every passkey of one user, and the newest comes
	// first.
	ListPasskeys(ctx context.Context, userID string) ([]Passkey, error)
	// UpdatePasskeyUse writes the credential record and the last use time
	// after a sign-in.
	UpdatePasskeyUse(ctx context.Context, id, credential string, at time.Time) error
	// DeletePasskey removes one passkey of one user. It returns ErrNotFound
	// when the user holds no passkey with that identifier.
	DeletePasskey(ctx context.Context, id, userID string) error
	// CreatePasskeyChallenge inserts the state of one ceremony.
	CreatePasskeyChallenge(ctx context.Context, c *PasskeyChallenge) error
	// ConsumePasskeyChallenge atomically consumes one ceremony of one kind and
	// returns it. Two concurrent calls produce at most one success. It returns
	// ErrNotFound for a ceremony that is absent, of another kind, consumed, or
	// expired at the given time.
	ConsumePasskeyChallenge(ctx context.Context, id, kind string, at time.Time) (*PasskeyChallenge, error)
	// DeleteExpiredPasskeyChallenges removes every ceremony that expired
	// before the given time, and returns the number of removed rows.
	DeleteExpiredPasskeyChallenges(ctx context.Context, before time.Time) (int, error)
}
