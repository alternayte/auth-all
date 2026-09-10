package store

import "time"

// APIKey is one machine credential of a user. The plaintext key exists only in
// the response of the create route. The store keeps the digest.
type APIKey struct {
	ID     string
	UserID string
	// Name is the label of the owner.
	Name string
	// Start is the prefix and the first characters of the random part. A list
	// shows it, so a person recognizes the key.
	Start string
	// KeyHash is the SHA-256 hex digest of the plaintext key.
	KeyHash string
	// Role is the role of the key at creation. The effective role is the lower
	// of this role and the current role of the owner.
	Role       string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	RevokedBy  *string
}
