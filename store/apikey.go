package store

import (
	"strings"
	"time"
)

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
	Role string
	// OrgID names the organization of the key. A nil value means a key of the
	// whole application. The permissions of an organization key are the
	// intersection of the key permissions and the live permissions of the
	// owner in that organization.
	OrgID *string
	// Scopes holds the sorted scope names of the key, separated by one space,
	// the form of Membership.Permissions. An empty value in the store means a
	// key from before the scope column, or a key of a plugin with no declared
	// scope. On a resolved principal the plugin has replaced an empty value with
	// the default scopes, so an empty value there means that the application
	// declares no scope.
	Scopes     string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	RevokedBy  *string
}

// ScopeList returns the scope names of the key.
func (k *APIKey) ScopeList() []string { return strings.Fields(k.Scopes) }
