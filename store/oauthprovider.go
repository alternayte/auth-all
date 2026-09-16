package store

import (
	"context"
	"time"
)

// The rows of the OAuth provider plugin. The plugin owns the tables. An
// adapter that implements OAuthProviderStore can host the plugin, and an
// adapter that does not keeps working for every other capability.

// OAuthKey is one signing key of the authorization server. The private key is
// wrapped with the key encryption key of the host, so a database dump holds no
// usable signing key.
type OAuthKey struct {
	// ID is the JWKS key identifier.
	ID string
	// Algorithm is the JWS algorithm, for example ES256.
	Algorithm string
	// WrappedPrivate is the AES-256-GCM ciphertext of the PKCS#8 private key.
	WrappedPrivate []byte
	// PublicJWK is the serialized public JSON Web Key.
	PublicJWK string
	CreatedAt time.Time
	// RetiredAt marks a key that signs nothing and still verifies.
	RetiredAt *time.Time
}

// OAuthClient is one registered relying party. A static first-party client is
// declared in host source and holds no row.
type OAuthClient struct {
	ID       string
	ClientID string
	// SecretHash is the SHA-256 hex digest of the client secret. A public
	// client holds an empty value.
	SecretHash string
	Name       string
	LogoURI    string
	// RedirectURIs holds the exact registered values.
	RedirectURIs []string
	GrantTypes   []string
	Scopes       []string
	// TokenEndpointAuthMethod is client_secret_basic, client_secret_post, or
	// none.
	TokenEndpointAuthMethod string
	// DPoPRequired refuses a bearer presentation of a token of this client.
	DPoPRequired bool
	// OwnerUserID is the subject that created the client through the
	// authenticated management route. A dynamically registered client holds
	// nil.
	OwnerUserID *string
	// OrgID is the organization that was active at creation.
	OrgID *string
	// RegistrationTokenHash is the digest of the RFC 7592 registration access
	// token. Only a dynamically registered client holds one.
	RegistrationTokenHash *string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// OAuthAuthorizationRequest is the server-side row of one authorize call. The
// redirect to the host login page and consent page names its identifier and
// nothing else.
type OAuthAuthorizationRequest struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	Scopes              []string
	Resources           []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	// Prompt holds the requested prompt values.
	Prompt []string
	// MaxAge is the requested authentication freshness in seconds. A nil value
	// means the request named none.
	MaxAge *int
	// DPoPJKT is the thumbprint of the DPoP key the client announced.
	DPoPJKT   string
	CreatedAt time.Time
	ExpiresAt time.Time
	// ConsumedAt marks a request that produced a code or a denial.
	ConsumedAt *time.Time
}

// OAuthGrant is the standing authorization of one user for one client. It owns
// the access tokens and the refresh tokens.
type OAuthGrant struct {
	ID       string
	ClientID string
	// UserID is nil for a client credentials grant.
	UserID    *string
	Scopes    []string
	Resources []string
	// AuthTime is the moment the user authenticated.
	AuthTime *time.Time
	// SessionID records the session that approved the grant. Nothing resolves
	// it after issuance.
	SessionID *string
	CreatedAt time.Time
	RevokedAt *time.Time
}

// OAuthCode is one authorization code. The store keeps the digest.
type OAuthCode struct {
	ID          string
	CodeHash    string
	GrantID     string
	ClientID    string
	RedirectURI string
	// CodeChallenge is the S256 challenge of the request.
	CodeChallenge string
	Nonce         string
	Scopes        []string
	Resources     []string
	DPoPJKT       string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
}

// OAuthAccessToken records one issued access token. The token itself is a
// signed JWT, so the row holds the identifier and never token material.
type OAuthAccessToken struct {
	// ID is the jti claim.
	ID       string
	GrantID  string
	ClientID string
	UserID   *string
	Scopes   []string
	// Audience is the resource indicator, or the issuer identifier.
	Audience string
	// JKT binds the token to a DPoP key.
	JKT       string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// OAuthRefreshToken is one refresh token of a grant. The store keeps the
// digest.
type OAuthRefreshToken struct {
	ID        string
	TokenHash string
	GrantID   string
	ClientID  string
	UserID    *string
	Scopes    []string
	Resources []string
	JKT       string
	CreatedAt time.Time
	ExpiresAt time.Time
	// RotatedAt marks the moment a successor replaced the token.
	RotatedAt *time.Time
	// SuccessorID names the token that replaced it, so a retry inside the
	// grace window answers with the same pair.
	SuccessorID *string
	RevokedAt   *time.Time
}

// OAuthConsent records the scopes and the resources a user granted to a
// client.
type OAuthConsent struct {
	ID        string
	ClientID  string
	UserID    string
	Scopes    []string
	Resources []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// OAuthProviderStore holds the rows of the OAuth provider plugin. It is an
// optional capability of an adapter.
type OAuthProviderStore interface {
	// CreateOAuthKey inserts one signing key.
	CreateOAuthKey(ctx context.Context, k *OAuthKey) error
	// ListOAuthKeys returns every key, the newest first.
	ListOAuthKeys(ctx context.Context) ([]OAuthKey, error)
	// RetireOAuthKeys marks every key that is not id as retired.
	RetireOAuthKeys(ctx context.Context, id string, at time.Time) error

	// CreateOAuthClient inserts one client.
	CreateOAuthClient(ctx context.Context, c *OAuthClient) error
	// OAuthClientByClientID reads one client.
	OAuthClientByClientID(ctx context.Context, clientID string) (*OAuthClient, error)
	// UpdateOAuthClient replaces the mutable fields of one client.
	UpdateOAuthClient(ctx context.Context, c *OAuthClient) error
	// DeleteOAuthClient removes one client.
	DeleteOAuthClient(ctx context.Context, clientID string) error
	// ListOAuthClients returns the clients of one owner. An empty owner
	// returns every client.
	ListOAuthClients(ctx context.Context, ownerUserID string) ([]OAuthClient, error)

	// CreateOAuthRequest inserts one authorization request.
	CreateOAuthRequest(ctx context.Context, a *OAuthAuthorizationRequest) error
	// OAuthRequestByID reads one authorization request.
	OAuthRequestByID(ctx context.Context, id string) (*OAuthAuthorizationRequest, error)
	// ConsumeOAuthRequest atomically consumes one authorization request. Two
	// concurrent calls produce at most one success.
	ConsumeOAuthRequest(ctx context.Context, id string, at time.Time) (*OAuthAuthorizationRequest, error)

	// CreateOAuthGrant inserts one grant.
	CreateOAuthGrant(ctx context.Context, g *OAuthGrant) error
	// OAuthGrantByID reads one grant.
	OAuthGrantByID(ctx context.Context, id string) (*OAuthGrant, error)
	// RevokeOAuthGrant revokes one grant and every token of it.
	RevokeOAuthGrant(ctx context.Context, id string, at time.Time) error
	// RevokeOAuthGrantsOfUser revokes every grant of one user.
	RevokeOAuthGrantsOfUser(ctx context.Context, userID string, at time.Time) error
	// RevokeOAuthGrantsOfConsent revokes every grant of one user for one
	// client.
	RevokeOAuthGrantsOfConsent(ctx context.Context, userID, clientID string, at time.Time) error

	// CreateOAuthCode inserts one authorization code.
	CreateOAuthCode(ctx context.Context, c *OAuthCode) error
	// ConsumeOAuthCode atomically consumes one authorization code.
	ConsumeOAuthCode(ctx context.Context, codeHash string, at time.Time) (*OAuthCode, error)
	// OAuthCodeByHash reads one code and consumes nothing.
	OAuthCodeByHash(ctx context.Context, codeHash string) (*OAuthCode, error)

	// CreateOAuthAccessToken records one issued access token.
	CreateOAuthAccessToken(ctx context.Context, t *OAuthAccessToken) error
	// OAuthAccessTokenByID reads one access token record.
	OAuthAccessTokenByID(ctx context.Context, id string) (*OAuthAccessToken, error)
	// RevokeOAuthAccessToken revokes one access token record.
	RevokeOAuthAccessToken(ctx context.Context, id string, at time.Time) error

	// CreateOAuthRefreshToken inserts one refresh token.
	CreateOAuthRefreshToken(ctx context.Context, t *OAuthRefreshToken) error
	// OAuthRefreshTokenByHash reads one refresh token.
	OAuthRefreshTokenByHash(ctx context.Context, tokenHash string) (*OAuthRefreshToken, error)
	// OAuthRefreshTokenByID reads one refresh token.
	OAuthRefreshTokenByID(ctx context.Context, id string) (*OAuthRefreshToken, error)
	// RotateOAuthRefreshToken atomically marks a token rotated and names its
	// successor. Two concurrent calls produce at most one success.
	RotateOAuthRefreshToken(ctx context.Context, id, successorID string, at time.Time) error

	// UpsertOAuthConsent records the consent of one user for one client.
	UpsertOAuthConsent(ctx context.Context, c *OAuthConsent) error
	// OAuthConsent reads the consent of one user for one client.
	OAuthConsent(ctx context.Context, userID, clientID string) (*OAuthConsent, error)
	// ListOAuthConsents returns every consent of one user.
	ListOAuthConsents(ctx context.Context, userID string) ([]OAuthConsent, error)
	// DeleteOAuthConsent removes one consent.
	DeleteOAuthConsent(ctx context.Context, userID, clientID string) error

	// ClaimOAuthProof records the identifier of one DPoP proof. It returns
	// ErrConflict for an identifier that a request already used, so a replayed
	// proof reaches no second token.
	ClaimOAuthProof(ctx context.Context, id string, expiresAt time.Time) error

	// DeleteExpiredOAuthRows removes the consumed and expired rows of the
	// plugin. The host calls it from its cleanup job.
	DeleteExpiredOAuthRows(ctx context.Context, before time.Time) (int, error)
}
