// Package authall is an embedded authentication framework for Go applications.
//
// Auth-All runs inside the application, stores its data in the database the
// application owns, and integrates through net/http.
package authall

import (
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/oauth"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// Defaults used when an option is not supplied.
const (
	DefaultBasePath   = "/api/auth"
	DefaultCookieName = "authall.session"
	DefaultSessionTTL = 30 * 24 * time.Hour
	// DefaultSessionTouchInterval limits how often a session read writes
	// last_seen_at.
	DefaultSessionTouchInterval = 5 * time.Minute
	DefaultVerificationTTL      = 24 * time.Hour
	DefaultPasswordResetTTL     = time.Hour
	DefaultOAuthStateTTL        = 15 * time.Minute
)

// EmailPasswordOptions configures email and password authentication.
type EmailPasswordOptions struct {
	// RequireEmailVerification blocks sign-in until the address is verified.
	RequireEmailVerification bool
	// SendVerificationOnSignUp sends a verification email after sign-up. It is
	// implied by RequireEmailVerification.
	SendVerificationOnSignUp bool
	// VerifyEmailURL is the application page that receives a verification
	// token. Auth-All appends the token query parameter. The default is
	// BaseURL + /verify-email.
	VerifyEmailURL string
	// ResetPasswordURL is the application page that receives a password reset
	// token. Auth-All appends the token query parameter. The default is
	// BaseURL + /reset-password.
	ResetPasswordURL string
}

// PasswordPolicy configures the accepted passwords. Auth-All does not require
// special characters, because a length requirement protects better.
type PasswordPolicy struct {
	MinLength int
	MaxLength int
}

// DefaultPasswordPolicy returns the default policy.
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{MinLength: 8, MaxLength: 4096}
}

// CookieOptions configures the session cookie.
type CookieOptions struct {
	Name     string
	Domain   string
	Path     string
	SameSite http.SameSite
	// Secure defaults to true. Set it to false only for local development
	// over plain HTTP.
	Secure *bool
}

// SessionOptions configures session lifetime.
type SessionOptions struct {
	TTL time.Duration
	// TouchInterval limits how often a session read updates last_seen_at.
	TouchInterval time.Duration
}

// TokenTTLOptions configures one-time token lifetimes.
type TokenTTLOptions struct {
	EmailVerification time.Duration
	PasswordReset     time.Duration
	OAuthState        time.Duration
}

// AccountLinkingOptions configures how an external account joins a user.
type AccountLinkingOptions struct {
	// AllowVerifiedEmailAutoLink links an external account to an existing user
	// when the provider proves the same verified email address. It is off by
	// default, because email matching alone allows account takeover through a
	// provider that does not verify addresses.
	AllowVerifiedEmailAutoLink bool
}

type config struct {
	store          store.Store
	basePath       string
	baseURL        string
	trustedOrigins []string
	trustedProxies []string
	// proxyNets holds the parsed form of trustedProxies. normalizeConfig fills
	// it, so a request never parses a configuration value.
	proxyNets []netip.Prefix

	emailPasswordEnabled bool
	emailPassword        EmailPasswordOptions
	passwordPolicy       PasswordPolicy
	argon                crypto.Argon2Params

	sender    email.Sender
	providers []oauth.Provider
	plugins   []plugin.Plugin

	cookie   CookieOptions
	session  SessionOptions
	tokenTTL TokenTTLOptions
	linking  AccountLinkingOptions

	limiter  ratelimit.Limiter
	logger   *slog.Logger
	now      func() time.Time
	handlers []events.Handler
}

// Option configures Auth-All.
type Option func(*config)

// WithStore sets the storage adapter. It is required.
func WithStore(s store.Store) Option { return func(c *config) { c.store = s } }

// WithBasePath sets the mount path of the HTTP handler. The default is
// /api/auth.
func WithBasePath(p string) Option { return func(c *config) { c.basePath = p } }

// WithBaseURL sets the absolute public URL of the application, for example
// https://app.example.com. Auth-All uses it to build links and to validate
// redirects. It is required when an OAuth provider is configured.
func WithBaseURL(u string) Option { return func(c *config) { c.baseURL = u } }

// WithTrustedOrigins adds browser origins that can call state-changing
// endpoints. The origin of BaseURL is always trusted. A credentialed wildcard
// origin is never allowed.
func WithTrustedOrigins(origins ...string) Option {
	return func(c *config) { c.trustedOrigins = append(c.trustedOrigins, origins...) }
}

// WithTrustedProxies declares the reverse proxies that stand in front of the
// application. Auth-All reads a forwarded client address only when the direct
// peer is inside one of these blocks.
//
// Each value is a CIDR block, for example 10.0.0.0/8. A single IP address is
// also valid, and Auth-All treats it as one host. An invalid value fails the
// construction.
//
// Auth-All ignores the X-Forwarded-For header when no trusted proxy is
// declared, because any client can set that header. Declare the proxies of the
// deployment. See docs/guides/deployment.md.
func WithTrustedProxies(cidrs ...string) Option {
	return func(c *config) { c.trustedProxies = append(c.trustedProxies, cidrs...) }
}

// WithEmailPassword enables email and password authentication.
func WithEmailPassword(opts ...EmailPasswordOptions) Option {
	return func(c *config) {
		c.emailPasswordEnabled = true
		if len(opts) > 0 {
			c.emailPassword = opts[0]
		}
	}
}

// WithEmailSender sets the email delivery boundary of the application.
func WithEmailSender(s email.Sender) Option { return func(c *config) { c.sender = s } }

// WithProvider registers one or more OAuth providers.
func WithProvider(providers ...oauth.Provider) Option {
	return func(c *config) { c.providers = append(c.providers, providers...) }
}

// WithPlugins registers one or more plugins.
func WithPlugins(plugins ...plugin.Plugin) Option {
	return func(c *config) { c.plugins = append(c.plugins, plugins...) }
}

// WithCookie configures the session cookie.
func WithCookie(o CookieOptions) Option { return func(c *config) { c.cookie = o } }

// WithSession configures session lifetime.
func WithSession(o SessionOptions) Option { return func(c *config) { c.session = o } }

// WithTokenTTL configures one-time token lifetimes.
func WithTokenTTL(o TokenTTLOptions) Option { return func(c *config) { c.tokenTTL = o } }

// WithPasswordPolicy configures the accepted passwords.
func WithPasswordPolicy(p PasswordPolicy) Option { return func(c *config) { c.passwordPolicy = p } }

// WithArgon2Params configures the password hashing cost. A sign-in rehashes a
// password that was stored with different parameters.
func WithArgon2Params(p crypto.Argon2Params) Option { return func(c *config) { c.argon = p } }

// WithAccountLinking configures the account linking policy.
func WithAccountLinking(o AccountLinkingOptions) Option { return func(c *config) { c.linking = o } }

// WithRateLimiter sets the rate limiter for sensitive operations.
func WithRateLimiter(l ratelimit.Limiter) Option { return func(c *config) { c.limiter = l } }

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option { return func(c *config) { c.logger = l } }

// WithEventHandler registers an observability handler.
func WithEventHandler(h events.Handler) Option {
	return func(c *config) { c.handlers = append(c.handlers, h) }
}

// WithClock replaces the clock. Tests use it for deterministic expiry.
func WithClock(now func() time.Time) Option { return func(c *config) { c.now = now } }

// Argon2Params re-exports the password hashing parameters.
type Argon2Params = crypto.Argon2Params

// DefaultArgon2Params returns the default password hashing cost.
func DefaultArgon2Params() Argon2Params { return crypto.DefaultArgon2Params() }
