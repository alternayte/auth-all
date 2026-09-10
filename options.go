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

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/oauth"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// Defaults used when an option is not supplied.
const (
	DefaultBasePath   = "/api/auth"
	DefaultCookieName = "authall.session"
	// DefaultSessionTTL is the absolute lifetime of a session. A session ends
	// at this age, even when the person stays active.
	DefaultSessionTTL = 30 * 24 * time.Hour
	// DefaultSessionIdleTimeout ends a session that saw no request for this
	// long.
	DefaultSessionIdleTimeout = 7 * 24 * time.Hour
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
	// ChangeEmailURL is the application page that receives an email change
	// token. Auth-All appends the token query parameter. The default is
	// BaseURL + /change-email.
	ChangeEmailURL string
	// DeleteAccountURL is the application page that receives an account delete
	// token. Auth-All appends the token query parameter. The default is
	// BaseURL + /delete-account.
	DeleteAccountURL string
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
	// TTL is the absolute lifetime. A session ends at this age, even when the
	// person stays active. The default is 30 days.
	TTL time.Duration
	// IdleTimeout ends a session that saw no request for this long. The
	// default is 7 days.
	IdleTimeout time.Duration
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

	totpEnabled bool
	totp        TOTPOptions

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

	errorWriter apierr.Writer

	// hostOriginCheck runs the origin check on a host route that a cookie
	// authenticated. normalizeConfig fills it, so the default is on.
	hostOriginCheck *bool

	// consistencyBound is the maximum time between a committed change and its
	// effect on every instance.
	consistencyBound time.Duration
	// principalCacheTTL turns the bounded principal cache on. Zero keeps the
	// cache off, so every request reads the store.
	principalCacheTTL time.Duration

	schemaOptions schema.Options
	schemaCheck   SchemaCheckMode

	limiter ratelimit.Limiter
	// strictRateLimiting turns the missing-limiter warning into a construction
	// error.
	strictRateLimiting bool
	logger             *slog.Logger
	now                func() time.Time
	handlers           []events.Handler
}

// Option configures Auth-All.
type Option func(*config)

// WithStore sets the storage adapter. It is required.
func WithStore(s store.Store) Option { return func(c *config) { c.store = s } }

// WithSchema configures the physical schema. It sets the table prefix, the
// identifier type, and the host-owned user fields. The store must accept the
// same options, so Auth-All passes them to a first-party store.
func WithSchema(o schema.Options) Option { return func(c *config) { c.schemaOptions = o } }

// WithUserFields adds host-owned columns to the users table. It appends to the
// fields of WithSchema.
func WithUserFields(fields ...schema.UserField) Option {
	return func(c *config) {
		c.schemaOptions.UserFields = append(c.schemaOptions.UserFields, fields...)
	}
}

// WithErrorWriter replaces the public error envelope of every Auth-All route,
// of RequireAuth, of LoadSession, and of every plugin route.
//
// The writer receives the public error only. Auth-All keeps the private cause
// in its log. The writer must keep a header that the status needs, for example
// Retry-After on status 429.
func WithErrorWriter(f func(w http.ResponseWriter, r *http.Request, e *Error)) Option {
	return func(c *config) { c.errorWriter = apierr.Writer(f) }
}

// WithHostOriginCheck turns the origin check of the host routes on or off. The
// default is on.
//
// RequireAuth, LoadSession, and a role check refuse an unsafe cross-site
// request that a cookie authenticated. A bearer request skips the check,
// because a cross-site page cannot send a bearer credential.
//
// Turn the check off only when another layer already refuses a cross-site
// request. Auth-All writes a warn-level log entry when the check is off.
func WithHostOriginCheck(on bool) Option {
	return func(c *config) { c.hostOriginCheck = &on }
}

// WithConsistencyBound sets the maximum time between a committed change and
// its effect on every instance. The default is 5 seconds.
//
// Auth-All keeps no authorization state in memory past this time.
func WithConsistencyBound(d time.Duration) Option {
	return func(c *config) { c.consistencyBound = d }
}

// WithPrincipalCache keeps a resolved principal in process memory for ttl.
//
// The cache saves one store round trip for each request. Construction fails
// when ttl is above the consistency bound, because a longer entry would keep a
// disabled user, a demoted user, or a revoked credential alive past the bound.
//
// The cache is off by default. With no cache, every request reads the store,
// so the effective bound is zero.
func WithPrincipalCache(ttl time.Duration) Option {
	return func(c *config) { c.principalCacheTTL = ttl }
}

// SchemaCheckMode selects how CheckSchema reads the state of the database.
type SchemaCheckMode int

const (
	// SchemaCheckRecord compares the Auth-All record table with the effective
	// schema. It is the default, and it fits an application that calls
	// Migrate.
	SchemaCheckRecord SchemaCheckMode = iota
	// SchemaCheckCatalog reads the database catalog. A host that applies the
	// exported migrations with its own tool writes no Auth-All record, so the
	// catalog is the only source of truth.
	SchemaCheckCatalog
)

// WithSchemaCheck selects the source that CheckSchema reads.
func WithSchemaCheck(m SchemaCheckMode) Option { return func(c *config) { c.schemaCheck = m } }

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

// TOTPOptions configures the time-based one-time password second factor.
type TOTPOptions struct {
	// Issuer is the name that the authenticator application shows. It defaults
	// to the host of the base URL.
	Issuer string
}

// WithTOTP enables the time-based one-time password second factor.
//
// The endpoints /totp/enrol, /totp/confirm, and /totp/disable appear. A user
// who confirms an enrolment must supply a code at every later sign-in.
func WithTOTP(opts ...TOTPOptions) Option {
	return func(c *config) {
		c.totpEnabled = true
		if len(opts) > 0 {
			c.totp = opts[0]
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

// WithCookieSameSite sets the SameSite attribute of the session cookie.
//
// Use http.SameSiteLaxMode when the application and the API share a
// registrable domain, for example app.example.com and api.example.com. Use
// http.SameSiteNoneMode only for a true cross-site setup. A browser refuses a
// cookie with SameSite=None and no Secure attribute, so that pair fails the
// construction. See docs/guides/deployment.md.
func WithCookieSameSite(mode http.SameSite) Option {
	return func(c *config) { c.cookie.SameSite = mode }
}

// WithSession configures session lifetime.
func WithSession(o SessionOptions) Option { return func(c *config) { c.session = o } }

// WithSessionLifetime sets the two session deadlines.
//
// idle ends a session that saw no request for that long. absolute ends a
// session at that age, even when the person stays active. One value cannot
// serve both, because a stolen token that stays active would never expire.
//
// The defaults are 7 days and 30 days.
func WithSessionLifetime(idle, absolute time.Duration) Option {
	return func(c *config) {
		c.session.IdleTimeout = idle
		c.session.TTL = absolute
	}
}

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

// WithStrictRateLimiting fails the construction when no rate limiter is
// configured.
//
// A production deployment needs a limiter. Without one, every sensitive
// endpoint accepts unlimited attempts, so a brute-force attack and an
// enumeration attack run without a bound. The default only writes a warning,
// because a test and a local run do not need a limiter.
func WithStrictRateLimiting() Option { return func(c *config) { c.strictRateLimiting = true } }

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
