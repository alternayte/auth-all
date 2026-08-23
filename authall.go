package authall

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/oauth"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// Version is the Auth-All API contract version.
const Version = "1.0.0"

// Token kinds used by core flows.
const (
	tokenKindVerifyEmail   = "verify-email"
	tokenKindResetPassword = "reset-password"
)

// Auth is a configured Auth-All instance.
type Auth struct {
	cfg             *config
	mux             *http.ServeMux
	hooks           *hook.Hooks
	emitter         *events.Emitter
	effectiveSchema *schema.Schema
	doc             *openapi.Document
	providers       map[string]oauth.Provider
	providerOrder   []string
	trustedOrigins  []string
	svc             *services
}

// New builds an Auth-All instance from functional options.
func New(opts ...Option) (*Auth, error) {
	cfg := &config{
		basePath:       DefaultBasePath,
		passwordPolicy: DefaultPasswordPolicy(),
		argon:          crypto.DefaultArgon2Params(),
		cookie:         CookieOptions{Name: DefaultCookieName, Path: "/", SameSite: http.SameSiteLaxMode},
		session:        SessionOptions{TTL: DefaultSessionTTL, TouchInterval: DefaultSessionTouchInterval},
		tokenTTL: TokenTTLOptions{
			EmailVerification: DefaultVerificationTTL,
			PasswordReset:     DefaultPasswordResetTTL,
			OAuthState:        DefaultOAuthStateTTL,
		},
		now: time.Now,
	}
	for _, o := range opts {
		o(cfg)
	}
	if err := normalizeConfig(cfg); err != nil {
		return nil, err
	}

	a := &Auth{
		cfg:       cfg,
		mux:       http.NewServeMux(),
		providers: map[string]oauth.Provider{},
	}
	a.emitter = events.NewEmitter(cfg.now)
	for _, h := range cfg.handlers {
		a.emitter.Add(h)
	}
	a.hooks = hook.New(func(ctx context.Context, name string, err error) {
		cfg.logger.Error("authall: a lifecycle hook failed", "hook", name, "error", err.Error())
	})
	a.trustedOrigins = buildTrustedOrigins(cfg)

	for _, p := range cfg.providers {
		id := p.ID()
		if id == "" {
			return nil, fmt.Errorf("authall: an OAuth provider has an empty id")
		}
		if _, exists := a.providers[id]; exists {
			return nil, fmt.Errorf("authall: the OAuth provider %q is registered twice", id)
		}
		if v, ok := p.(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return nil, err
			}
		}
		a.providers[id] = p
		a.providerOrder = append(a.providerOrder, id)
	}
	sort.Strings(a.providerOrder)

	sc, err := schema.NewCore()
	if err != nil {
		return nil, err
	}
	a.effectiveSchema = sc
	a.doc = openapi.New("Auth-All", Version)
	registerCoreSchemas(a.doc)
	a.svc = &services{auth: a}

	a.registerCoreRoutes()

	seen := map[string]bool{}
	for _, p := range cfg.plugins {
		id := p.ID()
		if id == "" {
			return nil, fmt.Errorf("authall: a plugin has an empty id")
		}
		if seen[id] {
			return nil, fmt.Errorf("authall: the plugin %q is registered twice", id)
		}
		seen[id] = true
		reg := plugin.NewRegistry(id, a.svc, a.hooks)
		if err := p.Register(reg); err != nil {
			return nil, fmt.Errorf("authall: the plugin %q failed to register: %w", id, err)
		}
		for _, t := range reg.Tables() {
			if err := a.effectiveSchema.Add(t); err != nil {
				return nil, fmt.Errorf("authall: the plugin %q contributed an invalid table: %w", id, err)
			}
		}
		for name, s := range reg.ComponentSchemas() {
			a.doc.AddSchema(name, s)
		}
		for _, rt := range reg.Routes() {
			if err := a.mount(rt.Method, rt.Path, rt.Handler, rt.Operation); err != nil {
				return nil, fmt.Errorf("authall: the plugin %q contributed an invalid route: %w", id, err)
			}
		}
	}
	return a, nil
}

func normalizeConfig(cfg *config) error {
	if cfg.store == nil {
		return fmt.Errorf("authall: a store is required. Use authall.WithStore")
	}
	if cfg.logger == nil {
		cfg.logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.limiter == nil {
		cfg.limiter = ratelimit.LimiterFunc(func(context.Context, ratelimit.Key) (bool, error) { return true, nil })
	}
	if cfg.cookie.Name == "" {
		cfg.cookie.Name = DefaultCookieName
	}
	if cfg.cookie.Path == "" {
		cfg.cookie.Path = "/"
	}
	if cfg.cookie.SameSite == 0 {
		cfg.cookie.SameSite = http.SameSiteLaxMode
	}
	if cfg.session.TTL <= 0 {
		cfg.session.TTL = DefaultSessionTTL
	}
	if cfg.session.TouchInterval <= 0 {
		cfg.session.TouchInterval = DefaultSessionTouchInterval
	}
	if cfg.tokenTTL.EmailVerification <= 0 {
		cfg.tokenTTL.EmailVerification = DefaultVerificationTTL
	}
	if cfg.tokenTTL.PasswordReset <= 0 {
		cfg.tokenTTL.PasswordReset = DefaultPasswordResetTTL
	}
	if cfg.tokenTTL.OAuthState <= 0 {
		cfg.tokenTTL.OAuthState = DefaultOAuthStateTTL
	}
	if cfg.passwordPolicy.MinLength <= 0 {
		cfg.passwordPolicy.MinLength = DefaultPasswordPolicy().MinLength
	}
	if cfg.passwordPolicy.MaxLength <= 0 {
		cfg.passwordPolicy.MaxLength = DefaultPasswordPolicy().MaxLength
	}
	if cfg.passwordPolicy.MaxLength < cfg.passwordPolicy.MinLength {
		return fmt.Errorf("authall: the password policy maximum length is below the minimum length")
	}
	if cfg.argon.KeyLength == 0 {
		cfg.argon = crypto.DefaultArgon2Params()
	}
	cfg.basePath = "/" + strings.Trim(cfg.basePath, "/")
	if cfg.basePath == "/" {
		cfg.basePath = ""
	}
	cfg.baseURL = strings.TrimRight(cfg.baseURL, "/")
	if cfg.baseURL != "" {
		u, err := url.Parse(cfg.baseURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("authall: the base URL must be absolute, for example https://app.example.com")
		}
	}
	if len(cfg.providers) > 0 && cfg.baseURL == "" {
		return fmt.Errorf("authall: an OAuth provider requires a base URL. Use authall.WithBaseURL")
	}
	if cfg.emailPasswordEnabled && cfg.sender == nil {
		if cfg.emailPassword.RequireEmailVerification || cfg.emailPassword.SendVerificationOnSignUp {
			return fmt.Errorf("authall: email verification requires an email sender. Use authall.WithEmailSender")
		}
	}
	for _, o := range cfg.trustedOrigins {
		if strings.Contains(o, "*") {
			return fmt.Errorf("authall: a wildcard trusted origin is not allowed: %q", o)
		}
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("authall: the trusted origin %q must be absolute, for example https://app.example.com", o)
		}
	}
	return nil
}

func buildTrustedOrigins(cfg *config) []string {
	out := make([]string, 0, len(cfg.trustedOrigins)+1)
	if cfg.baseURL != "" {
		if u, err := url.Parse(cfg.baseURL); err == nil && u.Host != "" {
			out = append(out, u.Scheme+"://"+u.Host)
		}
	}
	for _, o := range cfg.trustedOrigins {
		out = append(out, strings.TrimRight(o, "/"))
	}
	return out
}

// mount registers one route on the internal router and in the OpenAPI document.
func (a *Auth) mount(method, path string, h http.Handler, op *openapi.Operation) error {
	if h == nil {
		return fmt.Errorf("the route %s %s has no handler", method, path)
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("the route path %q must start with /", path)
	}
	method = strings.ToUpper(method)
	a.mux.Handle(method+" "+path, h)
	if op != nil {
		a.doc.AddOperation(method, a.cfg.basePath+path, op)
	}
	return nil
}

func (a *Auth) handle(method, path string, fn http.HandlerFunc, op *openapi.Operation) {
	if err := a.mount(method, path, fn, op); err != nil {
		panic("authall: " + err.Error())
	}
}

// Handler returns the Auth-All HTTP handler. Mount it at the configured base
// path, for example mux.Handle("/api/auth/", auth.Handler()).
func (a *Auth) Handler() http.Handler {
	inner := http.Handler(a.mux)
	if a.cfg.basePath != "" {
		inner = http.StripPrefix(a.cfg.basePath, a.mux)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				a.cfg.logger.Error("authall: a handler panicked", "panic", fmt.Sprint(rec))
				apierr.Write(w, apierr.ErrInternal)
			}
		}()
		inner.ServeHTTP(w, r)
	})
}

// BasePath returns the configured base path.
func (a *Auth) BasePath() string { return a.cfg.basePath }

// Schema returns the effective schema of core plus every registered plugin.
func (a *Auth) Schema() *schema.Schema { return a.effectiveSchema }

// OpenAPI returns the effective OpenAPI document of the enabled API.
func (a *Auth) OpenAPI() *openapi.Document { return a.doc }

// Hooks returns the lifecycle hook registry of the instance.
func (a *Auth) Hooks() *hook.Hooks { return a.hooks }

// CheckSchema reports an actionable error when the database schema is missing
// or outdated. Auth-All never migrates a schema on its own.
func (a *Auth) CheckSchema(ctx context.Context) error {
	return a.cfg.store.Migrator().Check(ctx, a.effectiveSchema)
}

// Migrate applies the effective schema. It runs only when the application or
// the command line tool calls it.
func (a *Auth) Migrate(ctx context.Context) ([]schema.Statement, error) {
	return a.cfg.store.Migrator().Apply(ctx, a.effectiveSchema)
}

// MigrationPlan returns the statements that are not applied yet.
func (a *Auth) MigrationPlan(ctx context.Context) ([]schema.Statement, error) {
	return a.cfg.store.Migrator().Plan(ctx, a.effectiveSchema)
}

// MigrationSQL returns the complete deterministic DDL for one dialect. It needs
// no database connection.
func (a *Auth) MigrationSQL(d schema.Dialect) ([]schema.Statement, error) {
	return schema.Render(d, a.effectiveSchema)
}

// Session returns the session of a request. It returns nil when the request
// carries no valid session.
func (a *Auth) Session(ctx context.Context, r *http.Request) (*store.Session, error) {
	sess, _, err := a.resolveSession(ctx, r)
	return sess, err
}

// User returns the authenticated user of a request. It returns nil when the
// request carries no valid session.
func (a *Auth) User(ctx context.Context, r *http.Request) (*store.User, error) {
	_, user, err := a.resolveSession(ctx, r)
	return user, err
}

// CreateUserInput describes a user created through the programmatic API.
type CreateUserInput struct {
	Email       string
	Password    string
	DisplayName string
	ImageURL    string
	// EmailVerified marks the address as already proven.
	EmailVerified bool
}

// CreateUser creates a user, and a password credential when a password is
// supplied. It returns apierr.ErrEmailAlreadyExists for a duplicate address.
func (a *Auth) CreateUser(ctx context.Context, in CreateUserInput) (*store.User, error) {
	if !email.Valid(in.Email) {
		return nil, apierr.ErrInvalidRequest.WithMessage("The email address is invalid.")
	}
	var hash string
	if in.Password != "" {
		if err := a.checkPassword(in.Password); err != nil {
			return nil, err
		}
		h, err := crypto.HashPassword(in.Password, a.cfg.argon)
		if err != nil {
			return nil, apierr.ErrInternal.WithCause(err)
		}
		hash = h
	}
	return a.createUser(ctx, in, hash)
}

// GetUser returns one user by id.
func (a *Auth) GetUser(ctx context.Context, id string) (*store.User, error) {
	u, err := a.cfg.store.Users().GetByID(ctx, id)
	if err != nil {
		return nil, mapStoreError(err)
	}
	return u, nil
}

// GetUserByEmail returns one user by the normalized form of an address.
func (a *Auth) GetUserByEmail(ctx context.Context, address string) (*store.User, error) {
	u, err := a.cfg.store.Users().GetByNormalizedEmail(ctx, email.Normalize(address))
	if err != nil {
		return nil, mapStoreError(err)
	}
	return u, nil
}

// RevokeSession revokes one session by id.
func (a *Auth) RevokeSession(ctx context.Context, sessionID string) error {
	if err := a.cfg.store.Sessions().Delete(ctx, sessionID); err != nil {
		return mapStoreError(err)
	}
	return nil
}

// RevokeUserSessions revokes every session of one user and returns the count.
func (a *Auth) RevokeUserSessions(ctx context.Context, userID string) (int, error) {
	n, err := a.cfg.store.Sessions().DeleteByUser(ctx, userID)
	if err != nil {
		return 0, mapStoreError(err)
	}
	return n, nil
}

// Accounts returns the external accounts of one user.
func (a *Auth) Accounts(ctx context.Context, userID string) ([]store.Account, error) {
	list, err := a.cfg.store.Accounts().ListByUser(ctx, userID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	return list, nil
}

// Cleanup removes expired sessions, tokens, and OAuth states.
func (a *Auth) Cleanup(ctx context.Context) error {
	now := a.cfg.now()
	if _, err := a.cfg.store.Sessions().DeleteExpired(ctx, now); err != nil {
		return err
	}
	if _, err := a.cfg.store.Tokens().DeleteExpired(ctx, now); err != nil {
		return err
	}
	_, err := a.cfg.store.OAuthStates().DeleteExpired(ctx, now)
	return err
}

func mapStoreError(err error) error {
	switch {
	case err == nil:
		return nil
	case isNotFound(err):
		return apierr.ErrNotFound.WithCause(err)
	case isConflict(err):
		return apierr.ErrEmailAlreadyExists.WithCause(err)
	default:
		return apierr.ErrInternal.WithCause(err)
	}
}
