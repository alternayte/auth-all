package authall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/migrations"
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
	tokenKindChangeEmail   = "email-change"
	tokenKindDeleteAccount = "delete-account"
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
	// resolvers hold the credential resolvers of the plugins, in registration
	// order.
	resolvers []plugin.CredentialResolver
	// principals caches resolved principals inside the consistency bound. It
	// is nil when the host enabled no cache.
	principals *principalCache
	// crossOrigin refuses an unsafe cross-site request on a host route. It is
	// nil when the host turned the check off.
	crossOrigin *http.CrossOriginProtection
	// roleHierarchy names the configured roles from the lowest to the highest.
	// It is nil until the roles plugin installs it.
	roleHierarchy []string
	// defaultRole names the role of a user whose role column is empty. The
	// roles plugin sets it.
	defaultRole string
	svc         *services
	routes      []RouteInfo
	// registering names the plugin whose routes are mounted right now.
	registering string

	dummyHashOnce sync.Once
	dummyHash     string
}

// RouteInfo describes one mounted Auth-All route.
type RouteInfo struct {
	Method string
	// Path is the complete path, including the configured base path.
	Path string
	// PluginID names the contributing plugin. It is empty for a core route.
	PluginID string
	// Documented reports whether the route appears in the OpenAPI document.
	Documented bool
}

// New builds an Auth-All instance from functional options.
func New(opts ...Option) (*Auth, error) {
	cfg := &config{
		basePath:       DefaultBasePath,
		passwordPolicy: DefaultPasswordPolicy(),
		argon:          crypto.DefaultArgon2Params(),
		cookie:         CookieOptions{Name: DefaultCookieName, Path: "/", SameSite: http.SameSiteLaxMode},
		// normalizeConfig fills IdleTimeout, because it depends on TTL.
		session: SessionOptions{TTL: DefaultSessionTTL, TouchInterval: DefaultSessionTouchInterval},
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
	if cfg.consistencyBound <= 0 {
		cfg.consistencyBound = DefaultConsistencyBound
	}
	if cfg.principalCacheTTL > 0 {
		if cfg.principalCacheTTL > cfg.consistencyBound {
			return nil, fmt.Errorf(
				"authall: the principal cache time %s is above the consistency bound %s. "+
					"A cached principal would keep a disabled user, a demoted user, or a revoked "+
					"credential alive past the bound. Use authall.WithConsistencyBound, or a shorter cache time",
				cfg.principalCacheTTL, cfg.consistencyBound)
		}
		a.principals = newPrincipalCache(cfg.principalCacheTTL, cfg.now)
	}
	a.trustedOrigins = buildTrustedOrigins(cfg)
	if cfg.hostOriginCheck == nil {
		on := true
		cfg.hostOriginCheck = &on
	}
	if *cfg.hostOriginCheck {
		protection := http.NewCrossOriginProtection()
		for _, origin := range a.trustedOrigins {
			if err := protection.AddTrustedOrigin(origin); err != nil {
				return nil, fmt.Errorf("authall: the trusted origin %q is not usable for the origin check: %w",
					origin, err)
			}
		}
		a.crossOrigin = protection
	} else {
		// A host route with no origin check accepts a cross-site form post
		// from any page that the browser sends the session cookie with.
		cfg.logger.Warn("authall: the host route origin check is off. " +
			"A cross-site page can then send an unsafe request with the session cookie of the user. " +
			"Use authall.WithHostOriginCheck(true), or refuse a cross-site request in another layer.")
	}

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

	sopts, err := cfg.schemaOptions.Normalize()
	if err != nil {
		return nil, err
	}
	cfg.schemaOptions = sopts
	sc, err := schema.NewCoreWithOptions(sopts)
	if err != nil {
		return nil, err
	}
	a.effectiveSchema = sc
	if err := applySchemaOptions(cfg.store, sopts); err != nil {
		return nil, err
	}
	if err := addContributedSchema(sc, sopts, cfg.limiter); err != nil {
		return nil, err
	}
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
		a.registering = id
		reg := plugin.NewRegistry(id, a.svc, a.hooks)
		if err := p.Register(reg); err != nil {
			return nil, fmt.Errorf("authall: the plugin %q failed to register: %w", id, err)
		}
		for _, t := range reg.Tables() {
			if err := a.effectiveSchema.Add(t); err != nil {
				return nil, fmt.Errorf("authall: the plugin %q contributed an invalid table: %w", id, err)
			}
		}
		for _, u := range reg.Units() {
			if err := a.effectiveSchema.AddUnit(u); err != nil {
				return nil, fmt.Errorf("authall: the plugin %q contributed an invalid migration unit: %w", id, err)
			}
		}
		for _, e := range reg.Extensions() {
			if err := a.effectiveSchema.Extend(e); err != nil {
				return nil, fmt.Errorf("authall: the plugin %q contributed an invalid extension: %w", id, err)
			}
		}
		a.resolvers = append(a.resolvers, reg.Resolvers()...)
		for name, s := range reg.ComponentSchemas() {
			a.doc.AddSchema(name, s)
		}
		for _, rt := range reg.Routes() {
			if err := a.mount(rt.Method, rt.Path, rt.Handler, rt.Operation); err != nil {
				return nil, fmt.Errorf("authall: the plugin %q contributed an invalid route: %w", id, err)
			}
		}
		a.registering = ""
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
		if cfg.strictRateLimiting {
			return fmt.Errorf("authall: no rate limiter is configured, and authall.WithStrictRateLimiting is set. " +
				"Use authall.WithRateLimiter, for example " +
				"authall.WithRateLimiter(ratelimit.NewMemory(10, time.Minute))")
		}
		// A silent start with no limiter is the common production mistake, so
		// the warning names the risk and the two options.
		cfg.logger.Warn("authall: no rate limiter is configured. " +
			"Sign-in, sign-up, password reset, and every other sensitive endpoint accepts unlimited attempts, " +
			"so a brute-force attack and an enumeration attack run without a bound. " +
			"Use authall.WithRateLimiter, or use authall.WithStrictRateLimiting to fail the construction instead.")
		cfg.limiter = ratelimit.LimiterFunc(func(context.Context, ratelimit.Key) (bool, error) { return true, nil })
	}
	if _, memory := cfg.limiter.(*ratelimit.Memory); memory && cfg.strictRateLimiting {
		// The memory limiter keeps its counters in process memory, which the
		// consistency bound does not cover. It holds no authorization state,
		// so it stays allowed, and the entry names the effect.
		cfg.logger.Warn("authall: the configured rate limiter keeps its counters in process memory. " +
			"Each instance then counts on its own, so the effective limit grows with the number of instances. " +
			"Use ratelimit/storelimit for a shared count.")
	}
	if cfg.cookie.Name == "" {
		cfg.cookie.Name = DefaultCookieName
	}
	if !validCookieName(cfg.cookie.Name) {
		// A browser drops a cookie whose name is not a token, so the session
		// would never come back.
		return fmt.Errorf("authall: the cookie name %q is not a valid cookie token. "+
			"Use letters, digits, and the characters !#$%%&'*+-.^_`|~", cfg.cookie.Name)
	}
	if cfg.cookie.Path == "" {
		cfg.cookie.Path = "/"
	}
	if cfg.cookie.SameSite == 0 {
		cfg.cookie.SameSite = http.SameSiteLaxMode
	}
	if cfg.cookie.SameSite == http.SameSiteNoneMode && !cookieSecure(cfg) {
		// A browser refuses a cookie with SameSite=None and no Secure
		// attribute, so the session would never reach the server.
		return fmt.Errorf("authall: a cookie with SameSite=None must be Secure. " +
			"A browser refuses the pair, so no session survives. " +
			"Serve the application over HTTPS and remove the Secure override, " +
			"or use http.SameSiteLaxMode for local development")
	}
	if cfg.session.TTL <= 0 {
		cfg.session.TTL = DefaultSessionTTL
	}
	if cfg.session.IdleTimeout <= 0 {
		// A short absolute lifetime keeps the idle timeout below it, so a
		// caller that sets only the lifetime needs no second value.
		cfg.session.IdleTimeout = DefaultSessionIdleTimeout
		if cfg.session.IdleTimeout > cfg.session.TTL {
			cfg.session.IdleTimeout = cfg.session.TTL
		}
	} else if cfg.session.IdleTimeout > cfg.session.TTL {
		// An idle timeout above the absolute lifetime never fires, which hides
		// the intent of the caller.
		return fmt.Errorf(
			"authall: the session idle timeout %s is above the absolute lifetime %s. Use authall.WithSessionLifetime",
			cfg.session.IdleTimeout, cfg.session.TTL)
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
	if err := checkArgon2(cfg.argon); err != nil {
		return err
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
	for _, raw := range cfg.trustedProxies {
		block, err := parseProxyBlock(raw)
		if err != nil {
			return fmt.Errorf(
				"authall: the trusted proxy %q must be a CIDR block or an IP address, for example 10.0.0.0/8", raw)
		}
		cfg.proxyNets = append(cfg.proxyNets, block)
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
	a.mux.Handle(method+" "+path, a.withAudit(h))
	if op != nil {
		a.doc.AddOperation(method, a.cfg.basePath+path, op)
	}
	a.routes = append(a.routes, RouteInfo{
		Method:     method,
		Path:       a.cfg.basePath + path,
		PluginID:   a.registering,
		Documented: op != nil,
	})
	return nil
}

// withAudit puts the client address of the request in the context, so every
// event of the request carries it.
func (a *Auth) withAudit(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := events.WithActor(r.Context(), events.Actor{IP: a.clientIP(r)})
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Routes returns every mounted route of the enabled API.
func (a *Auth) Routes() []RouteInfo { return append([]RouteInfo(nil), a.routes...) }

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
				a.writeError(w, r, apierr.ErrInternal)
			}
		}()
		inner.ServeHTTP(w, r)
	})
}

// Store returns the configured storage adapter. The application owns it.
func (a *Auth) Store() store.Store { return a.cfg.store }

// ConsistencyBound returns the configured bound.
func (a *Auth) ConsistencyBound() time.Duration { return a.cfg.consistencyBound }

// BasePath returns the configured base path.
func (a *Auth) BasePath() string { return a.cfg.basePath }

// RevokeOtherSessions removes every session of the owner of sessionID, except
// that session. It returns the number of removed sessions.
//
// The session that the caller names stays valid, so the person keeps the
// current browser and loses every other one.
func (a *Auth) RevokeOtherSessions(ctx context.Context, sessionID string) (int, error) {
	if sessionID == "" {
		return 0, apierr.ErrInvalidRequest.WithMessage("A session identifier is required.")
	}
	if revoker, ok := a.cfg.store.(store.SessionRevoker); ok {
		n, err := revoker.DeleteSessionsExcept(ctx, sessionID)
		if err != nil {
			return 0, apierr.ErrInternal.WithCause(err)
		}
		return n, nil
	}
	return 0, apierr.ErrInternal.WithCause(
		errors.New("authall: the configured store revokes no other session. Use a first-party store"))
}

// HandlerStripped returns the Auth-All handler for a router that already
// removed the base path.
//
//	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", auth.HandlerStripped()))
//
// Handler removes the base path itself, so a router that also removes it would
// leave no path for the route table.
func (a *Auth) HandlerStripped() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				a.cfg.logger.Error("authall: a handler panicked", "panic", fmt.Sprint(rec))
				a.writeError(w, r, apierr.ErrInternal)
			}
		}()
		a.mux.ServeHTTP(w, r)
	})
}

// Schema returns the effective schema of core plus every registered plugin.
func (a *Auth) Schema() *schema.Schema { return a.effectiveSchema }

// OpenAPI returns the effective OpenAPI document of the enabled API.
func (a *Auth) OpenAPI() *openapi.Document { return a.doc }

// Hooks returns the lifecycle hook registry of the instance.
func (a *Auth) Hooks() *hook.Hooks { return a.hooks }

// minArgon2Memory is the lowest accepted memory cost in KiB. RFC 9106 names
// 19 MiB as the low-memory parameter set.
const minArgon2Memory = 19 * 1024

// checkArgon2 refuses a cost that is below the accepted minimum.
func checkArgon2(p crypto.Argon2Params) error {
	if p.Memory < minArgon2Memory {
		return fmt.Errorf("authall: the argon2id memory %d KiB is below the minimum of %d KiB. "+
			"Use authall.WithArgon2Params with a higher memory", p.Memory, minArgon2Memory)
	}
	if p.Iterations < 1 {
		return fmt.Errorf("authall: the argon2id time cost must be 1 or more")
	}
	if p.Parallelism < 1 {
		return fmt.Errorf("authall: the argon2id parallelism must be 1 or more")
	}
	if p.SaltLength < 16 {
		return fmt.Errorf("authall: the argon2id salt must be 16 bytes or more")
	}
	if p.KeyLength < 32 {
		return fmt.Errorf("authall: the argon2id key must be 32 bytes or more")
	}
	return nil
}

// validCookieName reports whether name is an HTTP token. A browser drops every
// other name.
func validCookieName(name string) bool {
	if name == "" {
		return false
	}
	const separators = "!#$%&'*+-.^_`|~"
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.ContainsRune(separators, c):
		default:
			return false
		}
	}
	return true
}

// SchemaContributor is an optional interface of a component that owns a table,
// for example the store-backed rate limiter. Auth-All adds the tables and the
// migration units of a contributor to the effective schema.
type SchemaContributor interface {
	// SchemaTables returns the tables of the contributor.
	SchemaTables(o schema.Options) []schema.Table
	// SchemaUnits returns the migration units of the contributor.
	SchemaUnits(o schema.Options) ([]schema.Unit, error)
}

// addContributedSchema adds the tables and the units of every contributor.
func addContributedSchema(sc *schema.Schema, o schema.Options, parts ...any) error {
	for _, part := range parts {
		c, ok := part.(SchemaContributor)
		if !ok {
			continue
		}
		for _, t := range c.SchemaTables(o) {
			if err := sc.Add(t); err != nil {
				return err
			}
		}
		units, err := c.SchemaUnits(o)
		if err != nil {
			return err
		}
		for _, u := range units {
			if err := sc.AddUnit(u); err != nil {
				return err
			}
		}
	}
	return nil
}

// applySchemaOptions passes the physical options to a store that accepts them.
// A store that ignores them must keep the v1 names, so a host that sets a
// prefix gets an error instead of a wrong query.
func applySchemaOptions(s store.Store, o schema.Options) error {
	if o.Prefix == schema.DefaultPrefix && o.IDType == schema.IDText && len(o.UserFields) == 0 {
		return nil
	}
	c, ok := s.(store.SchemaConfigurable)
	if !ok {
		return fmt.Errorf("authall: the configured store does not accept schema options. " +
			"Use a first-party store, or remove authall.WithSchema")
	}
	return c.UseSchema(o)
}

// CheckSchema reports an actionable error when the database schema is missing
// or outdated. Auth-All never migrates a schema on its own.
//
// The default mode reads the Auth-All record table. SchemaCheckCatalog reads
// the database catalog, which fits a host that applies the exported migrations
// with its own tool.
func (a *Auth) CheckSchema(ctx context.Context) error {
	if a.cfg.schemaCheck == SchemaCheckCatalog {
		return a.checkCatalog(ctx)
	}
	return a.cfg.store.Migrator().Check(ctx, a.effectiveSchema)
}

// checkCatalog compares the effective schema with the catalog of the database.
// The error names every absent table and every absent column.
func (a *Auth) checkCatalog(ctx context.Context) error {
	inspector, ok := a.cfg.store.(store.CatalogInspector)
	if !ok {
		return fmt.Errorf("authall: the configured store cannot read the database catalog. " +
			"Use authall.WithSchemaCheck(authall.SchemaCheckRecord)")
	}
	var missing []string
	for _, t := range a.effectiveSchema.Tables() {
		columns, exists, err := inspector.TableColumns(ctx, t.Name)
		if err != nil {
			return fmt.Errorf("authall: cannot read the database catalog: %w", err)
		}
		if !exists {
			missing = append(missing, "table "+t.Name)
			continue
		}
		have := map[string]bool{}
		for _, c := range columns {
			have[c] = true
		}
		for _, c := range t.Columns {
			if !have[c.Name] {
				missing = append(missing, "column "+t.Name+"."+c.Name)
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("authall: the database schema is incomplete. Missing: %s. "+
		"Apply the exported Auth-All migrations", strings.Join(missing, ", "))
}

// ExportMigrations returns the migration files of the enabled units, sorted by
// version. The host applies them with its own migration tool.
func (a *Auth) ExportMigrations(d schema.Dialect, f migrations.Format) ([]migrations.File, error) {
	units, err := a.effectiveSchema.Units()
	if err != nil {
		return nil, err
	}
	return migrations.Render(units, d, f)
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
	// Extra holds the host-owned user fields. A field that the host did not
	// declare is dropped.
	//
	// The field is a pointer, so a CreateUserInput value stays comparable.
	Extra *store.ExtraFields
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

// VerifyEmailToken consumes an email verification token and records that the
// user controls the address. It exists so an application can verify an address
// from its own page without a call to the HTTP API.
func (a *Auth) VerifyEmailToken(ctx context.Context, token string) (*store.User, error) {
	tok, err := a.consumeToken(ctx, tokenKindVerifyEmail, token)
	if err != nil {
		return nil, err
	}
	if tok.UserID == nil {
		return nil, apierr.ErrInvalidToken
	}
	// The proof revokes every session of the user, because a session can
	// predate the proof. It keeps the password credential, because this flow
	// cannot tell the account owner apart from the victim of a pre-account
	// hijack. See docs/guides/security-model.md.
	if err := a.proveEmailOwnership(ctx, *tok.UserID, true); err != nil {
		return nil, err
	}
	return a.GetUser(ctx, *tok.UserID)
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
