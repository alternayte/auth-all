// Package apikeys adds machine credentials to Auth-All.
//
// A key authenticates through the Authorization header, so a host route under
// RequireAuth or under a role check accepts it with no change.
//
//	k := apikeys.New(apikeys.Prefix("ak_"), apikeys.MaxTTL(365*24*time.Hour))
//	auth, err := authall.New(authall.WithStore(s), authall.WithPlugins(r, k))
//
// The plaintext key exists one time, in the response of the create route. The
// store keeps the SHA-256 digest.
package apikeys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// ID is the stable plugin identifier.
const ID = "apikeys"

// DefaultPrefix starts every generated key.
const DefaultPrefix = "ak_"

// DefaultTouchInterval limits how often a key request writes the last use
// time.
const DefaultTouchInterval = 60 * time.Second

// keyBytes is the number of random bytes of one key. 32 bytes carry 256 bits,
// which needs no slow hash.
const keyBytes = 32

// startRandomChars is the number of random characters that the display start
// shows.
const startRandomChars = 4

// unitVersion is the version of the migration unit of the key table.
const unitVersion = "20260910000002"

// orgColumnVersion is the version of the unit that adds the organization
// column. The column is nullable, so the unit applies to a database with rows.
const orgColumnVersion = "20261101000007"

// prefixPattern is the accepted form of a key prefix.
var prefixPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,15}$`)

// Plugin is the API keys plugin.
type Plugin struct {
	prefix        string
	maxTTL        time.Duration
	requireExpiry bool
	touchInterval time.Duration
	adminRole     string
	organizations OrganizationResolver

	svc           plugin.Services
	roles         plugin.RoleService
	principals    plugin.PrincipalService
	protect       func(http.Handler) http.Handler
	hooks         *hook.Hooks
	keys          store.APIKeyStore
	now           func() time.Time
	schemaOptions schema.Options
}

// OrganizationResolver answers the organization credential of one key. The
// organizations plugin implements it.
//
// The permissions of an organization key are the intersection of the key
// permissions and the live permissions of the owner in that organization, so a
// demoted member keeps no stronger key.
type OrganizationResolver interface {
	// KeyCredential returns the organization, the membership, and the
	// effective statements of one key. It returns an error when the owner
	// holds no active membership of that organization.
	KeyCredential(ctx context.Context, orgID, ownerID, keyRole string) (
		*store.Organization, *store.Membership, []string, error)
	// KnownRole reports whether the organization holds the role.
	KnownRole(ctx context.Context, orgID, role string) (bool, error)
}

// Option configures the plugin.
type Option func(*Plugin)

// Organizations lets a key name an organization. The value is the
// organizations plugin.
//
//	orgs := organizations.New(...)
//	keys := apikeys.New(apikeys.Organizations(orgs))
func Organizations(r OrganizationResolver) Option {
	return func(p *Plugin) { p.organizations = r }
}

// Prefix starts every generated key. The default is ak_.
func Prefix(value string) Option { return func(p *Plugin) { p.prefix = value } }

// MaxTTL sets the highest accepted lifetime of a key. A key with no expiry
// then fails, unless the host allows one with AllowNoExpiry.
func MaxTTL(d time.Duration) Option {
	return func(p *Plugin) {
		p.maxTTL = d
		p.requireExpiry = true
	}
}

// AllowNoExpiry accepts a key with no expiry, even when a maximum lifetime
// exists.
func AllowNoExpiry() Option { return func(p *Plugin) { p.requireExpiry = false } }

// TouchInterval limits how often a key request writes the last use time. The
// default is 60 seconds.
func TouchInterval(d time.Duration) Option { return func(p *Plugin) { p.touchInterval = d } }

// AdminRole names the role that can list and revoke the keys of another user.
// The default is "admin".
func AdminRole(name string) Option { return func(p *Plugin) { p.adminRole = name } }

// New returns the API keys plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{
		prefix:        DefaultPrefix,
		touchInterval: DefaultTouchInterval,
		adminRole:     "admin",
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// ID implements plugin.Plugin.
func (p *Plugin) ID() string { return ID }

// Register implements plugin.Plugin.
func (p *Plugin) Register(r *plugin.Registry) error {
	if !prefixPattern.MatchString(p.prefix) {
		return fmt.Errorf("authall/apikeys: the prefix %q must match %s", p.prefix, prefixPattern)
	}
	svc := r.Services()
	reader, ok := svc.(plugin.RoleServices)
	if !ok {
		return errors.New("authall/apikeys: the roles plugin must be enabled before the API keys plugin")
	}
	principals, ok := svc.(plugin.PrincipalServices)
	if !ok {
		return errors.New("authall/apikeys: this Auth-All version has no principal service")
	}
	protector, ok := svc.(plugin.ProtectService)
	if !ok {
		return errors.New("authall/apikeys: this Auth-All version has no authentication middleware")
	}
	keys, ok := svc.Store().(store.APIKeyStore)
	if !ok {
		return errors.New("authall/apikeys: the configured store holds no API key")
	}
	p.svc = svc
	p.roles = reader.Roles()
	if len(p.roles.Names()) == 0 {
		return errors.New("authall/apikeys: the roles plugin must be enabled before the API keys plugin")
	}
	p.principals = principals.Principals()
	p.protect = protector.Protect
	p.hooks = r.Hooks()
	p.keys = keys
	p.now = svc.Now
	p.schemaOptions = schema.DefaultOptions()
	if reporter, ok := svc.(plugin.SchemaService); ok {
		p.schemaOptions = reporter.SchemaOptions()
	}

	r.Schema(Table(p.schemaOptions))
	unit, err := unitOf(p.schemaOptions)
	if err != nil {
		return err
	}
	r.Unit(unit)
	orgUnit, err := orgColumnUnit(p.schemaOptions)
	if err != nil {
		return err
	}
	r.Unit(orgUnit)
	r.Resolver(p)
	p.registerOrganizationCleanup(r)

	registerSchemas(r)
	p.registerRoutes(r)
	return nil
}

// Table returns the key table for the physical schema options.
func Table(o schema.Options) schema.Table {
	n := schema.TableNames(o)
	id := schema.TypeText
	if o.IDType == schema.IDUUID {
		id = schema.TypeUUID
	}
	return schema.Table{
		Name: n.APIKeys,
		Columns: []schema.Column{
			{Name: "id", Type: id, PrimaryKey: true},
			{Name: "user_id", Type: id},
			{Name: "name", Type: schema.TypeText},
			// The start shows the prefix and the first random characters, so a
			// person recognizes a key in a list.
			{Name: "start", Type: schema.TypeText},
			{Name: "key_hash", Type: schema.TypeText},
			{Name: "role", Type: schema.TypeText},
			{Name: "created_at", Type: schema.TypeTimestamp},
			{Name: "expires_at", Type: schema.TypeTimestamp, Nullable: true},
			{Name: "last_used_at", Type: schema.TypeTimestamp, Nullable: true},
			{Name: "revoked_at", Type: schema.TypeTimestamp, Nullable: true},
			{Name: "revoked_by", Type: id, Nullable: true},
			// The organization of the key. A null value means a key of the
			// whole application.
			{Name: "org_id", Type: id, Nullable: true},
		},
		Indexes: []schema.Index{
			{Name: o.Name("apikeys_key_hash_key"), Columns: []string{"key_hash"}, Unique: true},
			{Name: o.Name("apikeys_user_id_idx"), Columns: []string{"user_id"}},
		},
		ForeignKeys: []schema.ForeignKey{
			{Column: "user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "CASCADE"},
		},
	}
}

// unitOf returns the migration unit of the key table. The unit holds the
// columns of the v0.3.0 release, and it never changes.
func unitOf(o schema.Options) (schema.Unit, error) {
	table := Table(o)
	// The released unit creates the v0.3.0 columns only. The organization
	// column arrives in its own unit.
	table.Columns = table.Columns[:len(table.Columns)-1]
	return schema.TableUnit(unitVersion, ID, "authall_apikeys",
		[]schema.Dialect{schema.Postgres, schema.SQLite}, []schema.Table{table})
}

// orgColumnExtension returns the organization column of the key table.
func orgColumnExtension(o schema.Options) schema.Extension {
	n := schema.TableNames(o)
	id := schema.TypeText
	if o.IDType == schema.IDUUID {
		id = schema.TypeUUID
	}
	return schema.Extension{
		Table:   n.APIKeys,
		Columns: []schema.Column{{Name: "org_id", Type: id, Nullable: true}},
	}
}

// orgColumnUnit returns the unit that adds the organization column.
func orgColumnUnit(o schema.Options) (schema.Unit, error) {
	return schema.ExtensionUnit(orgColumnVersion, ID, "authall_apikeys_org_column",
		[]schema.Dialect{schema.Postgres, schema.SQLite}, []schema.Extension{orgColumnExtension(o)})
}

// Claims implements plugin.CredentialResolver. It reads the shape of the value
// only, and it makes no database call.
func (p *Plugin) Claims(bearer string) bool { return strings.HasPrefix(bearer, p.prefix) }

// Resolve implements plugin.CredentialResolver.
//
// A revoked key, an expired key, an unknown key, and a key of a disabled owner
// give one error, so the caller learns nothing about the key.
func (p *Plugin) Resolve(ctx context.Context, bearer string) (*plugin.Principal, error) {
	key, user, err := p.keys.APIKeyByHash(ctx, digest(bearer))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, apierr.ErrUnauthorized
		}
		return nil, apierr.ErrInternal.WithCause(err)
	}
	now := p.now()
	switch {
	case key.RevokedAt != nil,
		key.ExpiresAt != nil && !now.Before(*key.ExpiresAt),
		user.DisabledAt != nil:
		return nil, apierr.ErrUnauthorized
	}
	// The effective role is the lower of the key role and the current owner
	// role, so a demoted owner keeps no stronger key.
	role := key.Role
	ownerRole := p.roleOf(user)
	if p.roles.Rank(ownerRole) < p.roles.Rank(role) {
		role = ownerRole
	}
	principal := &plugin.Principal{User: user, APIKey: key, Role: role, Method: "api_key"}
	if key.OrgID != nil && *key.OrgID != "" {
		if p.organizations == nil {
			// The key names an organization that this instance cannot resolve,
			// so it authenticates nothing. Default deny.
			return nil, apierr.ErrUnauthorized
		}
		org, member, permissions, err := p.organizations.KeyCredential(ctx, *key.OrgID, user.ID, key.Role)
		if err != nil {
			// A key of an organization that the owner left never
			// authenticates.
			return nil, apierr.ErrUnauthorized
		}
		principal.Organization = org
		principal.Membership = member
		principal.Permissions = permissions
	}
	p.touch(ctx, key, now)
	return principal, nil
}

// touch writes the last use time at most once for each interval.
func (p *Plugin) touch(ctx context.Context, key *store.APIKey, now time.Time) {
	if key.LastUsedAt != nil && now.Sub(*key.LastUsedAt) < p.touchInterval {
		return
	}
	if err := p.keys.TouchAPIKey(ctx, key.ID, now); err != nil {
		p.svc.Logger().Error("authall/apikeys: cannot write the last use time", "error", err.Error())
	}
}

// roleOf returns the effective role of one user.
func (p *Plugin) roleOf(u *store.User) string {
	if u.Role == "" {
		return p.roles.Default()
	}
	return u.Role
}

// CreateInput describes a new key.
type CreateInput struct {
	// UserID is the owner of the key.
	UserID string
	// Name is the label of the owner. It has 1 to 100 characters.
	Name string
	// Role is the role of the key. An empty value takes the role of the owner.
	Role string
	// ExpiresAt ends the key. A nil value means no expiry.
	ExpiresAt *time.Time
	// OrgID names the organization of the key. An empty value creates a key of
	// the whole application.
	OrgID string
}

// Create returns a new key and its plaintext value. The plaintext exists only
// in this return value.
func (p *Plugin) Create(ctx context.Context, owner *store.User, in CreateInput) (*store.APIKey, string, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len([]rune(name)) > 100 {
		return nil, "", apierr.ErrInvalidRequest.WithMessage("The name must have 1 to 100 characters.")
	}
	now := p.now()
	if in.ExpiresAt == nil {
		if p.requireExpiry {
			return nil, "", apierr.ErrAPIKeyExpiryRequired
		}
	} else {
		if !in.ExpiresAt.After(now) {
			return nil, "", apierr.ErrInvalidRequest.WithMessage("The expiry must be in the future.")
		}
		if p.maxTTL > 0 && in.ExpiresAt.Sub(now) > p.maxTTL {
			return nil, "", apierr.ErrAPIKeyExpiryTooLong
		}
	}
	role := in.Role
	if in.OrgID != "" {
		if p.organizations == nil {
			return nil, "", apierr.ErrInvalidRequest.WithMessage("This application holds no organization.")
		}
		// The owner must hold an active membership of that organization. The
		// resolver refuses every other case.
		if _, _, _, err := p.organizations.KeyCredential(ctx, in.OrgID, owner.ID, role); err != nil {
			return nil, "", err
		}
		if role != "" {
			known, err := p.organizations.KnownRole(ctx, in.OrgID, role)
			if err != nil {
				return nil, "", err
			}
			if !known {
				return nil, "", apierr.ErrRoleUnknown
			}
		}
	} else {
		if role == "" {
			role = p.roleOf(owner)
		}
		if p.roles.Rank(role) < 0 {
			return nil, "", apierr.ErrRoleUnknown
		}
		if p.roles.Rank(role) > p.roles.Rank(p.roleOf(owner)) {
			// A key never has more power than its owner.
			return nil, "", apierr.ErrRoleNotAllowed
		}
	}
	plaintext, err := newKey(p.prefix)
	if err != nil {
		return nil, "", apierr.ErrInternal.WithCause(err)
	}
	key := &store.APIKey{
		ID:        uuid.NewString(),
		UserID:    owner.ID,
		Name:      name,
		Start:     start(plaintext, p.prefix),
		KeyHash:   digest(plaintext),
		Role:      role,
		CreatedAt: now,
		ExpiresAt: in.ExpiresAt,
	}
	if in.OrgID != "" {
		orgID := in.OrgID
		key.OrgID = &orgID
	}
	if err := p.keys.CreateAPIKey(ctx, key); err != nil {
		return nil, "", apierr.ErrInternal.WithCause(err)
	}
	p.hooks.RunAfterAPIKeyCreate(ctx, &hook.APIKeyEvent{Key: key, User: owner})
	p.emit(ctx, events.APIKeyCreated, owner.ID, map[string]any{"key_id": key.ID, "role": role})
	return key, plaintext, nil
}

// Revoke ends one key. actor names the user that revokes it.
func (p *Plugin) Revoke(ctx context.Context, keyID string, actor *store.User, isAdmin bool) error {
	key, err := p.keys.APIKeyByID(ctx, keyID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return apierr.ErrNotFound
		}
		return apierr.ErrInternal.WithCause(err)
	}
	if key.UserID != actor.ID && !isAdmin {
		// The response never tells whether the key of another owner exists.
		return apierr.ErrNotFound
	}
	if err := p.keys.RevokeAPIKey(ctx, key.ID, actor.ID, p.now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return apierr.ErrNotFound
		}
		return apierr.ErrInternal.WithCause(err)
	}
	p.hooks.RunAfterAPIKeyRevoke(ctx, &hook.APIKeyEvent{Key: key, User: actor})
	p.emit(ctx, events.APIKeyRevoked, key.UserID, map[string]any{"key_id": key.ID})
	return nil
}

// List returns every key of one owner.
func (p *Plugin) List(ctx context.Context, userID string) ([]store.APIKey, error) {
	keys, err := p.keys.ListAPIKeys(ctx, userID)
	if err != nil {
		return nil, apierr.ErrInternal.WithCause(err)
	}
	return keys, nil
}

// emit sends one audit event with the caller as the actor.
func (p *Plugin) emit(ctx context.Context, name events.Name, target string, fields map[string]any) {
	actor, ok := events.ActorFrom(ctx)
	if !ok || actor.ID == "" {
		actor.ID = events.ActorSystem
	}
	p.svc.Events().EmitEvent(ctx, events.Event{
		Name:   name,
		UserID: target,
		Target: target,
		Actor:  actor.ID,
		Method: actor.Method,
		IP:     actor.IP,
		Fields: fields,
	})
}

// newKey returns one plaintext key. The random part carries 32 bytes from
// crypto/rand, encoded as unpadded base64url.
func newKey(prefix string) (string, error) {
	raw := make([]byte, keyBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// start returns the display start of one key.
func start(plaintext, prefix string) string {
	random := strings.TrimPrefix(plaintext, prefix)
	if len(random) > startRandomChars {
		random = random[:startRandomChars]
	}
	return prefix + random
}

// digest returns the SHA-256 hex digest of one key.
func digest(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// registerSchemas adds the component schemas of the key responses.
func registerSchemas(r *plugin.Registry) {
	key := openapi.Object(
		[]string{"id", "name", "start", "role", "createdAt"},
		map[string]*openapi.Schema{
			"id":         openapi.String(),
			"userId":     openapi.String(),
			"name":       openapi.String(),
			"start":      openapi.String(),
			"role":       openapi.String(),
			"createdAt":  {Type: "string", Format: "date-time"},
			"expiresAt":  {Type: "string", Format: "date-time", Nullable: true},
			"lastUsedAt": {Type: "string", Format: "date-time", Nullable: true},
			"revokedAt":  {Type: "string", Format: "date-time", Nullable: true},
			"orgId":      {Type: "string", Nullable: true},
		})
	r.OpenAPISchema("APIKey", key)
	r.OpenAPISchema("APIKeyListResponse", openapi.Object([]string{"keys"},
		map[string]*openapi.Schema{"keys": {Type: "array", Items: openapi.Ref("APIKey")}}))
	r.OpenAPISchema("APIKeyCreateResponse", openapi.Object([]string{"key", "plaintext"},
		map[string]*openapi.Schema{
			"key": openapi.Ref("APIKey"),
			// The plaintext appears one time, in this response.
			"plaintext": openapi.String(),
		}))
}

// NewPlaintextKey returns one plaintext key with the given prefix. A test uses
// it to check the shape of a key with no database.
func NewPlaintextKey(prefix string) (string, error) { return newKey(prefix) }

// registerOrganizationCleanup removes the keys of one organization in the
// transaction of its deletion.
//
// The application deletes its own rows in the same transaction, so no orphan
// survives. The hook runs only when the host wired the organizations plugin.
func (p *Plugin) registerOrganizationCleanup(r *plugin.Registry) {
	if p.organizations == nil {
		return
	}
	table := schema.TableNames(p.schemaOptions).APIKeys
	r.Hooks().OnBeforeOrganizationDelete(func(ctx context.Context, ev *hook.OrganizationEvent) error {
		deleter, ok := ev.Tx.(store.RowDeleter)
		if !ok {
			return errors.New("authall/apikeys: the configured store cannot remove the keys of an organization")
		}
		_, err := deleter.DeleteRows(ctx, table, "org_id", ev.Org.ID)
		return err
	})
}
