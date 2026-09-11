package schema

import (
	"fmt"
	"regexp"
	"strings"
)

// DefaultPrefix is the prefix of every Auth-All object when the host sets no
// other value. It keeps the v1 names.
const DefaultPrefix = "auth_"

// IDType selects the physical type of every primary key and foreign key.
type IDType string

// Supported identifier types.
const (
	// IDText stores an identifier as text. This is the v1 behavior.
	IDText IDType = "text"
	// IDUUID stores an identifier as a PostgreSQL uuid. SQLite keeps text.
	IDUUID IDType = "uuid"
)

// prefixPattern is the accepted form of a table prefix.
var prefixPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// UserField is one host-owned column on the users table.
type UserField struct {
	// Name is the column name.
	Name string
	// Type is the column type.
	Type Type
	// Nullable allows a null value.
	Nullable bool
	// Default is the rendered SQL default. An empty value adds no default.
	Default string
	// Input allows an HTTP route to write the field. The default is false.
	Input bool
	// Returned allows a response to carry the field. The default is false.
	Returned bool
}

// Options configure the physical schema.
type Options struct {
	// Prefix starts every table name, index name, and record table name.
	Prefix string
	// IDType selects the physical type of the identifier columns.
	IDType IDType
	// UserFields are host-owned columns on the users table.
	UserFields []UserField
	// OrgFields are host-owned columns on the organizations table. They apply
	// only when the organizations plugin is enabled.
	OrgFields []UserField
}

// DefaultOptions returns the v1 physical schema.
func DefaultOptions() Options { return Options{Prefix: DefaultPrefix, IDType: IDText} }

// Normalize fills the empty fields and reports an invalid option.
func (o Options) Normalize() (Options, error) {
	if o.Prefix == "" {
		o.Prefix = DefaultPrefix
	}
	if !prefixPattern.MatchString(o.Prefix) {
		return Options{}, fmt.Errorf("authall/schema: the table prefix %q must match %s", o.Prefix, prefixPattern)
	}
	switch o.IDType {
	case "":
		o.IDType = IDText
	case IDText, IDUUID:
	default:
		return Options{}, fmt.Errorf("authall/schema: unsupported id type %q", o.IDType)
	}
	seen := map[string]bool{}
	for _, f := range o.UserFields {
		if f.Name == "" {
			return Options{}, fmt.Errorf("authall/schema: a user field has an empty name")
		}
		if !prefixPattern.MatchString(f.Name) {
			return Options{}, fmt.Errorf("authall/schema: the user field %q must match %s", f.Name, prefixPattern)
		}
		if seen[f.Name] {
			return Options{}, fmt.Errorf("authall/schema: the user field %q is declared twice", f.Name)
		}
		if reservedUserColumns[f.Name] {
			return Options{}, fmt.Errorf("authall/schema: the user field %q is an Auth-All column", f.Name)
		}
		switch f.Type {
		case TypeText, TypeTimestamp, TypeInt, TypeBool:
		default:
			return Options{}, fmt.Errorf("authall/schema: the user field %q has the unsupported type %q", f.Name, f.Type)
		}
		seen[f.Name] = true
	}
	orgSeen := map[string]bool{}
	for _, f := range o.OrgFields {
		if f.Name == "" {
			return Options{}, fmt.Errorf("authall/schema: an organization field has an empty name")
		}
		if !prefixPattern.MatchString(f.Name) {
			return Options{}, fmt.Errorf("authall/schema: the organization field %q must match %s", f.Name, prefixPattern)
		}
		if orgSeen[f.Name] {
			return Options{}, fmt.Errorf("authall/schema: the organization field %q is declared twice", f.Name)
		}
		if reservedOrgColumns[f.Name] {
			return Options{}, fmt.Errorf("authall/schema: the organization field %q is an Auth-All column", f.Name)
		}
		switch f.Type {
		case TypeText, TypeTimestamp, TypeInt, TypeBool:
		default:
			return Options{}, fmt.Errorf("authall/schema: the organization field %q has the unsupported type %q", f.Name, f.Type)
		}
		orgSeen[f.Name] = true
	}
	return o, nil
}

// idType returns the column type of an identifier column.
func (o Options) idType() Type {
	if o.IDType == IDUUID {
		return TypeUUID
	}
	return TypeText
}

// Name returns the physical name of one base object name.
func (o Options) Name(base string) string { return o.Prefix + base }

// Names holds the physical name of every Auth-All table.
type Names struct {
	Users        string
	Credentials  string
	Accounts     string
	Sessions     string
	Tokens       string
	OAuthStates  string
	TOTP         string
	TOTPRecovery string
	APIKeys      string
	RateLimits   string
	Bootstrap    string
	Migrations   string
}

// Base names of the Auth-All tables. The physical name is the prefix plus the
// base name.
const (
	baseUsers        = "users"
	baseCredentials  = "credentials"
	baseAccounts     = "accounts"
	baseSessions     = "sessions"
	baseTokens       = "tokens"
	baseOAuthStates  = "oauth_states"
	baseTOTP         = "totp"
	baseTOTPRecovery = "totp_recovery"
	baseAPIKeys      = "api_keys"
	baseRateLimits   = "rate_limits"
	baseBootstrap    = "bootstrap"
	baseMigrations   = "schema_migrations"
)

// TableNames returns the physical table names for the options.
func TableNames(o Options) Names {
	return Names{
		Users:        o.Name(baseUsers),
		Credentials:  o.Name(baseCredentials),
		Accounts:     o.Name(baseAccounts),
		Sessions:     o.Name(baseSessions),
		Tokens:       o.Name(baseTokens),
		OAuthStates:  o.Name(baseOAuthStates),
		TOTP:         o.Name(baseTOTP),
		TOTPRecovery: o.Name(baseTOTPRecovery),
		APIKeys:      o.Name(baseAPIKeys),
		RateLimits:   o.Name(baseRateLimits),
		Bootstrap:    o.Name(baseBootstrap),
		Migrations:   o.Name(baseMigrations),
	}
}

// DefaultNames returns the v1 table names.
func DefaultNames() Names { return TableNames(DefaultOptions()) }

// reservedUserColumns names the columns that Auth-All owns on the users table.
var reservedUserColumns = map[string]bool{
	"id": true, "email": true, "email_normalized": true, "email_verified_at": true,
	"display_name": true, "image_url": true, "created_at": true, "updated_at": true,
	"role": true, "disabled_at": true, "must_change_password": true,
}

// reservedOrgColumns names the columns that Auth-All owns on the organizations
// table.
var reservedOrgColumns = map[string]bool{
	"id": true, "name": true, "slug": true, "created_at": true, "updated_at": true,
}

// Extension adds columns and indexes to a table that another owner declared.
type Extension struct {
	// Table is the physical name of the target table.
	Table string
	// Columns are the added columns. An added column is nullable, or it has a
	// default, because the target table can already hold rows.
	Columns []Column
	// Indexes are the added indexes.
	Indexes []Index
}

// Validate reports an unusable extension.
func (e Extension) Validate() error {
	if strings.TrimSpace(e.Table) == "" {
		return fmt.Errorf("authall/schema: an extension names no table")
	}
	if len(e.Columns) == 0 && len(e.Indexes) == 0 {
		return fmt.Errorf("authall/schema: the extension of %q adds nothing", e.Table)
	}
	for _, c := range e.Columns {
		if c.Name == "" {
			return fmt.Errorf("authall/schema: the extension of %q has an unnamed column", e.Table)
		}
		if !c.Nullable && c.Default == "" {
			return fmt.Errorf("authall/schema: the added column %q of %q needs a default or must be nullable",
				c.Name, e.Table)
		}
	}
	return nil
}
