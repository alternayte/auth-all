package schema

// Core table names. They hold the v1 names, which the default prefix produces.
// A schema with another prefix uses Schema.Names instead.
const (
	TableUsers        = DefaultPrefix + baseUsers
	TableCredentials  = DefaultPrefix + baseCredentials
	TableAccounts     = DefaultPrefix + baseAccounts
	TableSessions     = DefaultPrefix + baseSessions
	TableTokens       = DefaultPrefix + baseTokens
	TableOAuthStates  = DefaultPrefix + baseOAuthStates
	TableTOTP         = DefaultPrefix + baseTOTP
	TableTOTPRecovery = DefaultPrefix + baseTOTPRecovery
)

// Core returns the core Auth-All schema with the v1 physical options.
func Core() []Table { return CoreTables(DefaultOptions()) }

// CoreTables returns the effective core Auth-All schema for the given physical
// options. It is the v1 tables plus every later core extension.
func CoreTables(o Options) []Table {
	tables := coreV1Tables(o)
	for _, e := range coreExtensions(o) {
		for i := range tables {
			if tables[i].Name != e.Table {
				continue
			}
			tables[i].Columns = append(tables[i].Columns, e.Columns...)
			tables[i].Indexes = append(tables[i].Indexes, e.Indexes...)
		}
	}
	return tables
}

// coreExtensions returns the core columns that a release added after v1. The
// migration unit 20260910000001_authall_user_admin_columns adds them to a
// database that already holds the v1 tables.
func coreExtensions(o Options) []Extension {
	n := TableNames(o)
	return []Extension{{
		Table: n.Users,
		Columns: []Column{
			// An empty role means the configured default role.
			{Name: "role", Type: TypeText, Default: "''"},
			// A non-null value blocks sign-in and every credential.
			{Name: "disabled_at", Type: TypeTimestamp, Nullable: true},
			{Name: "must_change_password", Type: TypeBool, Default: "false"},
		},
		Indexes: []Index{
			{Name: o.Name("users_role_idx"), Columns: []string{"role"}},
		},
	}}
}

// coreV1Tables returns the tables of the v1 release. The core migration unit
// creates exactly these tables, so its SQL never changes.
func coreV1Tables(o Options) []Table {
	n := TableNames(o)
	id := o.idType()
	tables := []Table{
		{
			Name: n.Users,
			Columns: []Column{
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "email", Type: TypeText},
				{Name: "email_normalized", Type: TypeText},
				{Name: "email_verified_at", Type: TypeTimestamp, Nullable: true},
				{Name: "display_name", Type: TypeText},
				{Name: "image_url", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "updated_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: o.Name("users_email_normalized_key"), Columns: []string{"email_normalized"}, Unique: true},
			},
		},
		{
			Name: n.Credentials,
			Columns: []Column{
				{Name: "user_id", Type: TypeText, PrimaryKey: true},
				{Name: "password_hash", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "updated_at", Type: TypeTimestamp},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: n.Accounts,
			Columns: []Column{
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "user_id", Type: TypeText},
				{Name: "provider", Type: TypeText},
				{Name: "provider_account_id", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "updated_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: o.Name("accounts_provider_key"), Columns: []string{"provider", "provider_account_id"}, Unique: true},
				// One user owns at most one account of one provider, so the
				// unlink of a provider removes exactly one row and cannot
				// remove a second authentication method by accident.
				{Name: o.Name("accounts_user_provider_key"), Columns: []string{"user_id", "provider"}, Unique: true},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: n.Sessions,
			Columns: []Column{
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "user_id", Type: TypeText},
				{Name: "token_hash", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "expires_at", Type: TypeTimestamp},
				{Name: "last_seen_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: o.Name("sessions_token_hash_key"), Columns: []string{"token_hash"}, Unique: true},
				{Name: o.Name("sessions_user_id_idx"), Columns: []string{"user_id"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: n.Tokens,
			Columns: []Column{
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "user_id", Type: TypeText, Nullable: true},
				{Name: "kind", Type: TypeText},
				{Name: "identifier", Type: TypeText},
				{Name: "token_hash", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "expires_at", Type: TypeTimestamp},
				{Name: "consumed_at", Type: TypeTimestamp, Nullable: true},
			},
			Indexes: []Index{
				{Name: o.Name("tokens_kind_hash_key"), Columns: []string{"kind", "token_hash"}, Unique: true},
				{Name: o.Name("tokens_kind_identifier_idx"), Columns: []string{"kind", "identifier"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: n.OAuthStates,
			Columns: []Column{
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "state_hash", Type: TypeText},
				{Name: "provider", Type: TypeText},
				{Name: "verifier", Type: TypeText},
				{Name: "nonce", Type: TypeText},
				{Name: "redirect_to", Type: TypeText},
				{Name: "link_user_id", Type: TypeText, Nullable: true},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "expires_at", Type: TypeTimestamp},
				{Name: "consumed_at", Type: TypeTimestamp, Nullable: true},
			},
			Indexes: []Index{
				{Name: o.Name("oauth_states_state_hash_key"), Columns: []string{"state_hash"}, Unique: true},
			},
		},
		{
			Name: n.TOTP,
			Columns: []Column{
				{Name: "user_id", Type: TypeText, PrimaryKey: true},
				// The secret is base32. It is not encrypted at rest. See the
				// security guide, which states the reason and the remedy.
				{Name: "secret", Type: TypeText},
				// A null confirmation means an enrolment that the user never
				// completed. Such a row never authenticates.
				{Name: "confirmed_at", Type: TypeTimestamp, Nullable: true},
				// last_step holds the last accepted time step, which refuses a
				// replay of one code inside its own window. The step counter
				// passes the 32-bit range, so the column is a 64-bit integer.
				{Name: "last_step", Type: TypeInt},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "updated_at", Type: TypeTimestamp},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: n.TOTPRecovery,
			Columns: []Column{
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "user_id", Type: TypeText},
				// The hash is SHA-256. A recovery code carries about 49 bits
				// from a random source, so it needs no slow password hash.
				{Name: "code_hash", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: o.Name("totp_recovery_code_hash_key"), Columns: []string{"code_hash"}, Unique: true},
				{Name: o.Name("totp_recovery_user_idx"), Columns: []string{"user_id"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
	}
	applyIDType(tables, id)
	for i := range tables {
		if tables[i].Name != n.Users {
			continue
		}
		for _, f := range o.UserFields {
			tables[i].Columns = append(tables[i].Columns, Column{
				Name: f.Name, Type: f.Type, Nullable: f.Nullable, Default: f.Default,
			})
		}
	}
	return tables
}

// extraIDColumns names the identifier columns that no foreign key declares.
// link_user_id holds a user identifier, but it carries no constraint, because
// the row survives the deletion of the user.
var extraIDColumns = map[string]bool{"link_user_id": true}

// applyIDType gives every identifier column the configured type. A column is
// an identifier when it is the primary key column "id", when a foreign key
// names it, or when extraIDColumns names it.
func applyIDType(tables []Table, id Type) {
	if id == TypeText {
		return
	}
	for i := range tables {
		keys := map[string]bool{}
		for _, fk := range tables[i].ForeignKeys {
			keys[fk.Column] = true
		}
		for j := range tables[i].Columns {
			c := &tables[i].Columns[j]
			if c.Type != TypeText {
				continue
			}
			if (c.Name == "id" && c.PrimaryKey) || keys[c.Name] || extraIDColumns[c.Name] {
				c.Type = id
			}
		}
	}
}

// NewCore returns a schema that already contains the core tables with the v1
// physical options.
func NewCore() (*Schema, error) { return NewCoreWithOptions(DefaultOptions()) }

// NewCoreWithOptions returns a schema that already contains the core tables
// for the given physical options.
func NewCoreWithOptions(o Options) (*Schema, error) {
	s, err := NewWithOptions(o)
	if err != nil {
		return nil, err
	}
	for _, t := range CoreTables(s.Options()) {
		if err := s.Add(t); err != nil {
			return nil, err
		}
	}
	units, err := CoreUnits(s.Options())
	if err != nil {
		return nil, err
	}
	for _, u := range units {
		if err := s.AddUnit(u); err != nil {
			return nil, err
		}
	}
	return s, nil
}
