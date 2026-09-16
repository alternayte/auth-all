package schema

// Base names of the OAuth provider tables. The physical name is the prefix
// plus the base name.
const (
	baseOAuthKeys          = "oauth_keys"
	baseOAuthClients       = "oauth_clients"
	baseOAuthRequests      = "oauth_requests"
	baseOAuthGrants        = "oauth_grants"
	baseOAuthCodes         = "oauth_codes"
	baseOAuthAccessTokens  = "oauth_access_tokens"
	baseOAuthRefreshTokens = "oauth_refresh_tokens"
	baseOAuthConsents      = "oauth_consents"
	baseOAuthProofs        = "oauth_proofs"
)

// OAuth provider table names with the default prefix.
const (
	TableOAuthKeys          = DefaultPrefix + baseOAuthKeys
	TableOAuthClients       = DefaultPrefix + baseOAuthClients
	TableOAuthRequests      = DefaultPrefix + baseOAuthRequests
	TableOAuthGrants        = DefaultPrefix + baseOAuthGrants
	TableOAuthCodes         = DefaultPrefix + baseOAuthCodes
	TableOAuthAccessTokens  = DefaultPrefix + baseOAuthAccessTokens
	TableOAuthRefreshTokens = DefaultPrefix + baseOAuthRefreshTokens
	TableOAuthConsents      = DefaultPrefix + baseOAuthConsents
	TableOAuthProofs        = DefaultPrefix + baseOAuthProofs
)

// Versions of the OAuth provider migration units. A released unit never
// changes.
const (
	VersionOAuthKeys   = "20261201000001"
	VersionOAuthClient = "20261201000002"
	VersionOAuthGrants = "20261201000003"
	VersionOAuthTokens = "20261201000004"
)

// OAuthProviderNames holds the physical names of the OAuth provider tables.
type OAuthProviderNames struct {
	Keys          string
	Clients       string
	Requests      string
	Grants        string
	Codes         string
	AccessTokens  string
	RefreshTokens string
	Consents      string
	Proofs        string
}

// OAuthProviderTableNames returns the physical OAuth provider table names for
// the options.
func OAuthProviderTableNames(o Options) OAuthProviderNames {
	return OAuthProviderNames{
		Keys:          o.Name(baseOAuthKeys),
		Clients:       o.Name(baseOAuthClients),
		Requests:      o.Name(baseOAuthRequests),
		Grants:        o.Name(baseOAuthGrants),
		Codes:         o.Name(baseOAuthCodes),
		AccessTokens:  o.Name(baseOAuthAccessTokens),
		RefreshTokens: o.Name(baseOAuthRefreshTokens),
		Consents:      o.Name(baseOAuthConsents),
		Proofs:        o.Name(baseOAuthProofs),
	}
}

// OAuthProviderTables returns the tables of the OAuth provider plugin. The
// plugin contributes them, so an application that enables no provider gets no
// table.
//
// A list column holds a space-separated list. A scope, a resource indicator,
// and a redirect URI carry no space, so the encoding is lossless.
func OAuthProviderTables(o Options) []Table {
	n := TableNames(o)
	p := OAuthProviderTableNames(o)
	id := o.idType()
	return []Table{
		{
			Name: p.Keys,
			Columns: []Column{
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "algorithm", Type: TypeText},
				// The private key is the base64 form of the AES-256-GCM
				// ciphertext of the PKCS#8 key.
				{Name: "wrapped_private", Type: TypeText},
				{Name: "public_jwk", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "retired_at", Type: TypeTimestamp, Nullable: true},
			},
		},
		{
			Name: p.Clients,
			Columns: []Column{
				{Name: "id", Type: id, PrimaryKey: true},
				{Name: "client_id", Type: TypeText},
				{Name: "secret_hash", Type: TypeText},
				{Name: "name", Type: TypeText},
				{Name: "logo_uri", Type: TypeText},
				{Name: "redirect_uris", Type: TypeText},
				{Name: "grant_types", Type: TypeText},
				{Name: "scopes", Type: TypeText},
				{Name: "token_endpoint_auth_method", Type: TypeText},
				{Name: "dpop_required", Type: TypeBool},
				{Name: "owner_user_id", Type: id, Nullable: true},
				{Name: "org_id", Type: id, Nullable: true},
				{Name: "registration_token_hash", Type: TypeText, Nullable: true},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "updated_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: o.Name("oauth_clients_client_id_key"), Columns: []string{"client_id"}, Unique: true},
				{Name: o.Name("oauth_clients_owner_idx"), Columns: []string{"owner_user_id"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "owner_user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "SET NULL"},
			},
		},
		{
			Name: p.Requests,
			Columns: []Column{
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "client_id", Type: TypeText},
				{Name: "redirect_uri", Type: TypeText},
				{Name: "scopes", Type: TypeText},
				{Name: "resources", Type: TypeText},
				{Name: "state", Type: TypeText},
				{Name: "nonce", Type: TypeText},
				{Name: "code_challenge", Type: TypeText},
				{Name: "code_challenge_method", Type: TypeText},
				{Name: "prompt", Type: TypeText},
				{Name: "max_age", Type: TypeInt, Nullable: true},
				{Name: "dpop_jkt", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "expires_at", Type: TypeTimestamp},
				{Name: "consumed_at", Type: TypeTimestamp, Nullable: true},
			},
			Indexes: []Index{
				{Name: o.Name("oauth_requests_expires_idx"), Columns: []string{"expires_at"}},
			},
		},
		{
			Name: p.Grants,
			Columns: []Column{
				{Name: "id", Type: id, PrimaryKey: true},
				{Name: "client_id", Type: TypeText},
				{Name: "user_id", Type: id, Nullable: true},
				{Name: "scopes", Type: TypeText},
				{Name: "resources", Type: TypeText},
				{Name: "auth_time", Type: TypeTimestamp, Nullable: true},
				{Name: "session_id", Type: id, Nullable: true},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "revoked_at", Type: TypeTimestamp, Nullable: true},
			},
			Indexes: []Index{
				{Name: o.Name("oauth_grants_user_client_idx"), Columns: []string{"user_id", "client_id"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: p.Codes,
			Columns: []Column{
				{Name: "id", Type: id, PrimaryKey: true},
				{Name: "code_hash", Type: TypeText},
				{Name: "grant_id", Type: id},
				{Name: "client_id", Type: TypeText},
				{Name: "redirect_uri", Type: TypeText},
				{Name: "code_challenge", Type: TypeText},
				{Name: "nonce", Type: TypeText},
				{Name: "scopes", Type: TypeText},
				{Name: "resources", Type: TypeText},
				{Name: "dpop_jkt", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "expires_at", Type: TypeTimestamp},
				{Name: "consumed_at", Type: TypeTimestamp, Nullable: true},
			},
			Indexes: []Index{
				{Name: o.Name("oauth_codes_code_hash_key"), Columns: []string{"code_hash"}, Unique: true},
			},
			ForeignKeys: []ForeignKey{
				{Column: "grant_id", RefTable: p.Grants, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: p.AccessTokens,
			Columns: []Column{
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "grant_id", Type: id},
				{Name: "client_id", Type: TypeText},
				{Name: "user_id", Type: id, Nullable: true},
				{Name: "scopes", Type: TypeText},
				{Name: "audience", Type: TypeText},
				{Name: "jkt", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "expires_at", Type: TypeTimestamp},
				{Name: "revoked_at", Type: TypeTimestamp, Nullable: true},
			},
			Indexes: []Index{
				{Name: o.Name("oauth_access_tokens_grant_idx"), Columns: []string{"grant_id"}},
				{Name: o.Name("oauth_access_tokens_expires_idx"), Columns: []string{"expires_at"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "grant_id", RefTable: p.Grants, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: p.RefreshTokens,
			Columns: []Column{
				{Name: "id", Type: id, PrimaryKey: true},
				{Name: "token_hash", Type: TypeText},
				{Name: "grant_id", Type: id},
				{Name: "client_id", Type: TypeText},
				{Name: "user_id", Type: id, Nullable: true},
				{Name: "scopes", Type: TypeText},
				{Name: "resources", Type: TypeText},
				{Name: "jkt", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "expires_at", Type: TypeTimestamp},
				{Name: "rotated_at", Type: TypeTimestamp, Nullable: true},
				{Name: "successor_id", Type: id, Nullable: true},
				{Name: "revoked_at", Type: TypeTimestamp, Nullable: true},
			},
			Indexes: []Index{
				{Name: o.Name("oauth_refresh_tokens_hash_key"), Columns: []string{"token_hash"}, Unique: true},
				{Name: o.Name("oauth_refresh_tokens_grant_idx"), Columns: []string{"grant_id"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "grant_id", RefTable: p.Grants, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: p.Proofs,
			Columns: []Column{
				// The identifier of a DPoP proof. The primary key rejects a
				// replay, because the second insert conflicts.
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "expires_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: o.Name("oauth_proofs_expires_idx"), Columns: []string{"expires_at"}},
			},
		},
		{
			Name: p.Consents,
			Columns: []Column{
				{Name: "id", Type: id, PrimaryKey: true},
				{Name: "client_id", Type: TypeText},
				{Name: "user_id", Type: id},
				{Name: "scopes", Type: TypeText},
				{Name: "resources", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "updated_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: o.Name("oauth_consents_user_client_key"), Columns: []string{"user_id", "client_id"}, Unique: true},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
	}
}

// OAuthProviderUnits returns the migration units of the OAuth provider
// plugin.
func OAuthProviderUnits(o Options, owner string) ([]Unit, error) {
	o, err := o.Normalize()
	if err != nil {
		return nil, err
	}
	tables := OAuthProviderTables(o)
	dialects := []Dialect{Postgres, SQLite}
	plan := []struct {
		version string
		name    string
		tables  []Table
	}{
		{VersionOAuthKeys, "authall_oauth_keys", tables[0:1]},
		{VersionOAuthClient, "authall_oauth_clients", tables[1:3]},
		{VersionOAuthGrants, "authall_oauth_grants", tables[3:5]},
		{VersionOAuthTokens, "authall_oauth_tokens", tables[5:9]},
	}
	units := make([]Unit, 0, len(plan))
	for _, step := range plan {
		unit, err := TableUnit(step.version, owner, step.name, dialects, step.tables)
		if err != nil {
			return nil, err
		}
		units = append(units, unit)
	}
	return units, nil
}
