package schema

// Core table names.
const (
	TableUsers        = "auth_users"
	TableCredentials  = "auth_credentials"
	TableAccounts     = "auth_accounts"
	TableSessions     = "auth_sessions"
	TableTokens       = "auth_tokens"
	TableOAuthStates  = "auth_oauth_states"
	TableTOTP         = "auth_totp"
	TableTOTPRecovery = "auth_totp_recovery"
)

// Core returns the core Auth-All schema.
func Core() []Table {
	return []Table{
		{
			Name: TableUsers,
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
				{Name: "auth_users_email_normalized_key", Columns: []string{"email_normalized"}, Unique: true},
			},
		},
		{
			Name: TableCredentials,
			Columns: []Column{
				{Name: "user_id", Type: TypeText, PrimaryKey: true},
				{Name: "password_hash", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "updated_at", Type: TypeTimestamp},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: TableUsers, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: TableAccounts,
			Columns: []Column{
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "user_id", Type: TypeText},
				{Name: "provider", Type: TypeText},
				{Name: "provider_account_id", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "updated_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: "auth_accounts_provider_key", Columns: []string{"provider", "provider_account_id"}, Unique: true},
				// One user owns at most one account of one provider, so the
				// unlink of a provider removes exactly one row and cannot
				// remove a second authentication method by accident.
				{Name: "auth_accounts_user_provider_key", Columns: []string{"user_id", "provider"}, Unique: true},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: TableUsers, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: TableSessions,
			Columns: []Column{
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "user_id", Type: TypeText},
				{Name: "token_hash", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "expires_at", Type: TypeTimestamp},
				{Name: "last_seen_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: "auth_sessions_token_hash_key", Columns: []string{"token_hash"}, Unique: true},
				{Name: "auth_sessions_user_id_idx", Columns: []string{"user_id"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: TableUsers, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: TableTokens,
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
				{Name: "auth_tokens_kind_hash_key", Columns: []string{"kind", "token_hash"}, Unique: true},
				{Name: "auth_tokens_kind_identifier_idx", Columns: []string{"kind", "identifier"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: TableUsers, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: TableOAuthStates,
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
				{Name: "auth_oauth_states_state_hash_key", Columns: []string{"state_hash"}, Unique: true},
			},
		},
		{
			Name: TableTOTP,
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
				{Column: "user_id", RefTable: TableUsers, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: TableTOTPRecovery,
			Columns: []Column{
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "user_id", Type: TypeText},
				// The hash is SHA-256. A recovery code carries about 49 bits
				// from a random source, so it needs no slow password hash.
				{Name: "code_hash", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: "auth_totp_recovery_code_hash_key", Columns: []string{"code_hash"}, Unique: true},
				{Name: "auth_totp_recovery_user_idx", Columns: []string{"user_id"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: TableUsers, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
	}
}

// NewCore returns a schema that already contains the core tables.
func NewCore() (*Schema, error) {
	s := New()
	for _, t := range Core() {
		if err := s.Add(t); err != nil {
			return nil, err
		}
	}
	return s, nil
}
