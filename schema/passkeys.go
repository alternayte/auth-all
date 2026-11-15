package schema

// Base names of the passkey tables. The physical name is the prefix plus the
// base name.
const (
	basePasskeys          = "passkeys"
	basePasskeyChallenges = "passkey_challenges"
)

// Passkey table names with the default prefix.
const (
	TablePasskeys          = DefaultPrefix + basePasskeys
	TablePasskeyChallenges = DefaultPrefix + basePasskeyChallenges
)

// VersionPasskeys is the version of the passkey migration unit. A released
// unit never changes.
const VersionPasskeys = "20270115000001"

// PasskeyNames holds the physical names of the passkey tables.
type PasskeyNames struct {
	Passkeys   string
	Challenges string
}

// PasskeyTableNames returns the physical passkey table names for the options.
func PasskeyTableNames(o Options) PasskeyNames {
	return PasskeyNames{
		Passkeys:   o.Name(basePasskeys),
		Challenges: o.Name(basePasskeyChallenges),
	}
}

// PasskeyTables returns the tables of the passkeys plugin. The plugin
// contributes them, so an application that enables no passkey gets no table.
func PasskeyTables(o Options) []Table {
	n := TableNames(o)
	p := PasskeyTableNames(o)
	id := o.idType()
	return []Table{
		{
			Name: p.Passkeys,
			Columns: []Column{
				{Name: "id", Type: id, PrimaryKey: true},
				{Name: "user_id", Type: id},
				{Name: "credential_id", Type: TypeText},
				{Name: "name", Type: TypeText},
				// The credential record in its JSON form. It holds the public
				// key and the counter, and no secret.
				{Name: "credential", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "last_used_at", Type: TypeTimestamp, Nullable: true},
			},
			Indexes: []Index{
				{Name: o.Name("passkeys_credential_id_key"), Columns: []string{"credential_id"}, Unique: true},
				{Name: o.Name("passkeys_user_idx"), Columns: []string{"user_id"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: p.Challenges,
			Columns: []Column{
				// The digest of the ceremony handle.
				{Name: "id", Type: TypeText, PrimaryKey: true},
				{Name: "kind", Type: TypeText},
				{Name: "user_id", Type: id, Nullable: true},
				{Name: "session_data", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "expires_at", Type: TypeTimestamp},
				{Name: "consumed_at", Type: TypeTimestamp, Nullable: true},
			},
			Indexes: []Index{
				{Name: o.Name("passkey_challenges_expires_idx"), Columns: []string{"expires_at"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
	}
}

// PasskeyUnits returns the migration units of the passkeys plugin.
func PasskeyUnits(o Options, owner string) ([]Unit, error) {
	o, err := o.Normalize()
	if err != nil {
		return nil, err
	}
	unit, err := TableUnit(VersionPasskeys, owner, "authall_passkeys", []Dialect{Postgres, SQLite}, PasskeyTables(o))
	if err != nil {
		return nil, err
	}
	return []Unit{unit}, nil
}
