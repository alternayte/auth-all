package schema

// Base names of the organization tables. The physical name is the prefix plus
// the base name.
const (
	baseOrganizations = "organizations"
	baseOrgMembers    = "org_members"
	baseOrgInvites    = "org_invitations"
	baseOrgRoles      = "org_roles"
	baseOrgTeams      = "org_teams"
	baseOrgTeamMember = "org_team_members"
)

// Organization table names with the default prefix.
const (
	TableOrganizations  = DefaultPrefix + baseOrganizations
	TableOrgMembers     = DefaultPrefix + baseOrgMembers
	TableOrgInvitations = DefaultPrefix + baseOrgInvites
	TableOrgRoles       = DefaultPrefix + baseOrgRoles
	TableOrgTeams       = DefaultPrefix + baseOrgTeams
	TableOrgTeamMembers = DefaultPrefix + baseOrgTeamMember
)

// Versions of the organization migration units. A released unit never changes.
const (
	VersionOrganizations = "20261101000001"
	VersionOrgMembers    = "20261101000002"
	VersionOrgInvites    = "20261101000003"
	VersionOrgRoles      = "20261101000004"
	VersionOrgTeams      = "20261101000005"
	VersionOrgColumns    = "20261101000006"
)

// OrganizationNames returns the physical names of the organization tables.
type OrganizationNames struct {
	Organizations string
	Members       string
	Invitations   string
	Roles         string
	Teams         string
	TeamMembers   string
}

// OrgTableNames returns the physical organization table names for the options.
func OrgTableNames(o Options) OrganizationNames {
	return OrganizationNames{
		Organizations: o.Name(baseOrganizations),
		Members:       o.Name(baseOrgMembers),
		Invitations:   o.Name(baseOrgInvites),
		Roles:         o.Name(baseOrgRoles),
		Teams:         o.Name(baseOrgTeams),
		TeamMembers:   o.Name(baseOrgTeamMember),
	}
}

// OrganizationTables returns the tables of the organizations plugin. The
// plugin contributes them, so an application that enables no organization gets
// no table.
func OrganizationTables(o Options) []Table {
	n := TableNames(o)
	org := OrgTableNames(o)
	id := o.idType()
	tables := []Table{
		{
			Name: org.Organizations,
			Columns: append([]Column{
				{Name: "id", Type: id, PrimaryKey: true},
				{Name: "name", Type: TypeText},
				{Name: "slug", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
				{Name: "updated_at", Type: TypeTimestamp},
			}, orgFieldColumns(o)...),
			Indexes: []Index{
				{Name: o.Name("organizations_slug_key"), Columns: []string{"slug"}, Unique: true},
			},
		},
		{
			Name: org.Members,
			Columns: []Column{
				{Name: "id", Type: id, PrimaryKey: true},
				{Name: "org_id", Type: id},
				{Name: "user_id", Type: id},
				{Name: "role", Type: TypeText},
				{Name: "status", Type: TypeText},
				{Name: "joined_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: o.Name("org_members_org_user_key"), Columns: []string{"org_id", "user_id"}, Unique: true},
				{Name: o.Name("org_members_user_idx"), Columns: []string{"user_id"}},
				{Name: o.Name("org_members_org_role_idx"), Columns: []string{"org_id", "role"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "org_id", RefTable: org.Organizations, RefColumn: "id", OnDelete: "CASCADE"},
				{Column: "user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: org.Invitations,
			Columns: []Column{
				{Name: "id", Type: id, PrimaryKey: true},
				{Name: "org_id", Type: id},
				{Name: "email_normalized", Type: TypeText},
				{Name: "role", Type: TypeText},
				{Name: "invited_by", Type: id},
				{Name: "token_hash", Type: TypeText},
				{Name: "status", Type: TypeText},
				{Name: "expires_at", Type: TypeTimestamp},
				{Name: "created_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: o.Name("org_invitations_token_key"), Columns: []string{"token_hash"}, Unique: true},
				{Name: o.Name("org_invitations_org_status_idx"), Columns: []string{"org_id", "status"}},
			},
			ForeignKeys: []ForeignKey{
				{Column: "org_id", RefTable: org.Organizations, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: org.Roles,
			Columns: []Column{
				{Name: "id", Type: id, PrimaryKey: true},
				{Name: "org_id", Type: id},
				{Name: "name", Type: TypeText},
				// The permissions are a space-separated list of statements. A
				// custom role stores its own statements, so a later change of
				// a built-in role never widens it.
				{Name: "permissions", Type: TypeText},
				{Name: "created_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: o.Name("org_roles_org_name_key"), Columns: []string{"org_id", "name"}, Unique: true},
			},
			ForeignKeys: []ForeignKey{
				{Column: "org_id", RefTable: org.Organizations, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: org.Teams,
			Columns: []Column{
				{Name: "id", Type: id, PrimaryKey: true},
				{Name: "org_id", Type: id},
				{Name: "name", Type: TypeText},
				{Name: "role", Type: TypeText, Nullable: true},
				{Name: "created_at", Type: TypeTimestamp},
			},
			Indexes: []Index{
				{Name: o.Name("org_teams_org_name_key"), Columns: []string{"org_id", "name"}, Unique: true},
			},
			ForeignKeys: []ForeignKey{
				{Column: "org_id", RefTable: org.Organizations, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
		{
			Name: org.TeamMembers,
			// The pair of the columns identifies one row. The renderer emits
			// one primary key column, so a unique index carries the same
			// guarantee.
			Columns: []Column{
				{Name: "team_id", Type: id},
				{Name: "user_id", Type: id},
			},
			Indexes: []Index{
				{Name: o.Name("org_team_members_key"), Columns: []string{"team_id", "user_id"}, Unique: true},
			},
			ForeignKeys: []ForeignKey{
				{Column: "team_id", RefTable: org.Teams, RefColumn: "id", OnDelete: "CASCADE"},
				{Column: "user_id", RefTable: n.Users, RefColumn: "id", OnDelete: "CASCADE"},
			},
		},
	}
	return tables
}

// SessionOrganizationExtension returns the column that carries the active
// organization of one session. The column is nullable, so the unit applies to
// a database that already holds rows.
func SessionOrganizationExtension(o Options) Extension {
	n := TableNames(o)
	return Extension{
		Table:   n.Sessions,
		Columns: []Column{{Name: "active_org_id", Type: o.idType(), Nullable: true}},
	}
}

// orgFieldColumns returns the host-owned columns of the organizations table.
func orgFieldColumns(o Options) []Column {
	out := make([]Column, 0, len(o.OrgFields))
	for _, f := range o.OrgFields {
		out = append(out, Column{Name: f.Name, Type: f.Type, Nullable: f.Nullable, Default: f.Default})
	}
	return out
}

// OrganizationUnits returns the migration units of the organization tables.
// One unit creates one table, so a host applies them in the order of the
// design document.
func OrganizationUnits(owner string, o Options) ([]Unit, error) {
	tables := OrganizationTables(o)
	dialects := []Dialect{Postgres, SQLite}
	plan := []struct {
		version string
		name    string
		tables  []Table
	}{
		{VersionOrganizations, "authall_organizations", tables[0:1]},
		{VersionOrgMembers, "authall_org_members", tables[1:2]},
		{VersionOrgInvites, "authall_org_invitations", tables[2:3]},
		{VersionOrgRoles, "authall_org_roles", tables[3:4]},
		{VersionOrgTeams, "authall_org_teams", tables[4:6]},
	}
	units := make([]Unit, 0, len(plan)+1)
	for _, step := range plan {
		unit, err := TableUnit(step.version, owner, step.name, dialects, step.tables)
		if err != nil {
			return nil, err
		}
		units = append(units, unit)
	}
	columns, err := ExtensionUnit(VersionOrgColumns, owner, "authall_org_columns", dialects,
		[]Extension{SessionOrganizationExtension(o)})
	if err != nil {
		return nil, err
	}
	return append(units, columns), nil
}
