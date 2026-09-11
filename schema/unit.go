package schema

import (
	"fmt"
	"sort"
)

// OwnerCore names the owner of the core migration units.
const OwnerCore = "core"

// Unit is one versioned and immutable set of DDL statements with one owner.
//
// A released unit never changes. A later release adds a new unit instead, so a
// host that applied the earlier file keeps a valid database.
type Unit struct {
	// Version is a 14-digit timestamp. It orders the units.
	Version string
	// Owner is OwnerCore or a plugin identifier.
	Owner string
	// Name is the unit name without the version.
	Name string
	// Up holds the forward statements of each dialect.
	Up map[Dialect][]Statement
	// Down holds the reverse statements of each dialect.
	Down map[Dialect][]Statement
	// Creates names the tables that the unit creates. The schema uses it to
	// find a table that no unit covers.
	Creates []string
}

// FileName returns the version and the name, for example
// 20260101000000_authall_core.
func (u Unit) FileName() string { return u.Version + "_" + u.Name }

// Versions of the released core units.
const (
	versionCore            = "20260101000000"
	versionUserAdminColumn = "20260910000001"
)

// CoreUnits returns the core migration units in version order.
func CoreUnits(o Options) ([]Unit, error) {
	o, err := o.Normalize()
	if err != nil {
		return nil, err
	}
	base := coreV1Tables(o)
	core := Unit{Version: versionCore, Owner: OwnerCore, Name: "authall_core",
		Up: map[Dialect][]Statement{}, Down: map[Dialect][]Statement{}, Creates: tableNamesOf(base)}
	admin := Unit{Version: versionUserAdminColumn, Owner: OwnerCore, Name: "authall_user_admin_columns",
		Up: map[Dialect][]Statement{}, Down: map[Dialect][]Statement{}}
	for _, d := range []Dialect{Postgres, SQLite} {
		up, err := renderTables(d, base)
		if err != nil {
			return nil, err
		}
		core.Up[d] = up
		core.Down[d] = dropTables(base)
		for _, e := range coreExtensions(o) {
			eu, err := renderExtension(d, e)
			if err != nil {
				return nil, err
			}
			admin.Up[d] = append(admin.Up[d], eu...)
			admin.Down[d] = append(admin.Down[d], dropExtension(e)...)
		}
	}
	return []Unit{core, admin}, nil
}

// UnitsFor returns the core units and one unit for each extra table that a
// plugin contributed. The units are sorted by version.
func UnitsFor(o Options, extra []Unit) ([]Unit, error) {
	units, err := CoreUnits(o)
	if err != nil {
		return nil, err
	}
	units = append(units, extra...)
	seen := map[string]bool{}
	for _, u := range units {
		if seen[u.Version] {
			return nil, fmt.Errorf("authall/schema: the migration version %q is used twice", u.Version)
		}
		seen[u.Version] = true
	}
	sort.SliceStable(units, func(i, j int) bool { return units[i].Version < units[j].Version })
	return units, nil
}

// TableUnit returns one unit that creates the given tables.
func TableUnit(version, owner, name string, d []Dialect, tables []Table) (Unit, error) {
	u := Unit{Version: version, Owner: owner, Name: name,
		Up: map[Dialect][]Statement{}, Down: map[Dialect][]Statement{}}
	for _, dialect := range d {
		up, err := renderTables(dialect, tables)
		if err != nil {
			return Unit{}, err
		}
		u.Up[dialect] = up
		u.Down[dialect] = dropTables(tables)
	}
	u.Creates = tableNamesOf(tables)
	return u, nil
}

// ExtensionUnit returns one unit that adds the columns and the indexes of the
// given extensions. A plugin uses it for a column on a table that another
// owner declared.
func ExtensionUnit(version, owner, name string, d []Dialect, extensions []Extension) (Unit, error) {
	u := Unit{Version: version, Owner: owner, Name: name,
		Up: map[Dialect][]Statement{}, Down: map[Dialect][]Statement{}}
	for _, dialect := range d {
		for _, e := range extensions {
			up, err := renderExtension(dialect, e)
			if err != nil {
				return Unit{}, err
			}
			u.Up[dialect] = append(u.Up[dialect], up...)
			u.Down[dialect] = append(u.Down[dialect], dropExtension(e)...)
		}
	}
	return u, nil
}

// renderTables returns the create statements of the tables and their indexes.
func renderTables(d Dialect, tables []Table) ([]Statement, error) {
	if d != Postgres && d != SQLite {
		return nil, fmt.Errorf("authall/schema: unsupported dialect %q", d)
	}
	var out []Statement
	for _, t := range orderTables(sortTables(tables)) {
		st, err := renderTable(d, t)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
		for _, idx := range sortIndexes(t.Indexes) {
			out = append(out, renderIndex(t, idx))
		}
	}
	return out, nil
}

// dropTables returns the drop statements in the reverse creation order.
func dropTables(tables []Table) []Statement {
	ordered := orderTables(sortTables(tables))
	out := make([]Statement, 0, len(ordered))
	for i := len(ordered) - 1; i >= 0; i-- {
		out = append(out, Statement{
			ID:  "drop-table:" + ordered[i].Name,
			SQL: "DROP TABLE IF EXISTS " + ordered[i].Name,
		})
	}
	return out
}

// renderExtension returns the statements that add the columns and indexes.
func renderExtension(d Dialect, e Extension) ([]Statement, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	var out []Statement
	for _, c := range e.Columns {
		line := "ALTER TABLE " + e.Table + " ADD COLUMN " + c.Name + " " + columnType(d, c.Type)
		if !c.Nullable {
			line += " NOT NULL"
		}
		if c.Default != "" {
			line += " DEFAULT " + renderDefault(d, c.Default)
		}
		out = append(out, Statement{ID: "column:" + e.Table + "." + c.Name, SQL: line})
	}
	for _, idx := range sortIndexes(e.Indexes) {
		out = append(out, renderIndex(Table{Name: e.Table}, idx))
	}
	return out, nil
}

// dropExtension returns the statements that remove the columns and indexes.
func dropExtension(e Extension) []Statement {
	var out []Statement
	for _, idx := range sortIndexes(e.Indexes) {
		out = append(out, Statement{ID: "drop-index:" + idx.Name, SQL: "DROP INDEX IF EXISTS " + idx.Name})
	}
	for i := len(e.Columns) - 1; i >= 0; i-- {
		out = append(out, Statement{
			ID:  "drop-column:" + e.Table + "." + e.Columns[i].Name,
			SQL: "ALTER TABLE " + e.Table + " DROP COLUMN " + e.Columns[i].Name,
		})
	}
	return out
}

func tableNamesOf(tables []Table) []string {
	out := make([]string, 0, len(tables))
	for _, t := range sortTables(tables) {
		out = append(out, t.Name)
	}
	return out
}

func sortTables(tables []Table) []Table {
	out := append([]Table(nil), tables...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func sortIndexes(idx []Index) []Index {
	out := append([]Index(nil), idx...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
