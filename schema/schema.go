// Package schema describes the Auth-All database schema independently from a
// specific database engine. Core and plugins contribute tables. A dialect
// renderer turns the effective schema into deterministic SQL.
package schema

import (
	"fmt"
	"sort"
	"strings"
)

// Type is a database-independent column type.
type Type string

// Supported column types.
const (
	TypeText      Type = "text"
	TypeTimestamp Type = "timestamp"
	TypeInt       Type = "int"
	TypeBool      Type = "bool"
	// TypeUUID is an identifier column. PostgreSQL uses uuid. SQLite uses
	// text, because SQLite has no uuid type.
	TypeUUID Type = "uuid"
)

// Column describes one column.
type Column struct {
	Name       string
	Type       Type
	Nullable   bool
	PrimaryKey bool
	// Default is the rendered SQL default. An empty value adds no default.
	Default string
}

// ForeignKey describes one foreign key constraint.
type ForeignKey struct {
	Column    string
	RefTable  string
	RefColumn string
	OnDelete  string // CASCADE or SET NULL. Empty means no action.
}

// Index describes one index.
type Index struct {
	Name    string
	Columns []string
	Unique  bool
}

// Table describes one table.
type Table struct {
	Name        string
	Columns     []Column
	Indexes     []Index
	ForeignKeys []ForeignKey
}

// Schema is the effective set of tables.
type Schema struct {
	tables map[string]Table
	units  []Unit
	opts   Options
}

// New returns an empty schema with the default options.
func New() *Schema { return &Schema{tables: map[string]Table{}, opts: DefaultOptions()} }

// NewWithOptions returns an empty schema with the given physical options.
func NewWithOptions(o Options) (*Schema, error) {
	o, err := o.Normalize()
	if err != nil {
		return nil, err
	}
	return &Schema{tables: map[string]Table{}, opts: o}, nil
}

// Options returns the physical options of the schema.
func (s *Schema) Options() Options {
	if s.opts.Prefix == "" {
		return DefaultOptions()
	}
	return s.opts
}

// Names returns the physical table names of the schema.
func (s *Schema) Names() Names { return TableNames(s.Options()) }

// AddUnit registers one migration unit. A unit that creates a table must also
// name the table in Creates.
func (s *Schema) AddUnit(u Unit) error {
	if u.Version == "" || u.Name == "" {
		return fmt.Errorf("authall/schema: a migration unit needs a version and a name")
	}
	for _, have := range s.units {
		if have.Version == u.Version {
			return fmt.Errorf("authall/schema: the migration version %q is used twice", u.Version)
		}
	}
	s.units = append(s.units, u)
	return nil
}

// Units returns every migration unit in version order. A table that no unit
// covers gets a synthesized unit, so a third-party plugin that contributes
// only a table still exports a file.
func (s *Schema) Units() ([]Unit, error) {
	units := append([]Unit(nil), s.units...)
	covered := map[string]bool{}
	for _, u := range units {
		for _, name := range u.Creates {
			covered[name] = true
		}
	}
	var loose []Table
	for _, t := range s.Tables() {
		if !covered[t.Name] {
			loose = append(loose, t)
		}
	}
	for i, t := range loose {
		u, err := TableUnit(fmt.Sprintf("%s%02d", synthesizedVersionPrefix, i+1),
			"plugin", "authall_"+t.Name, []Dialect{Postgres, SQLite}, []Table{t})
		if err != nil {
			return nil, err
		}
		units = append(units, u)
	}
	sort.SliceStable(units, func(i, j int) bool { return units[i].Version < units[j].Version })
	return units, nil
}

// synthesizedVersionPrefix starts the version of a unit that Auth-All derives
// from a contributed table. The two last digits number the tables in name
// order.
const synthesizedVersionPrefix = "202609109000"

// Extend adds columns and indexes to a table that another owner declared.
func (s *Schema) Extend(e Extension) error {
	if err := e.Validate(); err != nil {
		return err
	}
	t, ok := s.tables[e.Table]
	if !ok {
		return fmt.Errorf("authall/schema: the extension target %q is not registered", e.Table)
	}
	have := map[string]bool{}
	for _, c := range t.Columns {
		have[c.Name] = true
	}
	for _, c := range e.Columns {
		if have[c.Name] {
			return fmt.Errorf("authall/schema: the column %q of %q exists already", c.Name, e.Table)
		}
		have[c.Name] = true
		t.Columns = append(t.Columns, c)
	}
	t.Indexes = append(t.Indexes, e.Indexes...)
	s.tables[e.Table] = t
	return nil
}

// Add registers a table. It reports an error when the name is already taken.
func (s *Schema) Add(t Table) error {
	if s.tables == nil {
		s.tables = map[string]Table{}
	}
	if t.Name == "" {
		return fmt.Errorf("authall/schema: table name is empty")
	}
	if len(t.Columns) == 0 {
		return fmt.Errorf("authall/schema: table %q has no column", t.Name)
	}
	if _, ok := s.tables[t.Name]; ok {
		return fmt.Errorf("authall/schema: table %q is already registered", t.Name)
	}
	s.tables[t.Name] = t
	return nil
}

// Tables returns every table sorted by name. The order is deterministic and
// does not depend on registration order.
func (s *Schema) Tables() []Table {
	out := make([]Table, 0, len(s.tables))
	for _, t := range s.tables {
		c := t
		c.Indexes = append([]Index(nil), t.Indexes...)
		sort.Slice(c.Indexes, func(i, j int) bool { return c.Indexes[i].Name < c.Indexes[j].Name })
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Table returns one table by name.
func (s *Schema) Table(name string) (Table, bool) {
	t, ok := s.tables[name]
	return t, ok
}

// Dialect selects the SQL flavor of a renderer.
type Dialect string

// Supported dialects.
const (
	Postgres Dialect = "postgres"
	SQLite   Dialect = "sqlite"
)

// Statement is one identified DDL statement.
//
// The ID is stable across runs and identifies the statement in the applied
// migration record.
type Statement struct {
	ID  string
	SQL string
}

// MigrationTable holds the applied statement IDs. It is the v1 name. A schema
// with another prefix uses Names().Migrations instead.
const MigrationTable = DefaultPrefix + baseMigrations

// Render returns the deterministic DDL for the schema in one dialect. The
// result is a pure function of the schema and needs no database connection.
func Render(d Dialect, s *Schema) ([]Statement, error) {
	if d != Postgres && d != SQLite {
		return nil, fmt.Errorf("authall/schema: unsupported dialect %q", d)
	}
	record := s.Names().Migrations
	out := []Statement{{
		ID: "table:" + record,
		SQL: "CREATE TABLE IF NOT EXISTS " + record + " (\n" +
			"    id " + columnType(d, TypeText) + " NOT NULL PRIMARY KEY,\n" +
			"    applied_at " + columnType(d, TypeTimestamp) + " NOT NULL\n)",
	}}
	units, err := s.Units()
	if err != nil {
		return nil, err
	}
	for _, u := range units {
		out = append(out, u.Up[d]...)
	}
	return out, nil
}

// orderTables returns the tables in a deterministic order that creates a
// referenced table before the table that references it.
func orderTables(tables []Table) []Table {
	known := map[string]bool{}
	for _, t := range tables {
		known[t.Name] = true
	}
	emitted := map[string]bool{}
	out := make([]Table, 0, len(tables))
	remaining := append([]Table(nil), tables...)
	for len(remaining) > 0 {
		progress := false
		next := remaining[:0]
		for _, t := range remaining {
			ready := true
			for _, fk := range t.ForeignKeys {
				if fk.RefTable == t.Name || !known[fk.RefTable] {
					continue
				}
				if !emitted[fk.RefTable] {
					ready = false
					break
				}
			}
			if ready {
				out = append(out, t)
				emitted[t.Name] = true
				progress = true
				continue
			}
			next = append(next, t)
		}
		remaining = next
		if !progress {
			// A cycle exists. Emit the rest in name order.
			out = append(out, remaining...)
			break
		}
	}
	return out
}

func renderTable(d Dialect, t Table) (Statement, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "CREATE TABLE IF NOT EXISTS %s (\n", t.Name)
	parts := make([]string, 0, len(t.Columns)+len(t.ForeignKeys))
	for _, c := range t.Columns {
		if c.Name == "" {
			return Statement{}, fmt.Errorf("authall/schema: table %q has an unnamed column", t.Name)
		}
		line := "    " + c.Name + " " + columnType(d, c.Type)
		if !c.Nullable {
			line += " NOT NULL"
		}
		if c.PrimaryKey {
			line += " PRIMARY KEY"
		}
		if c.Default != "" {
			line += " DEFAULT " + renderDefault(d, c.Default)
		}
		parts = append(parts, line)
	}
	for _, fk := range t.ForeignKeys {
		line := fmt.Sprintf("    FOREIGN KEY (%s) REFERENCES %s(%s)", fk.Column, fk.RefTable, fk.RefColumn)
		if fk.OnDelete != "" {
			line += " ON DELETE " + fk.OnDelete
		}
		parts = append(parts, line)
	}
	b.WriteString(strings.Join(parts, ",\n"))
	b.WriteString("\n)")
	return Statement{ID: "table:" + t.Name, SQL: b.String()}, nil
}

// renderDefault returns the default expression in one dialect. SQLite has no
// boolean literal, so it takes the numeric form.
func renderDefault(d Dialect, v string) string {
	if d != SQLite {
		return v
	}
	switch v {
	case "true":
		return "1"
	case "false":
		return "0"
	}
	return v
}

func renderIndex(t Table, idx Index) Statement {
	unique := ""
	if idx.Unique {
		unique = "UNIQUE "
	}
	sql := fmt.Sprintf("CREATE %sINDEX IF NOT EXISTS %s ON %s (%s)",
		unique, idx.Name, t.Name, strings.Join(idx.Columns, ", "))
	return Statement{ID: "index:" + idx.Name, SQL: sql}
}

func columnType(d Dialect, t Type) string {
	switch d {
	case Postgres:
		switch t {
		case TypeText:
			return "text"
		case TypeTimestamp:
			return "timestamptz"
		case TypeInt:
			return "bigint"
		case TypeBool:
			return "boolean"
		case TypeUUID:
			return "uuid"
		}
	case SQLite:
		switch t {
		case TypeText, TypeTimestamp, TypeUUID:
			return "TEXT"
		case TypeInt:
			return "INTEGER"
		case TypeBool:
			return "INTEGER"
		}
	}
	return "text"
}
