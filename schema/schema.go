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
)

// Column describes one column.
type Column struct {
	Name       string
	Type       Type
	Nullable   bool
	PrimaryKey bool
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
}

// New returns an empty schema.
func New() *Schema { return &Schema{tables: map[string]Table{}} }

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

// MigrationTable holds the applied statement IDs.
const MigrationTable = "auth_schema_migrations"

// Render returns the deterministic DDL for the schema in one dialect. The
// result is a pure function of the schema and needs no database connection.
func Render(d Dialect, s *Schema) ([]Statement, error) {
	if d != Postgres && d != SQLite {
		return nil, fmt.Errorf("authall/schema: unsupported dialect %q", d)
	}
	out := []Statement{{
		ID: "table:" + MigrationTable,
		SQL: "CREATE TABLE IF NOT EXISTS " + MigrationTable + " (\n" +
			"    id " + columnType(d, TypeText) + " NOT NULL PRIMARY KEY,\n" +
			"    applied_at " + columnType(d, TypeTimestamp) + " NOT NULL\n)",
	}}
	for _, t := range orderTables(s.Tables()) {
		stmt, err := renderTable(d, t)
		if err != nil {
			return nil, err
		}
		out = append(out, stmt)
		for _, idx := range t.Indexes {
			out = append(out, renderIndex(t, idx))
		}
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
		}
	case SQLite:
		switch t {
		case TypeText, TypeTimestamp:
			return "TEXT"
		case TypeInt:
			return "INTEGER"
		case TypeBool:
			return "INTEGER"
		}
	}
	return "text"
}
