// Package migrations exports the Auth-All migration units as files. The host
// applies the files with its own migration tool. Auth-All never runs a
// migration on its own.
package migrations

import (
	"fmt"
	"strings"

	"github.com/alternayte/auth-all/schema"
)

// Format selects the file layout of the export.
type Format string

// Supported formats.
const (
	// Goose writes one file for each unit with the goose annotations.
	Goose Format = "goose"
	// Plain writes one up file and one down file for each unit.
	Plain Format = "plain"
)

// File is one exported migration file.
type File struct {
	// Name is the file name without a directory.
	Name string
	// Content is the complete file content.
	Content string
}

// Render returns the files of the units in version order.
func Render(units []schema.Unit, d schema.Dialect, f Format) ([]File, error) {
	switch f {
	case Goose, Plain:
	default:
		return nil, fmt.Errorf("authall/migrations: unsupported format %q", f)
	}
	if d != schema.Postgres && d != schema.SQLite {
		return nil, fmt.Errorf("authall/migrations: unsupported dialect %q", d)
	}
	var out []File
	for _, u := range units {
		up, ok := u.Up[d]
		if !ok {
			return nil, fmt.Errorf("authall/migrations: the unit %s has no %s statement", u.FileName(), d)
		}
		down := u.Down[d]
		if f == Plain {
			out = append(out,
				File{Name: u.FileName() + ".up.sql", Content: body(up)},
				File{Name: u.FileName() + ".down.sql", Content: body(down)})
			continue
		}
		var b strings.Builder
		b.WriteString("-- " + u.FileName() + "\n")
		b.WriteString("-- Owner: " + u.Owner + "\n")
		b.WriteString("-- +goose Up\n")
		b.WriteString(body(up))
		b.WriteString("\n-- +goose Down\n")
		b.WriteString(body(down))
		out = append(out, File{Name: u.FileName() + ".sql", Content: b.String()})
	}
	return out, nil
}

// body returns the statements as SQL, one statement for each block.
func body(statements []schema.Statement) string {
	var b strings.Builder
	for _, st := range statements {
		b.WriteString("-- " + st.ID + "\n")
		b.WriteString(st.SQL)
		b.WriteString(";\n\n")
	}
	return b.String()
}
