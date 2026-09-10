package store

import (
	"context"

	"github.com/alternayte/auth-all/schema"
)

// The interfaces in this file are optional. A store that does not implement one
// keeps the v1 behavior, and the caller that needs the capability reports a
// clear error. A new method on Store would break every third-party adapter, so
// every later capability arrives here.

// SchemaConfigurable accepts the physical schema options of the host. Auth-All
// calls it during construction when the host uses a table prefix or another
// identifier type.
type SchemaConfigurable interface {
	// UseSchema sets the physical names and types. It reports an error when the
	// store cannot serve the options.
	UseSchema(o schema.Options) error
}

// CatalogInspector reads the state of the database from the catalog of the
// engine. A host that applies the exported migrations with its own tool writes
// no Auth-All record, so the catalog is the only source of truth.
type CatalogInspector interface {
	// TableColumns returns the column names of one table. It returns false when
	// the table is absent.
	TableColumns(ctx context.Context, table string) ([]string, bool, error)
}
