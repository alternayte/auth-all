// Package postgres provides the PostgreSQL storage adapter for Auth-All.
package postgres

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/alternayte/auth-all/internal/sqlstore"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

var dialect = sqlstore.Dialect{
	Name:                 schema.Postgres,
	NumberedPlaceholders: true,
	TextTime:             false,
	IsUniqueViolation:    isUniqueViolation,
	StringAgg:            func(expr, sep string) string { return "string_agg(" + expr + ", '" + sep + "')" },
}

// New returns a PostgreSQL store over an application-owned database handle.
func New(db *sql.DB) store.Store {
	return sqlstore.New(db, dialect)
}

// Option configures the pool store.
type Option func(*poolConfig)

type poolConfig struct {
	// allowStatementCache accepts a pool that caches prepared statements.
	allowStatementCache bool
}

// AllowStatementCache accepts a pool whose exec mode caches a prepared
// statement. Use it only when no transaction pooler stands between the
// application and PostgreSQL.
func AllowStatementCache() Option {
	return func(c *poolConfig) { c.allowStatementCache = true }
}

// NewPool returns a PostgreSQL store over an application-owned pgx pool.
//
// The store is safe behind a transaction pooler. It makes no named prepared
// statement, takes no advisory lock, and creates no temporary table. The pool
// must therefore use an exec mode that caches no statement. NewPool refuses
// another mode, because the failure would otherwise appear later as a random
// "prepared statement does not exist" error.
func NewPool(pool *pgxpool.Pool, opts ...Option) (store.Store, error) {
	if pool == nil {
		return nil, errors.New("authall/postgres: the pool is nil")
	}
	cfg := &poolConfig{}
	for _, o := range opts {
		o(cfg)
	}
	mode := pool.Config().ConnConfig.DefaultQueryExecMode
	if !cfg.allowStatementCache && cachesStatements(mode) {
		return nil, fmt.Errorf("authall/postgres: the pool uses the exec mode %v, which caches a prepared statement. "+
			"A transaction pooler then fails with \"prepared statement does not exist\". "+
			"Use pgx.QueryExecModeExec, or use postgres.AllowStatementCache", mode)
	}
	db := stdlib.OpenDBFromPool(pool)
	return sqlstore.New(db, dialect), nil
}

// cachesStatements reports whether an exec mode keeps a named prepared
// statement on the server connection.
func cachesStatements(m pgx.QueryExecMode) bool {
	return m == pgx.QueryExecModeCacheStatement || m == pgx.QueryExecModeCacheDescribe
}

// Open returns a database handle for a PostgreSQL DSN. The application owns the
// returned handle.
func Open(dsn string) (*sql.DB, error) {
	return sql.Open("pgx", dsn)
}

func isUniqueViolation(err error) bool {
	var e *pgconn.PgError
	if errors.As(err, &e) {
		return e.Code == "23505"
	}
	return false
}
