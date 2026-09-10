package postgres_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
	"github.com/alternayte/auth-all/store/postgres"
	"github.com/alternayte/auth-all/store/storetest"
)

// TestStorageContract covers DB-001.
func TestStorageContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		return testsupport.NewPostgres(t)
	})
}

// TestSCNSCH004TheContractPassesWithAPrefixAndUUIDKeys proves REQ-SCH-005 and
// REQ-SCH-006 on PostgreSQL. The catalog check confirms that no default name
// survives.
func TestSCNSCH004TheContractPassesWithAPrefixAndUUIDKeys(t *testing.T) {
	o := schema.Options{Prefix: "iam_", IDType: schema.IDUUID}
	storetest.RunWithOptions(t, func(t *testing.T) store.Store {
		return testsupport.NewPostgresWithOptions(t, o)
	}, o)
	t.Run("NoDefaultNameInTheCatalog", func(t *testing.T) {
		s := testsupport.NewPostgresWithOptions(t, o)
		inspector, ok := s.(store.CatalogInspector)
		if !ok {
			t.Fatal("the store cannot read the catalog")
		}
		for _, name := range []string{"auth_users", "auth_sessions", "auth_schema_migrations"} {
			if _, exists, err := inspector.TableColumns(context.Background(), name); err != nil {
				t.Fatalf("catalog: %v", err)
			} else if exists {
				t.Fatalf("the table %s exists", name)
			}
		}
		columns, exists, err := inspector.TableColumns(context.Background(), "iam_users")
		if err != nil || !exists {
			t.Fatalf("iam_users is absent: %v", err)
		}
		if len(columns) == 0 {
			t.Fatal("iam_users has no column")
		}
	})
}

// TestSCNPG001TheContractPassesOverAPool proves REQ-PG-001 and REQ-PG-005. The
// pool store and the handle store run the same suite.
func TestSCNPG001TheContractPassesOverAPool(t *testing.T) {
	dsn := testsupport.PostgresDSN(t)
	o := schema.Options{Prefix: testsupport.UniquePrefix()}
	storetest.RunWithOptions(t, func(t *testing.T) store.Store {
		return testsupport.NewPostgresPool(t, dsn, o)
	}, o)
}

// TestSCNPG002ThePoolRefusesAStatementCache proves REQ-PG-002.
func TestSCNPG002ThePoolRefusesAStatementCache(t *testing.T) {
	refused := []pgx.QueryExecMode{pgx.QueryExecModeCacheStatement, pgx.QueryExecModeCacheDescribe}
	for _, mode := range refused {
		pool := newPool(t, mode)
		if _, err := postgres.NewPool(pool); err == nil {
			t.Fatalf("the exec mode %v was accepted", mode)
		}
		if _, err := postgres.NewPool(pool, postgres.AllowStatementCache()); err != nil {
			t.Fatalf("AllowStatementCache refused the exec mode %v: %v", mode, err)
		}
	}
	for _, mode := range []pgx.QueryExecMode{pgx.QueryExecModeExec, pgx.QueryExecModeSimpleProtocol} {
		if _, err := postgres.NewPool(newPool(t, mode)); err != nil {
			t.Fatalf("the exec mode %v was refused: %v", mode, err)
		}
	}
	if _, err := postgres.NewPool(nil); err == nil {
		t.Fatal("a nil pool was accepted")
	}
}

// newPool returns a pool configuration with one exec mode. It opens no
// connection, so the test needs no database.
func newPool(t *testing.T, mode pgx.QueryExecMode) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://authall:authall@127.0.0.1:1/authall?sslmode=disable")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg.ConnConfig.DefaultQueryExecMode = mode
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestSCNPG003TheContractPassesThroughATransactionPooler proves REQ-PG-003 and
// REQ-PG-004.
func TestSCNPG003TheContractPassesThroughATransactionPooler(t *testing.T) {
	dsn := testsupport.PgBouncerDSN(t)
	o := schema.Options{Prefix: testsupport.UniquePrefix()}
	storetest.RunWithOptions(t, func(t *testing.T) store.Store {
		return testsupport.NewPostgresPool(t, dsn, o)
	}, o)
}
