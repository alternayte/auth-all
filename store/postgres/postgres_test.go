package postgres_test

import (
	"context"
	"testing"

	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
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
