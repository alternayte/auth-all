package sqlite_test

import (
	"testing"

	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
	"github.com/alternayte/auth-all/store/storetest"
)

// TestStorageContract covers DB-002.
func TestStorageContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		return testsupport.NewSQLite(t)
	})
}

// TestSCNSCH004TheContractPassesWithAPrefixAndUUIDKeys proves REQ-SCH-005 and
// REQ-SCH-006 on SQLite.
func TestSCNSCH004TheContractPassesWithAPrefixAndUUIDKeys(t *testing.T) {
	o := schema.Options{Prefix: "iam_", IDType: schema.IDUUID}
	storetest.RunWithOptions(t, func(t *testing.T) store.Store {
		return testsupport.NewSQLiteWithOptions(t, o)
	}, o)
}
