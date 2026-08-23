package sqlite_test

import (
	"testing"

	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/store"
	"github.com/alternayte/auth-all/store/storetest"
)

// TestStorageContract covers DB-002.
func TestStorageContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		return testsupport.NewSQLite(t)
	})
}
