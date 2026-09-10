package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/store/sqlite"
)

// TestSCNSCH003TheCLIExportsTheMigrationFiles proves REQ-SCH-003.
func TestSCNSCH003TheCLIExportsTheMigrationFiles(t *testing.T) {
	cases := []struct {
		format string
		want   []string
	}{
		{"goose", []string{
			"20260101000000_authall_core.sql",
			"20260910000001_authall_user_admin_columns.sql",
			"20260910000002_authall_apikeys.sql",
			"20260910000004_authall_bootstrap.sql",
		}},
		{"plain", []string{
			"20260101000000_authall_core.up.sql",
			"20260101000000_authall_core.down.sql",
			"20260910000001_authall_user_admin_columns.up.sql",
			"20260910000001_authall_user_admin_columns.down.sql",
			"20260910000002_authall_apikeys.up.sql",
			"20260910000002_authall_apikeys.down.sql",
			"20260910000004_authall_bootstrap.up.sql",
			"20260910000004_authall_bootstrap.down.sql",
		}},
	}
	for _, c := range cases {
		dir := filepath.Join(t.TempDir(), c.format)
		err := run([]string{"migrate", "export", "--driver", "postgres", "--format", c.format, "--dir", dir})
		if err != nil {
			t.Fatalf("%s export: %v", c.format, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir: %v", err)
		}
		if len(entries) != len(c.want) {
			t.Fatalf("the %s export wrote %d files, want %d", c.format, len(entries), len(c.want))
		}
		for _, name := range c.want {
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			if len(raw) == 0 {
				t.Fatalf("the file %s is empty", name)
			}
			if c.format == "goose" && !strings.Contains(string(raw), "-- +goose Up") {
				t.Fatalf("the file %s has no goose marker", name)
			}
		}
	}
}

// TestSCNSCH003TheCLIExportRefusesAnUnknownFormat proves REQ-SCH-003.
func TestSCNSCH003TheCLIExportRefusesAnUnknownFormat(t *testing.T) {
	if err := run([]string{"migrate", "export", "--format", "yaml", "--dir", t.TempDir()}); err == nil {
		t.Fatal("an unknown format was accepted")
	}
	if err := run([]string{"migrate", "export", "--format", "goose"}); err == nil {
		t.Fatal("a missing directory was accepted")
	}
}

// TestSCNOPS006TheCLICreatesAUserThatSignsIn proves REQ-OPS-008.
func TestSCNOPS006TheCLICreatesAUserThatSignsIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cli.db")
	dsn := "file:" + path
	const address = "cli.person@example.com"
	const password = "a-correct-horse-battery"

	if err := run([]string{"migrate", "--driver", "sqlite", "--dsn", dsn}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := run([]string{"user", "create", "--driver", "sqlite", "--dsn", dsn,
		"--email", address, "--role", "operator", "--password", password, "--temporary=false"}); err != nil {
		t.Fatalf("user create: %v", err)
	}

	db, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlite.New(db)
	h := testsupport.NewHarnessWithStore(t, s, authall.WithEmailPassword())
	resp, _ := h.SignIn(address, password)
	if resp.Status != http.StatusOK {
		t.Fatalf("the sign-in returned %d: %s", resp.Status, string(resp.Body))
	}

	// The reset sets a new password, and the old one stops to work.
	const fresh = "another-correct-horse"
	if err := run([]string{"user", "reset-password", "--driver", "sqlite", "--dsn", dsn,
		"--email", address, "--password", fresh, "--temporary=false"}); err != nil {
		t.Fatalf("user reset-password: %v", err)
	}
	h.ClearCookies()
	if resp, _ = h.SignIn(address, password); resp.Status == http.StatusOK {
		t.Fatal("the old password still works")
	}
	h.ClearCookies()
	if resp, _ = h.SignIn(address, fresh); resp.Status != http.StatusOK {
		t.Fatalf("the new password returned %d: %s", resp.Status, string(resp.Body))
	}
}
