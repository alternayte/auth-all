package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
			"20260910000004_authall_bootstrap.sql",
		}},
		{"plain", []string{
			"20260101000000_authall_core.up.sql",
			"20260101000000_authall_core.down.sql",
			"20260910000001_authall_user_admin_columns.up.sql",
			"20260910000001_authall_user_admin_columns.down.sql",
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
