package schema_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/alternayte/auth-all/migrations"
	"github.com/alternayte/auth-all/schema"
)

// defaultName finds an object name that still starts with the default prefix.
var defaultName = regexp.MustCompile(`\bauth_`)

// export renders the core units of one dialect in the goose format.
func export(t *testing.T, d schema.Dialect, o schema.Options) string {
	t.Helper()
	units, err := schema.CoreUnits(o)
	if err != nil {
		t.Fatalf("core units: %v", err)
	}
	files, err := migrations.Render(units, d, migrations.Goose)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var b strings.Builder
	for _, f := range files {
		b.WriteString("===== " + f.Name + " =====\n")
		b.WriteString(f.Content)
	}
	return b.String()
}

// TestSCNSCH001ExportMatchesTheGoldenFiles proves REQ-SCH-001 and REQ-SCH-004.
// A released unit produces byte-identical SQL, so the test compares the export
// with a committed file.
func TestSCNSCH001ExportMatchesTheGoldenFiles(t *testing.T) {
	for _, d := range []schema.Dialect{schema.Postgres, schema.SQLite} {
		got := export(t, d, schema.DefaultOptions())
		golden := filepath.Join("testdata", "export_"+string(d)+".sql")
		if os.Getenv("AUTHALL_UPDATE_GOLDEN") == "1" {
			if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
				t.Fatalf("write golden: %v", err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("read golden: %v", err)
		}
		if got != string(want) {
			t.Fatalf("the %s export differs from %s.\n--- got ---\n%s", d, golden, got)
		}
	}
}

// TestSCNSCH001ExportSortsTheUnitsByVersion proves REQ-SCH-001.
func TestSCNSCH001ExportSortsTheUnitsByVersion(t *testing.T) {
	s, err := schema.NewCore()
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	units, err := s.Units()
	if err != nil {
		t.Fatalf("units: %v", err)
	}
	if len(units) < 2 {
		t.Fatalf("want at least two units, got %d", len(units))
	}
	for i := 1; i < len(units); i++ {
		if units[i-1].Version >= units[i].Version {
			t.Fatalf("unit %d is not after unit %d", i, i-1)
		}
	}
	if units[0].FileName() != "20260101000000_authall_core" {
		t.Fatalf("the first unit is %q", units[0].FileName())
	}
}

// TestSCNSCH005AnInvalidPrefixFailsConstruction proves REQ-SCH-005.
func TestSCNSCH005AnInvalidPrefixFailsConstruction(t *testing.T) {
	for _, prefix := range []string{"1bad", "Bad_", "bad-prefix", "way_too_long_prefix_for_one_table_name"} {
		if _, err := schema.NewCoreWithOptions(schema.Options{Prefix: prefix}); err == nil {
			t.Fatalf("the prefix %q was accepted", prefix)
		}
	}
	if _, err := schema.NewCoreWithOptions(schema.Options{Prefix: "iam_"}); err != nil {
		t.Fatalf("the prefix iam_ failed: %v", err)
	}
}

// TestSCNSCH005ThePrefixNamesEveryObject proves REQ-SCH-005. It also proves
// REQ-SCH-006 for the identifier columns.
func TestSCNSCH005ThePrefixNamesEveryObject(t *testing.T) {
	o := schema.Options{Prefix: "iam_", IDType: schema.IDUUID}
	s, err := schema.NewCoreWithOptions(o)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	for _, tab := range s.Tables() {
		if !strings.HasPrefix(tab.Name, "iam_") {
			t.Fatalf("the table %q keeps the default prefix", tab.Name)
		}
		for _, idx := range tab.Indexes {
			if !strings.HasPrefix(idx.Name, "iam_") {
				t.Fatalf("the index %q keeps the default prefix", idx.Name)
			}
		}
		for _, fk := range tab.ForeignKeys {
			if !strings.HasPrefix(fk.RefTable, "iam_") {
				t.Fatalf("the foreign key of %q names %q", tab.Name, fk.RefTable)
			}
		}
	}
	sql := export(t, schema.Postgres, o)
	if defaultName.MatchString(sql) {
		t.Fatalf("the export still holds an auth_ name:\n%s", sql)
	}
	if !strings.Contains(sql, "id uuid NOT NULL PRIMARY KEY") {
		t.Fatalf("the export has no uuid primary key:\n%s", sql)
	}
	if !strings.Contains(sql, "user_id uuid") {
		t.Fatalf("the export has no uuid foreign key:\n%s", sql)
	}
}

// TestSCNSCH006TheSQLiteExportKeepsTextIdentifiers proves REQ-SCH-006. SQLite
// has no uuid type.
func TestSCNSCH006TheSQLiteExportKeepsTextIdentifiers(t *testing.T) {
	sql := export(t, schema.SQLite, schema.Options{Prefix: "iam_", IDType: schema.IDUUID})
	if strings.Contains(sql, "uuid") {
		t.Fatalf("the SQLite export names a uuid type:\n%s", sql)
	}
}

// TestExtensionRefusesAnUnusableColumn proves that an added column cannot break
// an existing row.
func TestExtensionRefusesAnUnusableColumn(t *testing.T) {
	s, err := schema.NewCore()
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	err = s.Extend(schema.Extension{
		Table:   schema.TableUsers,
		Columns: []schema.Column{{Name: "team", Type: schema.TypeText}},
	})
	if err == nil {
		t.Fatal("a column with no default and no null was accepted")
	}
	if err := s.Extend(schema.Extension{
		Table:   schema.TableUsers,
		Columns: []schema.Column{{Name: "team", Type: schema.TypeText, Nullable: true}},
	}); err != nil {
		t.Fatalf("a nullable column was refused: %v", err)
	}
	users, _ := s.Table(schema.TableUsers)
	found := false
	for _, c := range users.Columns {
		if c.Name == "team" {
			found = true
		}
	}
	if !found {
		t.Fatal("the extension added no column")
	}
	if err := s.Extend(schema.Extension{
		Table:   "iam_missing",
		Columns: []schema.Column{{Name: "team", Type: schema.TypeText, Nullable: true}},
	}); err == nil {
		t.Fatal("an extension of an unknown table was accepted")
	}
}
