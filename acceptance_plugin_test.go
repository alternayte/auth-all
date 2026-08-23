package authall_test

import (
	"context"
	"database/sql"
	"errors"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/schema"
)

// testPlugin is a third-party plugin. It uses only the public plugin package,
// so it proves what an external author can do.
type testPlugin struct {
	mu           sync.Mutex
	createdUsers []string
	bannedEmail  string
	svc          plugin.Services
}

const testPluginTable = "test_plugin_notes"

func (p *testPlugin) ID() string { return "test-plugin" }

func (p *testPlugin) Register(r *plugin.Registry) error {
	p.svc = r.Services()

	// PLUG-002: schema contribution.
	r.Schema(schema.Table{
		Name: testPluginTable,
		Columns: []schema.Column{
			{Name: "id", Type: schema.TypeText, PrimaryKey: true},
			{Name: "note", Type: schema.TypeText},
			{Name: "created_at", Type: schema.TypeTimestamp},
		},
		Indexes: []schema.Index{{Name: "test_plugin_notes_note_idx", Columns: []string{"note"}}},
	})

	// PLUG-001 and PLUG-004: route and OpenAPI contribution.
	r.Route(plugin.Route{
		Method: http.MethodPost,
		Path:   "/test-plugin/ping",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]string{"pong": "ok"})
		}),
		Operation: &openapi.Operation{
			OperationID: "testPluginPing",
			Summary:     "Answer a plugin ping",
			Tags:        []string{"test-plugin"},
			RequestBody: openapi.JSONBody(openapi.Object(nil, map[string]*openapi.Schema{
				"note": openapi.String(),
			})),
			Responses: map[string]openapi.Response{
				"200": openapi.JSONResponse("A pong", openapi.Object([]string{"pong"},
					map[string]*openapi.Schema{"pong": openapi.String()})),
			},
			Client: &openapi.ClientBinding{Namespace: "testPlugin", Method: "ping"},
		},
	})

	// PLUG-003: hook contribution.
	r.Hooks().OnBeforeUserCreate(func(ctx context.Context, ev *hook.UserCreate) error {
		if p.bannedEmail != "" && ev.User.EmailNormalized == p.bannedEmail {
			return apierr.ErrForbidden.WithMessage("This address is not accepted.")
		}
		if ev.Tx == nil {
			return errors.New("a before hook must receive the transaction")
		}
		return nil
	})
	r.Hooks().OnAfterUserCreate(func(ctx context.Context, ev *hook.UserCreate) error {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.createdUsers = append(p.createdUsers, ev.User.ID)
		return nil
	})
	return nil
}

func (p *testPlugin) created() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.createdUsers...)
}

func pluginHarness(t *testing.T, p *testPlugin) *testsupport.Harness {
	t.Helper()
	return testsupport.NewHarness(t,
		authall.WithEmailPassword(),
		authall.WithPlugins(p))
}

// TestPLUG001Route covers PLUG-001.
func TestPLUG001Route(t *testing.T) {
	h := pluginHarness(t, &testPlugin{})
	resp := h.Do(http.MethodPost, "/test-plugin/ping", map[string]string{"note": "hello"})
	if resp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	var body map[string]string
	resp.Decode(t, &body)
	if body["pong"] != "ok" {
		t.Fatalf("unexpected body %v", body)
	}
}

// TestPLUG002Schema covers PLUG-002.
func TestPLUG002Schema(t *testing.T) {
	h := pluginHarness(t, &testPlugin{})
	if _, ok := h.Auth.Schema().Table(testPluginTable); !ok {
		t.Fatalf("the plugin table is missing from the effective schema")
	}
	raw, ok := h.Store.(interface{ DB() *sql.DB })
	if !ok {
		t.Fatalf("the store does not expose a database handle")
	}
	// The migration created the table, so a write succeeds.
	if _, err := raw.DB().Exec(
		"INSERT INTO "+testPluginTable+" (id, note, created_at) VALUES (?, ?, ?)",
		"note-1", "hello", "2026-01-01T00:00:00.000000000"); err != nil {
		t.Fatalf("the plugin table was not created: %v", err)
	}
	var note string
	if err := raw.DB().QueryRow("SELECT note FROM " + testPluginTable).Scan(&note); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if note != "hello" {
		t.Fatalf("unexpected note %q", note)
	}
}

// TestPLUG003Hook covers PLUG-003.
func TestPLUG003Hook(t *testing.T) {
	p := &testPlugin{bannedEmail: "banned@example.com"}
	h := pluginHarness(t, p)

	_, out := h.SignUp("hooked@example.com", testPassword)
	created := p.created()
	if len(created) != 1 || created[0] != out.User.ID {
		t.Fatalf("the after hook did not run: %v", created)
	}
	h.ClearCookies()
	resp, _ := h.SignUp("banned@example.com", testPassword)
	if resp.Status != http.StatusForbidden {
		t.Fatalf("the before hook did not reject the operation: %d %s", resp.Status, string(resp.Body))
	}
	if _, err := h.Auth.GetUserByEmail(context.Background(), "banned@example.com"); err == nil {
		t.Fatalf("the rejected user was created anyway")
	}
	if len(p.created()) != 1 {
		t.Fatalf("the after hook ran for a rejected user")
	}
}

// TestPLUG004OpenAPI covers PLUG-004.
func TestPLUG004OpenAPI(t *testing.T) {
	h := pluginHarness(t, &testPlugin{})
	doc := h.Auth.OpenAPI()
	item, ok := doc.Paths["/api/auth/test-plugin/ping"]
	if !ok {
		t.Fatalf("the plugin operation is missing from the OpenAPI document")
	}
	op, ok := item["post"]
	if !ok || op.OperationID != "testPluginPing" {
		t.Fatalf("unexpected operation %+v", op)
	}
	if op.Client == nil || op.Client.Namespace != "testPlugin" || op.Client.Method != "ping" {
		t.Fatalf("the plugin operation carries no client binding")
	}
}

// TestPLUG006MagicLinkUsesPublicAPIsOnly covers PLUG-006.
func TestPLUG006MagicLinkUsesPublicAPIsOnly(t *testing.T) {
	dir := filepath.Join("plugins", "magiclink")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the plugin directory: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		name := filepath.Join(dir, entry.Name())
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(path, "/internal/") {
				t.Fatalf("%s imports the internal package %q", name, path)
			}
			if path == "github.com/alternayte/auth-all" {
				t.Fatalf("%s imports the core package, which a third-party plugin cannot rely on for extension", name)
			}
		}
	}
	if checked == 0 {
		t.Fatalf("the Magic Link package was not found")
	}
}

// TestPluginIdMustBeUnique checks the registration guard.
func TestPluginIdMustBeUnique(t *testing.T) {
	s := testsupport.NewSQLite(t)
	_, err := authall.New(
		authall.WithStore(s),
		authall.WithPlugins(&testPlugin{}, &testPlugin{}),
	)
	if err == nil {
		t.Fatalf("a duplicate plugin id was accepted")
	}
}
