package humaauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/humaauth"
	"github.com/alternayte/auth-all/plugins/roles"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
	"github.com/alternayte/auth-all/store/sqlite"
)

// testHierarchy is the role hierarchy of these tests.
var testHierarchy = []string{"viewer", "operator", "editor", "admin"}

// newAuth returns one migrated Auth-All instance with the roles plugin.
func newAuth(t *testing.T) (*authall.Auth, *roles.Plugin, store.Store) {
	t.Helper()
	db, err := sqlite.Open("file:" + filepath.Join(t.TempDir(), "huma.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlite.New(db)
	r := roles.New(roles.Hierarchy(testHierarchy...), roles.Default("viewer"))
	insecure := false
	auth, err := authall.New(
		authall.WithStore(s),
		authall.WithBaseURL("https://app.example.com"),
		authall.WithEmailPassword(),
		authall.WithCookie(authall.CookieOptions{Secure: &insecure}),
		authall.WithRateLimiter(ratelimit.NewMemory(1000, time.Minute)),
		authall.WithPlugins(r),
	)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := auth.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := auth.CheckSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return auth, r, s
}

// TestSCNHTTP005TheDocumentHoldsEveryOperation proves REQ-HTTP-010 and
// REQ-HTTP-011.
func TestSCNHTTP005TheDocumentHoldsEveryOperation(t *testing.T) {
	auth, _, _ := newAuth(t)
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Example", "1.0.0"))
	if err := humaauth.Register(api, auth); err != nil {
		t.Fatalf("register: %v", err)
	}

	doc := api.OpenAPI()
	for _, route := range auth.Routes() {
		if !route.Documented {
			continue
		}
		item, ok := doc.Paths[route.Path]
		if !ok || item == nil {
			t.Fatalf("the path %s is absent", route.Path)
		}
		if operationOf(item, route.Method) == nil {
			t.Fatalf("the route %s %s is absent", route.Method, route.Path)
		}
	}
	for name := range auth.OpenAPI().Components.Schemas {
		if _, ok := doc.Components.Schemas.Map()[name]; !ok {
			t.Fatalf("the schema %s is absent", name)
		}
	}

	// A second merge collides with the first one.
	if err := humaauth.Register(api, auth); err == nil {
		t.Fatal("a duplicate operation id was accepted")
	}
}

// operationOf returns the operation of one method.
func operationOf(item *huma.PathItem, method string) *huma.Operation {
	switch method {
	case http.MethodGet:
		return item.Get
	case http.MethodPost:
		return item.Post
	case http.MethodPut:
		return item.Put
	case http.MethodPatch:
		return item.Patch
	case http.MethodDelete:
		return item.Delete
	}
	return nil
}

// TestSCNHTTP005ADuplicateSchemaNameFails proves REQ-HTTP-011.
func TestSCNHTTP005ADuplicateSchemaNameFails(t *testing.T) {
	auth, _, _ := newAuth(t)
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Example", "1.0.0"))
	api.OpenAPI().Components.Schemas.Map()["User"] = &huma.Schema{Type: "object"}
	if err := humaauth.Register(api, auth); err == nil {
		t.Fatal("a duplicate schema name was accepted")
	}
}

// deployOutput is the body of the protected huma operation.
type deployOutput struct {
	Body struct {
		Deployed bool `json:"deployed"`
	}
}

// TestSCNHTTP006TheRoleMiddlewareRefusesALowerRole proves REQ-HTTP-012.
func TestSCNHTTP006TheRoleMiddlewareRefusesALowerRole(t *testing.T) {
	auth, _, s := newAuth(t)
	mux := http.NewServeMux()
	mux.Handle(auth.BasePath()+"/", auth.Handler())
	api := humago.New(mux, huma.DefaultConfig("Example", "1.0.0"))
	if err := humaauth.Register(api, auth); err != nil {
		t.Fatalf("register: %v", err)
	}

	// The Auth-All middleware resolves the principal, and the huma middleware
	// checks the role.
	huma.Register(api, huma.Operation{
		OperationID: "deploy",
		Method:      http.MethodGet,
		Path:        "/deploy",
		Middlewares: huma.Middlewares{humaauth.RequireRole(api, auth, "admin")},
	}, func(context.Context, *struct{}) (*deployOutput, error) {
		out := &deployOutput{}
		out.Body.Deployed = true
		return out, nil
	})

	protected := auth.RequireAuth(mux)
	srv := httptest.NewServer(protectedOnly(mux, protected))
	t.Cleanup(srv.Close)

	client := srv.Client()
	token := signUp(t, srv, client, "huma@example.com")

	// The viewer role is below admin.
	if got := call(t, client, srv.URL+"/deploy", token); got != http.StatusForbidden {
		t.Fatalf("the viewer got %d", got)
	}

	// The administrator passes.
	setRole(t, s, "huma@example.com", "admin")
	if got := call(t, client, srv.URL+"/deploy", token); got != http.StatusOK {
		t.Fatalf("the administrator got %d", got)
	}

	// An anonymous request gets 401.
	if got := call(t, client, srv.URL+"/deploy", ""); got != http.StatusUnauthorized {
		t.Fatalf("the anonymous request got %d", got)
	}

	// An unknown minimum role panics at construction.
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("an unknown minimum role was accepted")
			}
		}()
		humaauth.RequireRole(api, auth, "root")
	}()
}

// protectedOnly sends the huma route through the Auth-All middleware and every
// other route straight to the mux.
func protectedOnly(mux http.Handler, protected http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/deploy" {
			protected.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// signUp creates one user and returns the session token.
func signUp(t *testing.T, srv *httptest.Server, client *http.Client, address string) string {
	t.Helper()
	body := `{"email":"` + address + `","password":"a-correct-horse-battery","name":"Test"}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/sign-up/email",
		strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("sign-up: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("the sign-up returned %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == authall.DefaultCookieName {
			return c.Value
		}
	}
	t.Fatal("the sign-up returned no session cookie")
	return ""
}

// call sends one request with an optional bearer token and returns the status.
func call(t *testing.T, client *http.Client, target, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// setRole writes the role of one user.
func setRole(t *testing.T, s store.Store, address, role string) {
	t.Helper()
	ctx := context.Background()
	user, err := s.Users().GetByNormalizedEmail(ctx, address)
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	user.Role = role
	if err := s.Users().Update(ctx, user); err != nil {
		t.Fatalf("update user: %v", err)
	}
}
