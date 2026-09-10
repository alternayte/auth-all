package authall_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/admin"
	"github.com/alternayte/auth-all/plugins/apikeys"
	"github.com/alternayte/auth-all/plugins/roles"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// instance is one Auth-All process over a shared database.
type instance struct {
	auth   *authall.Auth
	admin  *admin.Plugin
	server *httptest.Server
}

// newInstance builds one Auth-All instance over a store and serves it.
func newInstance(t *testing.T, s store.Store, migrate bool, opts ...authall.Option) *instance {
	t.Helper()
	adm := admin.New(admin.AdminRole("admin"))
	r := roles.New(roles.Hierarchy(testHierarchy...), roles.Default("viewer"))
	insecure := false
	base := []authall.Option{
		authall.WithStore(s),
		authall.WithEmailPassword(),
		authall.WithCookie(authall.CookieOptions{Secure: &insecure}),
		authall.WithRateLimiter(ratelimit.NewMemory(1000, time.Minute)),
		authall.WithPlugins(r, adm, apikeys.New()),
	}
	auth, err := authall.New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if migrate {
		if _, err := auth.Migrate(context.Background()); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	mux := http.NewServeMux()
	mux.Handle(auth.BasePath()+"/", auth.Handler())
	mux.Handle("/host/any", auth.RequireAuth(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &instance{auth: auth, admin: adm, server: srv}
}

// callWithKey sends one request with an API key and returns the status.
func callWithKey(t *testing.T, in *instance, key string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, in.server.URL+"/host/any", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := in.server.Client().Do(req)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestSCNCON001TheSecondInstanceRefusesADisabledUser proves REQ-CON-001 and
// REQ-CON-003.
func TestSCNCON001TheSecondInstanceRefusesADisabledUser(t *testing.T) {
	s := testsupport.NewSQLite(t)
	first := newInstance(t, s, true)
	second := newInstance(t, s, false)

	ctx := context.Background()
	user := testsupport.NewUser("shared@example.com")
	if err := s.Users().Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	_, plaintext, err := createKeyThroughStore(t, second, user)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	if got := callWithKey(t, second, plaintext); got != http.StatusNoContent {
		t.Fatalf("the key request returned %d", got)
	}

	// The first instance disables the user.
	if _, err := first.admin.Disable(ctx, user.ID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	// With no cache, the second instance reads the store for every request, so
	// the effective bound is zero.
	if got := callWithKey(t, second, plaintext); got != http.StatusUnauthorized {
		t.Fatalf("the second instance returned %d after the disable", got)
	}
}

// TestSCNCON002TheCacheTimeStaysInsideTheBound proves REQ-CON-002 and
// REQ-CON-004.
func TestSCNCON002TheCacheTimeStaysInsideTheBound(t *testing.T) {
	s := testsupport.NewSQLite(t)
	if _, err := authall.New(authall.WithStore(s),
		authall.WithPrincipalCache(10*time.Second)); err == nil {
		t.Fatal("a cache time above the bound was accepted")
	}
	auth, err := authall.New(authall.WithStore(s), authall.WithPrincipalCache(5*time.Second))
	if err != nil {
		t.Fatalf("a cache time of the bound failed: %v", err)
	}
	if auth.ConsistencyBound() != 5*time.Second {
		t.Fatalf("the default bound is %s", auth.ConsistencyBound())
	}
	if _, err := authall.New(authall.WithStore(s),
		authall.WithConsistencyBound(30*time.Second),
		authall.WithPrincipalCache(10*time.Second)); err != nil {
		t.Fatalf("a longer bound refused the cache: %v", err)
	}
}

// TestSCNCON003TheCacheEndsInsideTheBound proves REQ-CON-001 and REQ-CON-004.
func TestSCNCON003TheCacheEndsInsideTheBound(t *testing.T) {
	s := testsupport.NewSQLite(t)
	clock := time.Now().UTC()
	now := func() time.Time { return clock }
	first := newInstance(t, s, true, authall.WithClock(now))
	second := newInstance(t, s, false,
		authall.WithClock(now),
		authall.WithPrincipalCache(5*time.Second),
	)

	ctx := context.Background()
	user := testsupport.NewUser("cached@example.com")
	if err := s.Users().Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	keyID, plaintext, err := createKeyThroughStore(t, second, user)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	if got := callWithKey(t, second, plaintext); got != http.StatusNoContent {
		t.Fatalf("the key request returned %d", got)
	}

	// The first instance revokes the key. The cached entry of the second
	// instance still answers, which is the price of the cache.
	keys := s.(store.APIKeyStore)
	if err := keys.RevokeAPIKey(ctx, keyID, user.ID, clock); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_ = first
	if got := callWithKey(t, second, plaintext); got != http.StatusNoContent {
		t.Fatalf("the cached request returned %d before the bound", got)
	}

	// The bound passes on the fake clock, so the entry ends.
	clock = clock.Add(5 * time.Second)
	if got := callWithKey(t, second, plaintext); got != http.StatusUnauthorized {
		t.Fatalf("the request returned %d after the bound", got)
	}
}

// createKeyThroughStore inserts one key of a user and returns the identifier
// and the plaintext.
func createKeyThroughStore(t *testing.T, in *instance, user *store.User) (string, string, error) {
	t.Helper()
	plaintext, err := apikeys.NewPlaintextKey(apikeys.DefaultPrefix)
	if err != nil {
		return "", "", err
	}
	key := &store.APIKey{
		ID:        testsupport.NewUser("key@example.com").ID,
		UserID:    user.ID,
		Name:      "consistency",
		Start:     plaintext[:len(apikeys.DefaultPrefix)+4],
		KeyHash:   sha256Hex(plaintext),
		Role:      "viewer",
		CreatedAt: time.Now().UTC(),
	}
	keys, ok := in.auth.Store().(store.APIKeyStore)
	if !ok {
		t.Fatal("the store holds no API key")
	}
	if err := keys.CreateAPIKey(context.Background(), key); err != nil {
		return "", "", err
	}
	return key.ID, plaintext, nil
}

// TestSCNCON004NoPackageKeepsPrincipalsInMemory proves REQ-CON-005.
//
// The check reads the sources and refuses a package-level map or cache of
// principals outside the bounded cache.
func TestSCNCON004NoPackageKeepsPrincipalsInMemory(t *testing.T) {
	// principalcache.go holds the bounded cache, which the bound limits.
	allowed := map[string]bool{"principalcache.go": true}
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	var findings []string
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "node_modules" || entry.Name() == "clients" || entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if allowed[filepath.Base(path)] {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if !holdsPrincipalState(value) {
					continue
				}
				findings = append(findings, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(findings) > 0 {
		t.Fatalf("these files keep authorization state at package level: %s", strings.Join(findings, ", "))
	}
}

// holdsPrincipalState reports whether one package-level variable keeps a map or
// a cache of principals, sessions, keys, or users.
func holdsPrincipalState(value *ast.ValueSpec) bool {
	text := typeText(value.Type)
	for _, expr := range value.Values {
		text += " " + typeText(expr)
	}
	if !strings.Contains(text, "map[") && !strings.Contains(strings.ToLower(text), "cache") &&
		!strings.Contains(text, "sync.Map") {
		return false
	}
	for _, word := range []string{"Principal", "Session", "APIKey", "store.User"} {
		if strings.Contains(text, word) {
			return true
		}
	}
	return false
}

// typeText returns the source text of one expression.
func typeText(expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	var b strings.Builder
	ast.Inspect(expr, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			b.WriteString(node.Name + " ")
		case *ast.SelectorExpr:
			if pkg, ok := node.X.(*ast.Ident); ok {
				b.WriteString(pkg.Name + "." + node.Sel.Name + " ")
			}
		case *ast.MapType:
			b.WriteString("map[ ")
		}
		return true
	})
	return b.String()
}
