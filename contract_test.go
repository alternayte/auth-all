package authall_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/alternayte/auth-all/internal/clientgen"
	"github.com/alternayte/auth-all/internal/reference"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/openapi"

	authall "github.com/alternayte/auth-all"
)

// v1Endpoints is the normative endpoint set of Section 7 of the specification.
var v1Endpoints = []struct{ Method, Path string }{
	{"POST", "/api/auth/sign-up/email"},
	{"POST", "/api/auth/sign-in/email"},
	{"POST", "/api/auth/sign-out"},
	{"GET", "/api/auth/session"},
	{"POST", "/api/auth/password/forgot"},
	{"POST", "/api/auth/password/reset"},
	{"POST", "/api/auth/email-verification/send"},
	{"POST", "/api/auth/email-verification/verify"},
	{"GET", "/api/auth/oauth/{provider}"},
	{"GET", "/api/auth/oauth/{provider}/callback"},
	{"GET", "/api/auth/account/providers"},
	{"POST", "/api/auth/account/link/{provider}"},
	{"POST", "/api/auth/account/unlink/{provider}"},
	{"POST", "/api/auth/magic-link/send"},
	{"GET", "/api/auth/magic-link/verify"},
}

// TestAPI001OpenAPICompleteness covers API-001.
func TestAPI001OpenAPICompleteness(t *testing.T) {
	auth, err := reference.New()
	if err != nil {
		t.Fatal(err)
	}
	doc := auth.OpenAPI()
	for _, want := range v1Endpoints {
		item, ok := doc.Paths[want.Path]
		if !ok {
			t.Fatalf("the OpenAPI document misses the path %s", want.Path)
		}
		op, ok := item[strings.ToLower(want.Method)]
		if !ok || op == nil {
			t.Fatalf("the OpenAPI document misses %s %s", want.Method, want.Path)
		}
		if op.OperationID == "" {
			t.Fatalf("%s %s has no operation id", want.Method, want.Path)
		}
		if len(op.Responses) == 0 {
			t.Fatalf("%s %s documents no response", want.Method, want.Path)
		}
	}
	// Every mounted route is documented, so the contract cannot drift.
	for _, route := range auth.Routes() {
		if !route.Documented {
			t.Fatalf("the route %s %s is not documented", route.Method, route.Path)
		}
		item, ok := doc.Paths[route.Path]
		if !ok || item[strings.ToLower(route.Method)] == nil {
			t.Fatalf("the route %s %s is missing from the document", route.Method, route.Path)
		}
	}
	if len(auth.Routes()) != len(v1Endpoints) {
		t.Fatalf("the enabled API has %d routes, the specification lists %d", len(auth.Routes()), len(v1Endpoints))
	}
}

// TestAPI002GeneratedArtifactFreshness covers API-002.
func TestAPI002GeneratedArtifactFreshness(t *testing.T) {
	auth, err := reference.New()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(auth.OpenAPI(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	committed, err := os.ReadFile("api/openapi.json")
	if err != nil {
		t.Fatalf("read the committed contract: %v", err)
	}
	if string(raw) != string(committed) {
		t.Fatalf("api/openapi.json is stale. Run: just generate")
	}

	source, err := clientgen.Generate(auth.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	generated, err := os.ReadFile("clients/typescript/src/generated.ts")
	if err != nil {
		t.Fatalf("read the committed client: %v", err)
	}
	if source != string(generated) {
		t.Fatalf("clients/typescript/src/generated.ts is stale. Run: just generate")
	}
}

// TestGenerationIsDeterministic checks that repeated runs produce one result.
func TestGenerationIsDeterministic(t *testing.T) {
	first, err := reference.New()
	if err != nil {
		t.Fatal(err)
	}
	second, err := reference.New()
	if err != nil {
		t.Fatal(err)
	}
	firstDoc, _ := json.Marshal(first.OpenAPI())
	secondDoc, _ := json.Marshal(second.OpenAPI())
	if string(firstDoc) != string(secondDoc) {
		t.Fatalf("the OpenAPI generation is not deterministic")
	}
	firstClient, err := clientgen.Generate(first.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	secondClient, err := clientgen.Generate(second.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	if firstClient != secondClient {
		t.Fatalf("the client generation is not deterministic")
	}
}

// TestPLUG005GeneratedClientPluginOperation covers PLUG-005.
func TestPLUG005GeneratedClientPluginOperation(t *testing.T) {
	s := testsupport.NewSQLite(t)
	auth, err := authall.New(
		authall.WithStore(s),
		authall.WithEmailPassword(),
		authall.WithPlugins(&testPlugin{}),
	)
	if err != nil {
		t.Fatal(err)
	}
	source, err := clientgen.Generate(auth.OpenAPI())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.Contains(source, "readonly testPlugin = {") {
		t.Fatalf("the generated client misses the plugin namespace:\n%s", source)
	}
	if !strings.Contains(source, "ping: (body: TestPluginPingBody)") {
		t.Fatalf("the generated client misses the plugin operation:\n%s", source)
	}
	if !strings.Contains(source, "/api/auth/test-plugin/ping") {
		t.Fatalf("the generated client misses the plugin path")
	}
	if !strings.Contains(source, "export interface TestPluginPingBody") {
		t.Fatalf("the generated client misses the plugin request type")
	}
}

// TestDuplicateClientBindingIsRejected checks the generator guard.
func TestDuplicateClientBindingIsRejected(t *testing.T) {
	doc := openapi.New("Auth-All", "1.0.0")
	binding := &openapi.ClientBinding{Namespace: "signIn", Method: "email"}
	doc.AddOperation("POST", "/a", &openapi.Operation{OperationID: "a", Client: binding})
	doc.AddOperation("POST", "/b", &openapi.Operation{OperationID: "b", Client: binding})
	if _, err := clientgen.Generate(doc); err == nil {
		t.Fatalf("a duplicate client binding was accepted")
	}
}
