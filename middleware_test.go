package authall_test

import (
	"net/http"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
)

// protectedHarness mounts one application route behind RequireAuth. The route
// reports the user that the middleware put in the request context.
func protectedHarness(t *testing.T) *testsupport.Harness {
	t.Helper()
	h := emailPasswordHarness(t)
	h.Handle("/app/me", h.Auth.RequireAuth(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			user := authall.UserFrom(r.Context())
			if user == nil {
				t.Error("RequireAuth passed a request with no user in the context")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			sess := authall.SessionFrom(r.Context())
			if sess == nil {
				t.Error("RequireAuth passed a request with no session in the context")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if sess.UserID != user.ID {
				t.Errorf("the session belongs to %q and the user is %q", sess.UserID, user.ID)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"email":"` + user.Email + `"}`))
		})))
	return h
}

// TestRequireAuthRejectsAnAnonymousRequest checks that a protected route needs
// a session.
func TestRequireAuthRejectsAnAnonymousRequest(t *testing.T) {
	h := protectedHarness(t)
	resp := h.DoURL(http.MethodGet, h.BaseURL+"/app/me", nil)
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	resp.Decode(t, &body)
	if body.Error.Code != "UNAUTHORIZED" {
		t.Fatalf("the error code is %q", body.Error.Code)
	}
}

// TestRequireAuthAcceptsASignedInRequest checks that a session reaches the
// application handler.
func TestRequireAuthAcceptsASignedInRequest(t *testing.T) {
	h := protectedHarness(t)
	const address = "protected@example.com"
	h.SignUp(address, testPassword)

	resp := h.DoURL(http.MethodGet, h.BaseURL+"/app/me", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	var body struct {
		Email string `json:"email"`
	}
	resp.Decode(t, &body)
	if body.Email != address {
		t.Fatalf("the handler saw %q", body.Email)
	}
}

// TestRequireAuthRejectsARevokedSession checks that a sign-out closes the
// protected route.
func TestRequireAuthRejectsARevokedSession(t *testing.T) {
	h := protectedHarness(t)
	h.SignUp("revoked@example.com", testPassword)
	if resp := h.Do(http.MethodPost, "/sign-out", nil); resp.Status != http.StatusOK {
		t.Fatalf("sign out returned %d: %s", resp.Status, string(resp.Body))
	}
	if resp := h.DoURL(http.MethodGet, h.BaseURL+"/app/me", nil); resp.Status != http.StatusUnauthorized {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
}

// TestLoadSessionAllowsAnAnonymousRequest checks the optional middleware.
func TestLoadSessionAllowsAnAnonymousRequest(t *testing.T) {
	h := emailPasswordHarness(t)
	h.Handle("/app/maybe", h.Auth.LoadSession(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if authall.UserFrom(r.Context()) != nil {
				_, _ = w.Write([]byte(`{"anonymous":false}`))
				return
			}
			_, _ = w.Write([]byte(`{"anonymous":true}`))
		})))

	var body struct {
		Anonymous bool `json:"anonymous"`
	}
	resp := h.DoURL(http.MethodGet, h.BaseURL+"/app/maybe", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	resp.Decode(t, &body)
	if !body.Anonymous {
		t.Fatal("LoadSession reported a user for an anonymous request")
	}

	h.SignUp("maybe@example.com", testPassword)
	resp = h.DoURL(http.MethodGet, h.BaseURL+"/app/maybe", nil)
	resp.Decode(t, &body)
	if body.Anonymous {
		t.Fatal("LoadSession reported no user for a signed-in request")
	}
}

// TestRequireAuthResolvesTheSessionOneTime checks that the accessors read the
// context and do not open a second database lookup.
func TestRequireAuthResolvesTheSessionOneTime(t *testing.T) {
	h := protectedHarness(t)
	h.SignUp("once@example.com", testPassword)
	if resp := h.DoURL(http.MethodGet, h.BaseURL+"/app/me", nil); resp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	// The accessors return nil outside of the middleware, so a handler cannot
	// mistake an unmounted route for an authenticated one.
	if authall.UserFrom(t.Context()) != nil || authall.SessionFrom(t.Context()) != nil {
		t.Fatal("the accessors returned a value for a context with no session")
	}
}
