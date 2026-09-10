package authall_test

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/admin"
	"github.com/alternayte/auth-all/plugins/apikeys"
	"github.com/alternayte/auth-all/plugins/roles"
	"github.com/alternayte/auth-all/store"
)

// keyEntry is the public shape of one key in a response.
type keyEntry struct {
	ID         string     `json:"id"`
	UserID     string     `json:"userId"`
	Name       string     `json:"name"`
	Start      string     `json:"start"`
	Role       string     `json:"role"`
	ExpiresAt  *time.Time `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	RevokedAt  *time.Time `json:"revokedAt"`
}

// keysHarness returns a harness with the roles plugin, the admin plugin, the
// API keys plugin, and one route for each role.
func keysHarness(t *testing.T, opts ...apikeys.Option) (*testsupport.Harness, *apikeys.Plugin) {
	t.Helper()
	r := roles.New(roles.Hierarchy(testHierarchy...), roles.Default("viewer"))
	k := apikeys.New(opts...)
	h := emailPasswordHarness(t, authall.WithPlugins(r, admin.New(), k))
	for _, name := range testHierarchy {
		min := name
		h.Handle("/host/"+min, r.Require(min, http.HandlerFunc(
			func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	}
	h.Handle("/host/any", h.Auth.RequireAuth(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	return h, k
}

// createKey creates one key for the signed-in user and returns the plaintext.
func createKey(t *testing.T, h *testsupport.Harness, body map[string]any) (*testsupport.Response, string, keyEntry) {
	t.Helper()
	resp := h.Do(http.MethodPost, "/api-keys", body)
	if resp.Status != http.StatusCreated {
		return resp, "", keyEntry{}
	}
	var out struct {
		Key       keyEntry `json:"key"`
		Plaintext string   `json:"plaintext"`
	}
	resp.Decode(t, &out)
	return resp, out.Plaintext, out.Key
}

// withKey sends the request with one API key.
func withKey(key string) testsupport.RequestOption {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+key) }
}

// TestSCNKEY001EveryKeyHasThePrefixAndIsUnique proves REQ-KEY-001 and
// REQ-KEY-002.
func TestSCNKEY001EveryKeyHasThePrefixAndIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 10000 {
		value, err := apikeys.NewPlaintextKey("ak_")
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if !strings.HasPrefix(value, "ak_") {
			t.Fatalf("the key %q has no prefix", value)
		}
		random := strings.TrimPrefix(value, "ak_")
		// 32 bytes give 43 characters of unpadded base64url.
		if len(random) != 43 {
			t.Fatalf("the random part has %d characters", len(random))
		}
		if seen[value] {
			t.Fatalf("the key %q repeats", value)
		}
		seen[value] = true
	}

	// The plugin refuses an unusable prefix.
	s := testsupport.NewSQLite(t)
	for _, prefix := range []string{"A_", "1ak", "a", "ak-", "way_too_long_prefix_"} {
		_, err := authall.New(authall.WithStore(s),
			authall.WithPlugins(roles.New(roles.Hierarchy("viewer", "admin")), apikeys.New(apikeys.Prefix(prefix))))
		if err == nil {
			t.Fatalf("the prefix %q was accepted", prefix)
		}
	}
}

// TestSCNKEY002TheCreateResponseCarriesThePlaintextOneTime proves REQ-KEY-003
// and REQ-KEY-011.
func TestSCNKEY002TheCreateResponseCarriesThePlaintextOneTime(t *testing.T) {
	h, _ := keysHarness(t)
	h.SignUp("owner@example.com", testPassword)
	_, plaintext, key := createKey(t, h, map[string]any{"name": "deploy"})
	if plaintext == "" || !strings.HasPrefix(plaintext, "ak_") {
		t.Fatalf("the plaintext is %q", plaintext)
	}
	if key.Start == "" || len(key.Start) != len("ak_")+4 {
		t.Fatalf("the start is %q", key.Start)
	}

	resp := h.Do(http.MethodGet, "/api-keys", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("list: %d %s", resp.Status, string(resp.Body))
	}
	if strings.Contains(string(resp.Body), plaintext) {
		t.Fatal("the list carries the plaintext key")
	}
	var list struct {
		Keys []keyEntry `json:"keys"`
	}
	resp.Decode(t, &list)
	if len(list.Keys) != 1 || list.Keys[0].ID != key.ID {
		t.Fatalf("the list is %+v", list.Keys)
	}
}

// TestSCNKEY003TheStoredRowHoldsOnlyTheDigest proves REQ-KEY-004.
func TestSCNKEY003TheStoredRowHoldsOnlyTheDigest(t *testing.T) {
	h, _ := keysHarness(t)
	h.SignUp("digest@example.com", testPassword)
	_, plaintext, key := createKey(t, h, map[string]any{"name": "digest"})

	keys, ok := h.Store.(store.APIKeyStore)
	if !ok {
		t.Fatal("the store holds no API key")
	}
	row, err := keys.APIKeyByID(context.Background(), key.ID)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if len(row.KeyHash) != 64 {
		t.Fatalf("the digest has %d characters", len(row.KeyHash))
	}
	if strings.Contains(row.KeyHash, plaintext) || row.KeyHash == plaintext {
		t.Fatal("the row holds the plaintext key")
	}
	if _, _, err := keys.APIKeyByHash(context.Background(), row.KeyHash); err != nil {
		t.Fatalf("the digest does not find the key: %v", err)
	}
}

// TestSCNKEY004TheCreateGuardsRefuseAnInvalidKey proves REQ-KEY-005 to
// REQ-KEY-007.
func TestSCNKEY004TheCreateGuardsRefuseAnInvalidKey(t *testing.T) {
	h, _ := keysHarness(t, apikeys.MaxTTL(24*time.Hour))
	h.SignUp("guards@example.com", testPassword)

	resp, _, _ := createKey(t, h, map[string]any{"name": "  "})
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("the empty name returned %d", resp.Status)
	}
	if code := errorCode(t, resp); code != string(apierr.CodeInvalidRequest) {
		t.Fatalf("the code is %q", code)
	}

	far := time.Now().UTC().Add(48 * time.Hour)
	resp, _, _ = createKey(t, h, map[string]any{"name": "long", "expiresAt": far})
	if code := errorCode(t, resp); code != string(apierr.CodeAPIKeyExpiryTooLong) {
		t.Fatalf("the long expiry gave %q", code)
	}

	resp, _, _ = createKey(t, h, map[string]any{"name": "none"})
	if code := errorCode(t, resp); code != string(apierr.CodeAPIKeyExpiryRequired) {
		t.Fatalf("the absent expiry gave %q", code)
	}

	near := time.Now().UTC().Add(time.Hour)
	resp, plaintext, _ := createKey(t, h, map[string]any{"name": "good", "expiresAt": near})
	if resp.Status != http.StatusCreated || plaintext == "" {
		t.Fatalf("the valid key returned %d: %s", resp.Status, string(resp.Body))
	}
}

// TestSCNKEY005AKeyNeverOutranksTheOwner proves REQ-KEY-008.
func TestSCNKEY005AKeyNeverOutranksTheOwner(t *testing.T) {
	h, _ := keysHarness(t)
	const address = "operator@example.com"
	h.SignUp(address, testPassword)
	setRole(t, h.Store, address, "operator")
	resp, _, _ := createKey(t, h, map[string]any{"name": "too strong", "role": "admin"})
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if code := errorCode(t, resp); code != string(apierr.CodeRoleNotAllowed) {
		t.Fatalf("the code is %q", code)
	}
	// The role of the owner is allowed.
	resp, _, key := createKey(t, h, map[string]any{"name": "fine", "role": "operator"})
	if resp.Status != http.StatusCreated || key.Role != "operator" {
		t.Fatalf("the valid key returned %d: %s", resp.Status, string(resp.Body))
	}
}

// TestSCNKEY006ADemotedOwnerWeakensTheKey proves REQ-KEY-009 and REQ-CON-001.
func TestSCNKEY006ADemotedOwnerWeakensTheKey(t *testing.T) {
	h, _ := keysHarness(t)
	const address = "editor-key@example.com"
	h.SignUp(address, testPassword)
	setRole(t, h.Store, address, "editor")
	_, plaintext, key := createKey(t, h, map[string]any{"name": "editor key", "role": "editor"})
	if key.Role != "editor" {
		t.Fatalf("the key role is %q", key.Role)
	}
	h.ClearCookies()
	if got := h.DoURL(http.MethodGet, h.BaseURL+"/host/editor", nil, withKey(plaintext)); got.Status != http.StatusNoContent {
		t.Fatalf("the editor key returned %d: %s", got.Status, string(got.Body))
	}

	// The owner drops to viewer, so the key drops with it.
	setRole(t, h.Store, address, "viewer")
	got := h.DoURL(http.MethodGet, h.BaseURL+"/host/editor", nil, withKey(plaintext))
	if got.Status != http.StatusForbidden {
		t.Fatalf("the demoted key returned %d", got.Status)
	}
	if code := errorCode(t, got); code != string(apierr.CodeInsufficientRole) {
		t.Fatalf("the code is %q", code)
	}
}

// TestSCNKEY007TheTouchWritesOnceForEachInterval proves REQ-KEY-010.
func TestSCNKEY007TheTouchWritesOnceForEachInterval(t *testing.T) {
	h, _ := keysHarness(t)
	h.SignUp("touch@example.com", testPassword)
	_, plaintext, key := createKey(t, h, map[string]any{"name": "touch"})
	h.ClearCookies()

	keys := h.Store.(store.APIKeyStore)
	ctx := context.Background()
	if got := h.DoURL(http.MethodGet, h.BaseURL+"/host/any", nil, withKey(plaintext)); got.Status != http.StatusNoContent {
		t.Fatalf("the key request returned %d", got.Status)
	}
	first, err := keys.APIKeyByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if first.LastUsedAt == nil {
		t.Fatal("the first request wrote no last use time")
	}
	if got := h.DoURL(http.MethodGet, h.BaseURL+"/host/any", nil, withKey(plaintext)); got.Status != http.StatusNoContent {
		t.Fatalf("the second request returned %d", got.Status)
	}
	second, err := keys.APIKeyByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !second.LastUsedAt.Equal(*first.LastUsedAt) {
		t.Fatal("the second request inside the interval wrote the last use time again")
	}
}

// TestSCNKEY008AnAdminRevokesAnyKey proves REQ-KEY-012 and REQ-KEY-013.
func TestSCNKEY008AnAdminRevokesAnyKey(t *testing.T) {
	h, _ := keysHarness(t)
	const owner = "key-owner@example.com"
	h.SignUp(owner, testPassword)
	_, plaintext, key := createKey(t, h, map[string]any{"name": "owned"})
	ownerID := userID(t, h, owner)

	// An administrator signs in and reads the keys of the owner.
	h.ClearCookies()
	h.SignUp("key-admin@example.com", testPassword)
	setRole(t, h.Store, "key-admin@example.com", "admin")
	resp := h.Do(http.MethodGet, "/api-keys?userId="+ownerID, nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("the admin list returned %d: %s", resp.Status, string(resp.Body))
	}
	var list struct {
		Keys []keyEntry `json:"keys"`
	}
	resp.Decode(t, &list)
	if len(list.Keys) != 1 {
		t.Fatalf("the admin sees %d keys", len(list.Keys))
	}
	if resp := h.Do(http.MethodPost, "/api-keys/"+key.ID+"/revoke", nil); resp.Status != http.StatusOK {
		t.Fatalf("the revoke returned %d: %s", resp.Status, string(resp.Body))
	}

	h.ClearCookies()
	got := h.DoURL(http.MethodGet, h.BaseURL+"/host/any", nil, withKey(plaintext))
	if got.Status != http.StatusUnauthorized {
		t.Fatalf("the revoked key returned %d", got.Status)
	}
}

// TestSCNKEY009EveryFailedKeyLooksEqual proves REQ-KEY-013 and SI-08.
func TestSCNKEY009EveryFailedKeyLooksEqual(t *testing.T) {
	h, _ := keysHarness(t)
	const owner = "many-keys@example.com"
	h.SignUp(owner, testPassword)
	_, revoked, revokedKey := createKey(t, h, map[string]any{"name": "revoked"})
	_, expired, expiredKey := createKey(t, h, map[string]any{
		"name": "expired", "expiresAt": time.Now().UTC().Add(time.Second),
	})
	_, disabled, _ := createKey(t, h, map[string]any{"name": "disabled owner"})
	if resp := h.Do(http.MethodPost, "/api-keys/"+revokedKey.ID+"/revoke", nil); resp.Status != http.StatusOK {
		t.Fatalf("revoke: %d", resp.Status)
	}

	// The expiry passes, so the key ends.
	setExpiry(t, h, expiredKey.ID, time.Now().UTC().Add(-time.Minute))

	// The owner of the third key is disabled.
	disableUser(t, h, userID(t, h, owner))

	h.ClearCookies()
	bodies := map[string]string{}
	for name, value := range map[string]string{
		"revoked": revoked, "expired": expired, "disabled": disabled, "unknown": "ak_" + strings.Repeat("A", 43),
	} {
		got := h.DoURL(http.MethodGet, h.BaseURL+"/host/any", nil, withKey(value))
		if got.Status != http.StatusUnauthorized {
			t.Fatalf("the %s key returned %d: %s", name, got.Status, string(got.Body))
		}
		bodies[name] = string(got.Body)
	}
	first := bodies["revoked"]
	for name, body := range bodies {
		if body != first {
			t.Fatalf("the %s key answers %q, the revoked key answers %q", name, body, first)
		}
	}
}

// setExpiry writes the expiry of one key directly in the database.
func setExpiry(t *testing.T, h *testsupport.Harness, id string, at time.Time) {
	t.Helper()
	handle, ok := h.Store.(interface{ DB() *sql.DB })
	if !ok {
		t.Fatal("the store exposes no database handle")
	}
	if _, err := handle.DB().ExecContext(context.Background(),
		"UPDATE "+h.Auth.Schema().Names().APIKeys+" SET expires_at = ? WHERE id = ?",
		at.Format("2006-01-02T15:04:05.000000000"), id); err != nil {
		t.Fatalf("set expiry: %v", err)
	}
}

// disableUser sets the disabled time of one user.
func disableUser(t *testing.T, h *testsupport.Harness, id string) {
	t.Helper()
	ctx := context.Background()
	user, err := h.Store.Users().GetByID(ctx, id)
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	now := time.Now().UTC()
	user.DisabledAt = &now
	if err := h.Store.Users().Update(ctx, user); err != nil {
		t.Fatalf("update user: %v", err)
	}
}

// TestSCNKEY010AKeyReachesAHostRoute proves REQ-KEY-014.
func TestSCNKEY010AKeyReachesAHostRoute(t *testing.T) {
	h, _ := keysHarness(t)
	const address = "host-route@example.com"
	h.SignUp(address, testPassword)
	setRole(t, h.Store, address, "operator")
	_, plaintext, _ := createKey(t, h, map[string]any{"name": "host"})
	h.ClearCookies()

	if got := h.DoURL(http.MethodGet, h.BaseURL+"/host/any", nil, withKey(plaintext)); got.Status != http.StatusNoContent {
		t.Fatalf("RequireAuth returned %d: %s", got.Status, string(got.Body))
	}
	if got := h.DoURL(http.MethodGet, h.BaseURL+"/host/operator", nil, withKey(plaintext)); got.Status != http.StatusNoContent {
		t.Fatalf("the role route returned %d: %s", got.Status, string(got.Body))
	}
	if got := h.DoURL(http.MethodGet, h.BaseURL+"/host/admin", nil, withKey(plaintext)); got.Status != http.StatusForbidden {
		t.Fatalf("the admin route returned %d", got.Status)
	}
}

// TestSCNKEY011AKeyManagesNoKeyAndNoPassword proves REQ-KEY-015 and
// REQ-KEY-016.
func TestSCNKEY011AKeyManagesNoKeyAndNoPassword(t *testing.T) {
	h, _ := keysHarness(t)
	h.SignUp("no-manage@example.com", testPassword)
	_, plaintext, _ := createKey(t, h, map[string]any{"name": "limited"})
	h.ClearCookies()

	create := h.Do(http.MethodPost, "/api-keys", map[string]any{"name": "second"}, withKey(plaintext))
	if create.Status != http.StatusForbidden {
		t.Fatalf("the key created a key: %d %s", create.Status, string(create.Body))
	}
	change := h.Do(http.MethodPost, "/password/change", map[string]any{
		"currentPassword": testPassword, "newPassword": "another-good-password",
	}, withKey(plaintext))
	if change.Status != http.StatusForbidden {
		t.Fatalf("the key changed a password: %d %s", change.Status, string(change.Body))
	}
	sessions := h.Do(http.MethodGet, "/sessions", nil, withKey(plaintext))
	if sessions.Status != http.StatusForbidden {
		t.Fatalf("the key read the sessions: %d", sessions.Status)
	}
}
