package authall_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugin"
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

// TestTheKeyOptionsAndGuardsHold covers the option paths and the revoke guard.
func TestTheKeyOptionsAndGuardsHold(t *testing.T) {
	h, _ := keysHarness(t,
		apikeys.MaxTTL(24*time.Hour),
		apikeys.AllowNoExpiry(),
		apikeys.TouchInterval(time.Millisecond),
		apikeys.AdminRole("admin"),
	)
	const owner = "options@example.com"
	h.SignUp(owner, testPassword)

	// AllowNoExpiry accepts a key with no expiry beside a maximum.
	resp, plaintext, key := createKey(t, h, map[string]any{"name": "endless"})
	if resp.Status != http.StatusCreated || plaintext == "" {
		t.Fatalf("the key returned %d: %s", resp.Status, string(resp.Body))
	}
	// An expiry in the past fails.
	past := time.Now().UTC().Add(-time.Hour)
	if got, _, _ := createKey(t, h, map[string]any{"name": "past", "expiresAt": past}); got.Status != http.StatusBadRequest {
		t.Fatalf("the past expiry returned %d", got.Status)
	}
	// An unknown role fails.
	if got, _, _ := createKey(t, h, map[string]any{"name": "ghost", "role": "ghost"}); got.Status != http.StatusBadRequest {
		t.Fatalf("the unknown role returned %d", got.Status)
	}

	// Another user never revokes the key, and never lists the keys.
	h.ClearCookies()
	h.SignUp("stranger@example.com", testPassword)
	if got := h.Do(http.MethodPost, "/api-keys/"+key.ID+"/revoke", nil); got.Status != http.StatusNotFound {
		t.Fatalf("the stranger revoked the key: %d", got.Status)
	}
	if got := h.Do(http.MethodGet, "/api-keys?userId="+key.UserID, nil); got.Status != http.StatusForbidden {
		t.Fatalf("the stranger listed the keys: %d", got.Status)
	}
	if got := h.Do(http.MethodPost, "/api-keys/11111111-1111-1111-1111-111111111111/revoke",
		nil); got.Status != http.StatusNotFound {
		t.Fatalf("an unknown key returned %d", got.Status)
	}

	// The owner revokes the key one time.
	h.ClearCookies()
	h.SignIn(owner, testPassword)
	if got := h.Do(http.MethodPost, "/api-keys/"+key.ID+"/revoke", nil); got.Status != http.StatusOK {
		t.Fatalf("the revoke returned %d", got.Status)
	}
	if got := h.Do(http.MethodPost, "/api-keys/"+key.ID+"/revoke", nil); got.Status != http.StatusNotFound {
		t.Fatalf("the second revoke returned %d", got.Status)
	}
}

// TestTheKeyPluginNeedsTheRolesPlugin covers the registration guard.
func TestTheKeyPluginNeedsTheRolesPlugin(t *testing.T) {
	s := testsupport.NewSQLite(t)
	if _, err := authall.New(authall.WithStore(s), authall.WithPlugins(apikeys.New())); err == nil {
		t.Fatal("the API keys plugin registered with no roles plugin")
	}
}

// TestATouchedKeyWritesTheLastUseTimeAgain covers the touch interval.
func TestATouchedKeyWritesTheLastUseTimeAgain(t *testing.T) {
	h, _ := keysHarness(t, apikeys.TouchInterval(time.Nanosecond))
	h.SignUp("touched@example.com", testPassword)
	_, plaintext, key := createKey(t, h, map[string]any{"name": "touch"})
	h.ClearCookies()
	keys := h.Store.(store.APIKeyStore)
	ctx := context.Background()

	if got := h.DoURL(http.MethodGet, h.BaseURL+"/host/any", nil, withKey(plaintext)); got.Status != http.StatusNoContent {
		t.Fatalf("the first request returned %d", got.Status)
	}
	first, err := keys.APIKeyByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if got := h.DoURL(http.MethodGet, h.BaseURL+"/host/any", nil, withKey(plaintext)); got.Status != http.StatusNoContent {
		t.Fatalf("the second request returned %d", got.Status)
	}
	second, err := keys.APIKeyByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !second.LastUsedAt.After(*first.LastUsedAt) {
		t.Fatal("the second request wrote no new last use time")
	}
}

// TestTheBeforeHookRefusesAKey checks that a host refuses a key for one owner.
// The refusal holds on the HTTP route and on the Go method, and no row
// remains.
func TestTheBeforeHookRefusesAKey(t *testing.T) {
	h, k := keysHarness(t)
	h.Auth.Hooks().OnBeforeAPIKeyCreate(func(_ context.Context, ev *hook.APIKeyEvent) error {
		if ev.Tx == nil || ev.Key == nil || ev.Key.KeyHash == "" {
			t.Errorf("the hook received an incomplete event: %+v", ev)
		}
		if strings.HasPrefix(ev.User.Email, "human") {
			return apierr.ErrForbidden.WithMessage("Only automation accounts hold keys.")
		}
		return nil
	})

	h.SignUp("human@example.com", testPassword)
	resp, _, _ := createKey(t, h, map[string]any{"name": "refused"})
	if resp.Status != http.StatusForbidden {
		t.Fatalf("the refused key returned %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "FORBIDDEN" {
		t.Fatalf("unexpected code %q", code)
	}
	human := h.GetSession().User
	owner, err := h.Store.Users().GetByID(context.Background(), human.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.Create(context.Background(), owner, apikeys.CreateInput{UserID: owner.ID, Name: "go"}); !errors.Is(err, apierr.ErrForbidden) {
		t.Fatalf("the Go method returned %v", err)
	}
	keys, err := k.List(context.Background(), owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("a refused create left %d keys", len(keys))
	}

	h.ClearCookies()
	h.SignUp("bot@example.com", testPassword)
	if resp, plaintext, _ := createKey(t, h, map[string]any{"name": "allowed"}); resp.Status != http.StatusCreated || plaintext == "" {
		t.Fatalf("the allowed key returned %d: %s", resp.Status, string(resp.Body))
	}
}

// scopeHarness returns a key harness and one route for each named scope.
func scopeHarness(t *testing.T, routes []string, opts ...apikeys.Option) (*testsupport.Harness, *apikeys.Plugin) {
	t.Helper()
	h, k := keysHarness(t, opts...)
	for _, scope := range routes {
		h.Handle("/host/scope/"+scope, k.RequireScope(scope)(http.HandlerFunc(
			func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	}
	return h, k
}

// scopesOfResponse decodes the scopes of one key response.
func scopesOfResponse(t *testing.T, resp *testsupport.Response) []string {
	t.Helper()
	var out struct {
		Key struct {
			Scopes []string `json:"scopes"`
		} `json:"key"`
	}
	resp.Decode(t, &out)
	return out.Key.Scopes
}

// execKeySQL runs one statement on the store of the harness.
func execKeySQL(t *testing.T, s store.Store, statement string) {
	t.Helper()
	handle, ok := s.(interface{ DB() *sql.DB })
	if !ok {
		t.Fatal("the store exposes no database handle")
	}
	if _, err := handle.DB().ExecContext(context.Background(), statement); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
}

// TestSCNKEY012CreateStoresAndReturnsTheScopes covers acceptance test 1 of
// issue 18.
func TestSCNKEY012CreateStoresAndReturnsTheScopes(t *testing.T) {
	h, k := scopeHarness(t, nil, apikeys.Scopes("read", "propose"))
	var hooked string
	h.Auth.Hooks().OnBeforeAPIKeyCreate(func(_ context.Context, ev *hook.APIKeyEvent) error {
		hooked = ev.Key.Scopes
		if !strings.Contains(strings.Join(ev.Key.ScopeList(), ","), "propose,read") {
			t.Errorf("the hook list is %v", ev.Key.ScopeList())
		}
		return nil
	})
	h.SignUp("owner@example.com", testPassword)

	resp := h.Do(http.MethodPost, "/api-keys", map[string]any{
		"name": "agent", "scopes": []string{"read", "propose", "read"},
	})
	if resp.Status != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if got := strings.Join(scopesOfResponse(t, resp), " "); got != "propose read" {
		t.Fatalf("the create returned %q", got)
	}
	if hooked != "propose read" {
		t.Fatalf("the hook saw %q", hooked)
	}

	list := h.Do(http.MethodGet, "/api-keys", nil)
	var listed struct {
		Keys []struct {
			Scopes []string `json:"scopes"`
		} `json:"keys"`
	}
	list.Decode(t, &listed)
	if len(listed.Keys) != 1 || strings.Join(listed.Keys[0].Scopes, " ") != "propose read" {
		t.Fatalf("the list returned %s", string(list.Body))
	}

	owner, err := h.Store.Users().GetByNormalizedEmail(context.Background(), "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := k.List(context.Background(), owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if keys[0].Scopes != "propose read" {
		t.Fatalf("the store returned %q", keys[0].Scopes)
	}
}

// TestSCNKEY013AnUnknownScopeFails covers acceptance test 2 of issue 18.
func TestSCNKEY013AnUnknownScopeFails(t *testing.T) {
	h, _ := scopeHarness(t, nil, apikeys.Scopes("read"))
	h.SignUp("owner@example.com", testPassword)
	resp := h.Do(http.MethodPost, "/api-keys", map[string]any{"name": "a", "scopes": []string{"read", "admin"}})
	if resp.Status != http.StatusBadRequest || resp.ErrorCode(t) != "SCOPE_UNKNOWN" {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
}

// TestSCNKEY014AKeyWithNoScopesTakesTheDefaults covers acceptance test 3 of
// issue 18.
func TestSCNKEY014AKeyWithNoScopesTakesTheDefaults(t *testing.T) {
	cases := []struct {
		name string
		opts []apikeys.Option
		want string
	}{
		{"the named default", []apikeys.Option{apikeys.Scopes("read", "propose"), apikeys.DefaultScopes("read")}, "read"},
		{"every declared scope", []apikeys.Option{apikeys.Scopes("read", "propose")}, "propose read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := scopeHarness(t, nil, tc.opts...)
			h.SignUp("owner@example.com", testPassword)
			resp := h.Do(http.MethodPost, "/api-keys", map[string]any{"name": "a"})
			if resp.Status != http.StatusCreated {
				t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
			}
			if got := strings.Join(scopesOfResponse(t, resp), " "); got != tc.want {
				t.Fatalf("got %q", got)
			}
		})
	}
}

// TestSCNKEY015RequireScopeLimitsAKeyAndNoSession covers acceptance test 4 of
// issue 18.
func TestSCNKEY015RequireScopeLimitsAKeyAndNoSession(t *testing.T) {
	h, _ := scopeHarness(t, []string{"read", "propose"}, apikeys.Scopes("read", "propose"))
	h.Handle("/host/scope/principal", h.Auth.RequireAuth(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			if !authall.PrincipalFrom(req.Context()).HasScope("read") ||
				authall.PrincipalFrom(req.Context()).HasScope("propose") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})))
	h.SignUp("owner@example.com", testPassword)
	_, plaintext, _ := createKey(t, h, map[string]any{"name": "a", "scopes": []string{"read"}})

	for _, path := range []string{"/host/scope/read", "/host/scope/propose"} {
		if resp := h.DoURL(http.MethodGet, h.Server.URL+path, nil); resp.Status != http.StatusNoContent {
			t.Fatalf("the session got %d on %s", resp.Status, path)
		}
	}

	h.ClearCookies()
	if resp := h.DoURL(http.MethodGet, h.Server.URL+"/host/scope/read", nil, withKey(plaintext)); resp.Status != http.StatusNoContent {
		t.Fatalf("the key got %d: %s", resp.Status, string(resp.Body))
	}
	resp := h.DoURL(http.MethodGet, h.Server.URL+"/host/scope/propose", nil, withKey(plaintext))
	if resp.Status != http.StatusForbidden || resp.ErrorCode(t) != "SCOPE_MISSING" {
		t.Fatalf("the key got %d: %s", resp.Status, string(resp.Body))
	}
	if resp := h.DoURL(http.MethodGet, h.Server.URL+"/host/scope/principal", nil, withKey(plaintext)); resp.Status != http.StatusNoContent {
		t.Fatalf("Principal.HasScope gave %d", resp.Status)
	}
	if resp := h.DoURL(http.MethodGet, h.Server.URL+"/host/scope/read", nil); resp.Status != http.StatusUnauthorized {
		t.Fatalf("the anonymous request got %d", resp.Status)
	}
}

// TestSCNKEY016AKeyFromBeforeTheColumnTakesTheDefaults covers acceptance test 5
// of issue 18.
func TestSCNKEY016AKeyFromBeforeTheColumnTakesTheDefaults(t *testing.T) {
	h, _ := scopeHarness(t, []string{"read", "propose"},
		apikeys.Scopes("read", "propose"), apikeys.DefaultScopes("read"))
	h.SignUp("owner@example.com", testPassword)
	_, plaintext, _ := createKey(t, h, map[string]any{"name": "old", "scopes": []string{"propose"}})
	execKeySQL(t, h.Store, "UPDATE "+h.Auth.Schema().Names().APIKeys+" SET scopes = NULL")

	h.ClearCookies()
	if resp := h.DoURL(http.MethodGet, h.Server.URL+"/host/scope/read", nil, withKey(plaintext)); resp.Status != http.StatusNoContent {
		t.Fatalf("the old key got %d on the default scope", resp.Status)
	}
	if resp := h.DoURL(http.MethodGet, h.Server.URL+"/host/scope/propose", nil, withKey(plaintext)); resp.Status != http.StatusForbidden {
		t.Fatalf("the old key got %d outside the default scope", resp.Status)
	}
}

// TestSCNKEY017WithNoDeclaredScopeEveryCheckPasses covers acceptance test 6 of
// issue 18.
func TestSCNKEY017WithNoDeclaredScopeEveryCheckPasses(t *testing.T) {
	h, _ := scopeHarness(t, []string{"anything"})
	h.SignUp("owner@example.com", testPassword)
	resp := h.Do(http.MethodPost, "/api-keys", map[string]any{"name": "a", "scopes": []string{"read"}})
	if resp.Status != http.StatusBadRequest || resp.ErrorCode(t) != "SCOPE_UNKNOWN" {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	created, plaintext, _ := createKey(t, h, map[string]any{"name": "a"})
	if got := scopesOfResponse(t, created); got == nil || len(got) != 0 {
		t.Fatalf("the create returned %v", got)
	}
	// A row from an earlier configuration still passes.
	execKeySQL(t, h.Store, "UPDATE "+h.Auth.Schema().Names().APIKeys+" SET scopes = 'read'")
	h.ClearCookies()
	if resp := h.DoURL(http.MethodGet, h.Server.URL+"/host/scope/anything", nil, withKey(plaintext)); resp.Status != http.StatusNoContent {
		t.Fatalf("the key got %d", resp.Status)
	}
}

// TestSCNKEY018TheScopeColumnArrivesOnADatabaseWithKeys covers acceptance test 7
// of issue 18 on both store backends.
func TestSCNKEY018TheScopeColumnArrivesOnADatabaseWithKeys(t *testing.T) {
	backends := map[string]func(*testing.T) store.Store{
		"sqlite":   testsupport.NewSQLite,
		"postgres": testsupport.NewPostgres,
	}
	for name, open := range backends {
		t.Run(name, func(t *testing.T) {
			r := roles.New(roles.Hierarchy(testHierarchy...), roles.Default("viewer"))
			k := apikeys.New(apikeys.Scopes("read", "propose"), apikeys.DefaultScopes("read"))
			h := testsupport.NewHarnessWithStore(t, open(t), authall.WithEmailPassword(), authall.WithPlugins(r, k))
			h.Handle("/host/scope/read", k.RequireScope("read")(http.HandlerFunc(
				func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusNoContent) })))
			if _, err := h.Auth.Migrate(context.Background()); err != nil {
				t.Fatal(err)
			}
			h.SignUp("owner@example.com", testPassword)
			_, plaintext, _ := createKey(t, h, map[string]any{"name": "old"})

			// The database returns to the shape before the unit, with one key.
			names := h.Auth.Schema().Names()
			execKeySQL(t, h.Store, "ALTER TABLE "+names.APIKeys+" DROP COLUMN scopes")
			execKeySQL(t, h.Store, "DELETE FROM "+names.Migrations+" WHERE id LIKE '%scopes%'")
			if _, err := h.Auth.Migrate(context.Background()); err != nil {
				t.Fatalf("the unit failed on a database with keys: %v", err)
			}

			h.ClearCookies()
			if resp := h.DoURL(http.MethodGet, h.Server.URL+"/host/scope/read", nil, withKey(plaintext)); resp.Status != http.StatusNoContent {
				t.Fatalf("the old key got %d: %s", resp.Status, string(resp.Body))
			}
			h.SignIn("owner@example.com", testPassword)
			resp := h.Do(http.MethodPost, "/api-keys", map[string]any{"name": "new", "scopes": []string{"read", "propose"}})
			if resp.Status != http.StatusCreated {
				t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
			}
			owner, err := h.Store.Users().GetByNormalizedEmail(context.Background(), "owner@example.com")
			if err != nil {
				t.Fatal(err)
			}
			keys, err := k.List(context.Background(), owner.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(keys) != 2 || keys[0].Scopes != "propose read" || keys[1].Scopes != "read" {
				t.Fatalf("the column did not round-trip: %+v", keys)
			}
		})
	}
}

// TestTheScopeConfigurationIsChecked covers the construction guards of the
// scope options.
func TestTheScopeConfigurationIsChecked(t *testing.T) {
	cases := map[string][]apikeys.Option{
		"a bad name":             {apikeys.Scopes("Read")},
		"an undeclared default":  {apikeys.Scopes("read"), apikeys.DefaultScopes("propose")},
		"a default and no scope": {apikeys.DefaultScopes("read")},
		"an empty default":       {apikeys.Scopes("read"), apikeys.DefaultScopes()},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			r := roles.New(roles.Hierarchy(testHierarchy...), roles.Default("viewer"))
			if _, err := authall.New(authall.WithStore(testsupport.NewSQLite(t)),
				authall.WithBaseURL("https://app.example.com"),
				authall.WithPlugins(r, apikeys.New(opts...))); err == nil {
				t.Fatal("the configuration was accepted")
			}
		})
	}

	_, k := scopeHarness(t, nil, apikeys.Scopes("read"))
	defer func() {
		if recover() == nil {
			t.Fatal("an undeclared scope was accepted")
		}
	}()
	k.RequireScope("reed")
}

// TestAnOtherCredentialFailsTheScopeCheck pins the default deny of HasScope.
func TestAnOtherCredentialFailsTheScopeCheck(t *testing.T) {
	if apikeys.HasScope(nil, "read") {
		t.Fatal("no principal passed")
	}
	if apikeys.HasScope(&plugin.Principal{Method: "oauthprovider"}, "read") {
		t.Fatal("an OAuth token passed")
	}
	if !apikeys.HasScope(&plugin.Principal{Method: "session"}, "read") {
		t.Fatal("a session failed")
	}
	if !apikeys.HasScope(&plugin.Principal{Method: "api_key", APIKey: &store.APIKey{Scopes: "read"}}, "read") {
		t.Fatal("a key with the scope failed")
	}
	var none *authall.Principal
	if none.HasScope("read") || (&authall.Principal{Method: "oauthprovider"}).HasScope("read") {
		t.Fatal("a principal with no scope source passed")
	}
}
