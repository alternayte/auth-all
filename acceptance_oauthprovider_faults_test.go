package authall_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/oauthprovider"
	"github.com/alternayte/auth-all/plugins/roles"
	"github.com/alternayte/auth-all/store"
)

// errFault is the storage failure of the fault store.
var errFault = errors.New("the storage failed")

// faultStore fails one named OAuth provider method and passes every other call
// to the real store. It proves that a storage failure reaches the caller as an
// error and never as a token.
type faultStore struct {
	store.Store
	rows store.OAuthProviderStore
	fail map[string]bool
}

func newFaultStore(t *testing.T, s store.Store, methods ...string) *faultStore {
	t.Helper()
	rows, ok := s.(store.OAuthProviderStore)
	if !ok {
		t.Fatal("the store holds no OAuth provider row")
	}
	fail := map[string]bool{}
	for _, m := range methods {
		fail[m] = true
	}
	return &faultStore{Store: s, rows: rows, fail: fail}
}

func (f *faultStore) failing(name string) error {
	if f.fail[name] {
		return errFault
	}
	return nil
}

func (f *faultStore) CreateOAuthKey(ctx context.Context, k *store.OAuthKey) error {
	if err := f.failing("CreateOAuthKey"); err != nil {
		return err
	}
	return f.rows.CreateOAuthKey(ctx, k)
}

func (f *faultStore) ListOAuthKeys(ctx context.Context) ([]store.OAuthKey, error) {
	if err := f.failing("ListOAuthKeys"); err != nil {
		return nil, err
	}
	return f.rows.ListOAuthKeys(ctx)
}

func (f *faultStore) RetireOAuthKeys(ctx context.Context, id string, at time.Time) error {
	return f.rows.RetireOAuthKeys(ctx, id, at)
}

func (f *faultStore) CreateOAuthClient(ctx context.Context, c *store.OAuthClient) error {
	if err := f.failing("CreateOAuthClient"); err != nil {
		return err
	}
	return f.rows.CreateOAuthClient(ctx, c)
}

func (f *faultStore) OAuthClientByClientID(ctx context.Context, clientID string) (*store.OAuthClient, error) {
	if err := f.failing("OAuthClientByClientID"); err != nil {
		return nil, err
	}
	return f.rows.OAuthClientByClientID(ctx, clientID)
}

func (f *faultStore) UpdateOAuthClient(ctx context.Context, c *store.OAuthClient) error {
	if err := f.failing("UpdateOAuthClient"); err != nil {
		return err
	}
	return f.rows.UpdateOAuthClient(ctx, c)
}

func (f *faultStore) DeleteOAuthClient(ctx context.Context, clientID string) error {
	if err := f.failing("DeleteOAuthClient"); err != nil {
		return err
	}
	return f.rows.DeleteOAuthClient(ctx, clientID)
}

func (f *faultStore) ListOAuthClients(ctx context.Context, owner string) ([]store.OAuthClient, error) {
	if err := f.failing("ListOAuthClients"); err != nil {
		return nil, err
	}
	return f.rows.ListOAuthClients(ctx, owner)
}

func (f *faultStore) CreateOAuthRequest(ctx context.Context, a *store.OAuthAuthorizationRequest) error {
	if err := f.failing("CreateOAuthRequest"); err != nil {
		return err
	}
	return f.rows.CreateOAuthRequest(ctx, a)
}

func (f *faultStore) OAuthRequestByID(ctx context.Context, id string) (*store.OAuthAuthorizationRequest, error) {
	return f.rows.OAuthRequestByID(ctx, id)
}

func (f *faultStore) ConsumeOAuthRequest(ctx context.Context, id string, at time.Time) (*store.OAuthAuthorizationRequest, error) {
	if err := f.failing("ConsumeOAuthRequest"); err != nil {
		return nil, err
	}
	return f.rows.ConsumeOAuthRequest(ctx, id, at)
}

func (f *faultStore) CreateOAuthGrant(ctx context.Context, g *store.OAuthGrant) error {
	if err := f.failing("CreateOAuthGrant"); err != nil {
		return err
	}
	return f.rows.CreateOAuthGrant(ctx, g)
}

func (f *faultStore) OAuthGrantByID(ctx context.Context, id string) (*store.OAuthGrant, error) {
	return f.rows.OAuthGrantByID(ctx, id)
}

func (f *faultStore) RevokeOAuthGrant(ctx context.Context, id string, at time.Time) error {
	return f.rows.RevokeOAuthGrant(ctx, id, at)
}

func (f *faultStore) RevokeOAuthGrantsOfUser(ctx context.Context, userID string, at time.Time) error {
	return f.rows.RevokeOAuthGrantsOfUser(ctx, userID, at)
}

func (f *faultStore) RevokeOAuthGrantsOfConsent(ctx context.Context, userID, clientID string, at time.Time) error {
	if err := f.failing("RevokeOAuthGrantsOfConsent"); err != nil {
		return err
	}
	return f.rows.RevokeOAuthGrantsOfConsent(ctx, userID, clientID, at)
}

func (f *faultStore) CreateOAuthCode(ctx context.Context, c *store.OAuthCode) error {
	if err := f.failing("CreateOAuthCode"); err != nil {
		return err
	}
	return f.rows.CreateOAuthCode(ctx, c)
}

func (f *faultStore) ConsumeOAuthCode(ctx context.Context, hash string, at time.Time) (*store.OAuthCode, error) {
	return f.rows.ConsumeOAuthCode(ctx, hash, at)
}

func (f *faultStore) OAuthCodeByHash(ctx context.Context, hash string) (*store.OAuthCode, error) {
	return f.rows.OAuthCodeByHash(ctx, hash)
}

func (f *faultStore) CreateOAuthAccessToken(ctx context.Context, tok *store.OAuthAccessToken) error {
	if err := f.failing("CreateOAuthAccessToken"); err != nil {
		return err
	}
	return f.rows.CreateOAuthAccessToken(ctx, tok)
}

func (f *faultStore) OAuthAccessTokenByID(ctx context.Context, id string) (*store.OAuthAccessToken, error) {
	return f.rows.OAuthAccessTokenByID(ctx, id)
}

func (f *faultStore) RevokeOAuthAccessToken(ctx context.Context, id string, at time.Time) error {
	return f.rows.RevokeOAuthAccessToken(ctx, id, at)
}

func (f *faultStore) CreateOAuthRefreshToken(ctx context.Context, tok *store.OAuthRefreshToken) error {
	if err := f.failing("CreateOAuthRefreshToken"); err != nil {
		return err
	}
	return f.rows.CreateOAuthRefreshToken(ctx, tok)
}

func (f *faultStore) OAuthRefreshTokenByHash(ctx context.Context, hash string) (*store.OAuthRefreshToken, error) {
	return f.rows.OAuthRefreshTokenByHash(ctx, hash)
}

func (f *faultStore) OAuthRefreshTokenByID(ctx context.Context, id string) (*store.OAuthRefreshToken, error) {
	return f.rows.OAuthRefreshTokenByID(ctx, id)
}

func (f *faultStore) RotateOAuthRefreshToken(ctx context.Context, id, successor string, at time.Time) error {
	return f.rows.RotateOAuthRefreshToken(ctx, id, successor, at)
}

func (f *faultStore) UpsertOAuthConsent(ctx context.Context, c *store.OAuthConsent) error {
	if err := f.failing("UpsertOAuthConsent"); err != nil {
		return err
	}
	return f.rows.UpsertOAuthConsent(ctx, c)
}

func (f *faultStore) OAuthConsent(ctx context.Context, userID, clientID string) (*store.OAuthConsent, error) {
	return f.rows.OAuthConsent(ctx, userID, clientID)
}

func (f *faultStore) ListOAuthConsents(ctx context.Context, userID string) ([]store.OAuthConsent, error) {
	if err := f.failing("ListOAuthConsents"); err != nil {
		return nil, err
	}
	return f.rows.ListOAuthConsents(ctx, userID)
}

func (f *faultStore) DeleteOAuthConsent(ctx context.Context, userID, clientID string) error {
	if err := f.failing("DeleteOAuthConsent"); err != nil {
		return err
	}
	return f.rows.DeleteOAuthConsent(ctx, userID, clientID)
}

func (f *faultStore) ClaimOAuthProof(ctx context.Context, id string, expires time.Time) error {
	return f.rows.ClaimOAuthProof(ctx, id, expires)
}

func (f *faultStore) DeleteExpiredOAuthRows(ctx context.Context, before time.Time) (int, error) {
	if err := f.failing("DeleteExpiredOAuthRows"); err != nil {
		return 0, err
	}
	return f.rows.DeleteExpiredOAuthRows(ctx, before)
}

// faultHarness builds an instance whose store fails the named methods.
func faultHarness(t *testing.T, methods ...string) *testsupport.Harness {
	t.Helper()
	real := testsupport.NewSQLite(t)
	p := oauthprovider.New(
		oauthprovider.KeyEncryptionKey(make([]byte, 32)),
		oauthprovider.LoginPath("/sign-in"),
		oauthprovider.ConsentPath("/consent"),
		oauthprovider.AllowDynamicRegistration(),
		oauthprovider.Clients(oauthprovider.StaticClient{
			ClientID: "first-party", Secret: "first-party-secret",
			AuthMethod:   "client_secret_post",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}),
	)
	return testsupport.NewHarnessWithStore(t, newFaultStore(t, real, methods...),
		authall.WithEmailPassword(authall.EmailPasswordOptions{}),
		authall.WithPlugins(roles.New(roles.Hierarchy("viewer", "admin"), roles.Default("viewer")), p),
	)
}

// TestOAuthProviderStorageFailureIssuesNoToken proves that every storage
// failure of the flow ends the call and hands out nothing.
func TestOAuthProviderStorageFailureIssuesNoToken(t *testing.T) {
	_, challenge := pkcePair(t)

	// The authorize route cannot store the request.
	h := faultHarness(t, "CreateOAuthRequest")
	h.SignUp("owner@example.com", "Password123!")
	resp := h.Do(http.MethodGet, authorizeURL(challenge, nil), nil)
	back, err := url.Parse(resp.Location())
	if err != nil {
		t.Fatal(err)
	}
	if back.Query().Get("error") != "server_error" {
		t.Fatalf("the authorize failure returned %s", resp.Location())
	}

	// The authorize route cannot store the grant.
	h = faultHarness(t, "CreateOAuthGrant")
	h.SignUp("owner@example.com", "Password123!")
	resp = h.Do(http.MethodGet, authorizeURL(challenge, nil), nil)
	back, err = url.Parse(resp.Location())
	if err != nil {
		t.Fatal(err)
	}
	if back.Query().Get("error") != "server_error" || back.Query().Get("code") != "" {
		t.Fatalf("the grant failure returned %s", resp.Location())
	}

	// The authorize route cannot store the code.
	h = faultHarness(t, "CreateOAuthCode")
	h.SignUp("owner@example.com", "Password123!")
	resp = h.Do(http.MethodGet, authorizeURL(challenge, nil), nil)
	back, err = url.Parse(resp.Location())
	if err != nil {
		t.Fatal(err)
	}
	if back.Query().Get("code") != "" {
		t.Fatalf("a failed code write returned a code: %s", resp.Location())
	}

	// The token route cannot record the access token.
	h = faultHarness(t, "CreateOAuthAccessToken")
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, nil)
	token := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	if token.Status != http.StatusInternalServerError {
		t.Fatalf("the token write failure returned %d %s", token.Status, token.Body)
	}

	// The token route cannot record the refresh token.
	h = faultHarness(t, "CreateOAuthRefreshToken")
	verifier, challenge = pkcePair(t)
	code = providerCodeFor(t, h, challenge, nil)
	token = h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	if token.Status != http.StatusInternalServerError {
		t.Fatalf("the refresh write failure returned %d %s", token.Status, token.Body)
	}

	// The key set cannot be read, so no route signs anything.
	h = faultHarness(t, "ListOAuthKeys")
	keys := h.Do(http.MethodGet, "/oauth2/jwks", nil)
	if keys.Status != http.StatusInternalServerError {
		t.Fatalf("the key set failure returned %d", keys.Status)
	}

	// The registration cannot be stored.
	h = faultHarness(t, "CreateOAuthClient")
	created := h.Do(http.MethodPost, "/oauth2/register", map[string]any{
		"client_name": "Desktop", "redirect_uris": []string{"myapp://callback"},
	})
	if created.Status != http.StatusInternalServerError {
		t.Fatalf("the registration failure returned %d %s", created.Status, created.Body)
	}

	// The consent routes report their failures.
	h = faultHarness(t, "ListOAuthConsents", "RevokeOAuthGrantsOfConsent", "DeleteExpiredOAuthRows")
	h.SignUp("owner@example.com", "Password123!")
	if list := h.Do(http.MethodGet, "/oauth2/consents", nil); list.Status != http.StatusInternalServerError {
		t.Fatalf("the consent list failure returned %d", list.Status)
	}
	withdraw := h.Do(http.MethodDelete, "/oauth2/consents/first-party", nil)
	if withdraw.Status != http.StatusInternalServerError {
		t.Fatalf("the withdrawal failure returned %d", withdraw.Status)
	}
}

// postRaw sends a body that is no JSON document and returns the status.
func postRaw(t *testing.T, h *testsupport.Harness, path, body string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.URL(path), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", h.BaseURL)
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestOAuthProviderManagementFailuresReachTheCaller proves that a storage
// failure of a management route ends the call.
func TestOAuthProviderManagementFailuresReachTheCaller(t *testing.T) {
	// The owned client cannot be stored.
	h := faultHarness(t, "CreateOAuthClient")
	h.SignUp("owner@example.com", "Password123!")
	resp := h.Do(http.MethodPost, "/oauth2/clients", map[string]any{
		"client_name": "One", "redirect_uris": []string{"https://one.example.com/cb"},
	})
	if resp.Status != http.StatusInternalServerError {
		t.Fatalf("the create failure returned %d %s", resp.Status, resp.Body)
	}

	// The owned clients cannot be listed.
	h = faultHarness(t, "ListOAuthClients")
	h.SignUp("owner@example.com", "Password123!")
	if list := h.Do(http.MethodGet, "/oauth2/clients", nil); list.Status != http.StatusInternalServerError {
		t.Fatalf("the list failure returned %d", list.Status)
	}

	// The owned client cannot be removed.
	h = faultHarness(t, "DeleteOAuthClient")
	h.SignUp("owner@example.com", "Password123!")
	created := h.Do(http.MethodPost, "/oauth2/clients", map[string]any{
		"client_name": "One", "redirect_uris": []string{"https://one.example.com/cb"},
	})
	var owned struct {
		ClientID string `json:"clientId"`
	}
	created.Decode(t, &owned)
	if del := h.Do(http.MethodDelete, "/oauth2/clients/"+owned.ClientID, nil); del.Status != http.StatusInternalServerError {
		t.Fatalf("the delete failure returned %d", del.Status)
	}

	// The registered client cannot be updated or removed.
	h = faultHarness(t, "UpdateOAuthClient", "DeleteOAuthClient")
	registered := h.Do(http.MethodPost, "/oauth2/register", map[string]any{
		"client_name": "Desktop", "redirect_uris": []string{"myapp://callback"},
	})
	var client struct {
		ClientID                string `json:"client_id"`
		RegistrationAccessToken string `json:"registration_access_token"`
	}
	registered.Decode(t, &client)
	update := h.Do(http.MethodPut, "/oauth2/register/"+client.ClientID, map[string]any{
		"client_name": "Desktop 2", "redirect_uris": []string{"myapp://callback"},
	}, testsupport.WithBearer(client.RegistrationAccessToken))
	if update.Status != http.StatusInternalServerError {
		t.Fatalf("the update failure returned %d %s", update.Status, update.Body)
	}
	remove := h.Do(http.MethodDelete, "/oauth2/register/"+client.ClientID, nil,
		testsupport.WithBearer(client.RegistrationAccessToken))
	if remove.Status != http.StatusInternalServerError {
		t.Fatalf("the delete failure returned %d", remove.Status)
	}

	// The consent of a decision cannot be stored, and the request cannot be
	// consumed.
	h = faultHarness(t, "UpsertOAuthConsent")
	third := h.Do(http.MethodPost, "/oauth2/register", map[string]any{
		"client_name": "Third", "redirect_uris": []string{"https://third.example.com/cb"},
	})
	third.Decode(t, &client)
	h.SignUp("owner@example.com", "Password123!")
	_, challenge := pkcePair(t)
	authorize := h.Do(http.MethodGet, "/oauth2/authorize?"+url.Values{
		"client_id": {client.ClientID}, "redirect_uri": {"https://third.example.com/cb"},
		"response_type": {"code"}, "scope": {"openid email"}, "state": {"s"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode(), nil)
	page, err := url.Parse(authorize.Location())
	if err != nil {
		t.Fatal(err)
	}
	decide := h.Do(http.MethodPost, "/oauth2/decide", map[string]any{
		"requestId": page.Query().Get("request_id"), "approve": true,
	})
	if decide.Status != http.StatusInternalServerError {
		t.Fatalf("the consent failure returned %d %s", decide.Status, decide.Body)
	}
}

// TestOAuthProviderDecisionRoutesCheckTheOrigin proves that a cross-site page
// posts no decision and withdraws no consent.
func TestOAuthProviderDecisionRoutesCheckTheOrigin(t *testing.T) {
	h := faultHarness(t)
	h.SignUp("owner@example.com", "Password123!")
	foreign := testsupport.WithHeader("Origin", "https://evil.example.com")
	decide := h.Do(http.MethodPost, "/oauth2/decide",
		map[string]any{"requestId": "any", "approve": true}, foreign)
	if decide.Status != http.StatusForbidden {
		t.Fatalf("a cross-site decision returned %d", decide.Status)
	}
	withdraw := h.Do(http.MethodDelete, "/oauth2/consents/first-party", nil, foreign)
	if withdraw.Status != http.StatusForbidden {
		t.Fatalf("a cross-site withdrawal returned %d", withdraw.Status)
	}
	create := h.Do(http.MethodPost, "/oauth2/clients",
		map[string]any{"client_name": "One"}, foreign)
	if create.Status != http.StatusForbidden {
		t.Fatalf("a cross-site client registration returned %d", create.Status)
	}
}

// TestOAuthProviderRejectsABadBody proves that an unreadable body reaches no
// handler logic.
func TestOAuthProviderRejectsABadBody(t *testing.T) {
	h := faultHarness(t)
	h.SignUp("owner@example.com", "Password123!")
	for _, path := range []string{"/oauth2/decide", "/oauth2/clients", "/oauth2/register"} {
		if status := postRaw(t, h, path, "not json"); status != http.StatusBadRequest {
			t.Errorf("a malformed body at %s returned %d", path, status)
		}
	}
}
