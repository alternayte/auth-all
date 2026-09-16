package storetest

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// runOAuthProviderTests executes the OAuth provider part of the contract
// suite. The tables belong to the OAuth provider plugin, so the suite applies
// them before the first test.
func runOAuthProviderTests(t *testing.T, newStore Factory, o schema.Options) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(t *testing.T, s store.Store, rows store.OAuthProviderStore)
	}{
		{"OAuthKeys", testOAuthKeys},
		{"OAuthClients", testOAuthClients},
		{"OAuthRequestConsumeIsSingleUse", testOAuthRequestConsume},
		{"OAuthCodeConsumeIsSingleUse", testOAuthCodeConsume},
		{"ConcurrentOAuthCodeConsume", testConcurrentOAuthCodeConsume},
		{"OAuthGrantRevocationReachesTheTokens", testOAuthGrantRevocation},
		{"OAuthRefreshRotationIsSingleUse", testOAuthRefreshRotation},
		{"OAuthConsentUpsert", testOAuthConsent},
		{"OAuthProofIsSingleUse", testOAuthProof},
		{"OAuthCleanupRemovesExpiredRows", testOAuthCleanup},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			migrateOAuthProvider(t, s, o)
			rows, ok := s.(store.OAuthProviderStore)
			if !ok {
				t.Skip("the adapter holds no OAuth provider row")
			}
			tc.fn(t, s, rows)
		})
	}
}

// migrateOAuthProvider applies the OAuth provider tables to a migrated store.
func migrateOAuthProvider(t *testing.T, s store.Store, o schema.Options) {
	t.Helper()
	sc, err := schema.NewCoreWithOptions(o)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	for _, table := range schema.OAuthProviderTables(sc.Options()) {
		if err := sc.Add(table); err != nil {
			t.Fatalf("add the OAuth provider table: %v", err)
		}
	}
	units, err := schema.OAuthProviderUnits(sc.Options(), "oauthprovider")
	if err != nil {
		t.Fatalf("OAuth provider units: %v", err)
	}
	for _, unit := range units {
		if err := sc.AddUnit(unit); err != nil {
			t.Fatalf("add the OAuth provider unit: %v", err)
		}
	}
	if _, err := s.Migrator().Apply(ctx(t), sc); err != nil {
		t.Fatalf("migrate the OAuth provider tables: %v", err)
	}
}

// newOAuthUser inserts one user that owns the grants of a test.
func newOAuthUser(t *testing.T, s store.Store) *store.User {
	t.Helper()
	user := NewUser("owner@example.com")
	if err := s.Users().Create(ctx(t), user); err != nil {
		t.Fatalf("create the user: %v", err)
	}
	return user
}

func testOAuthKeys(t *testing.T, s store.Store, rows store.OAuthProviderStore) {
	n := now()
	firstID, secondID := uuid.NewString(), uuid.NewString()
	first := &store.OAuthKey{ID: firstID, Algorithm: "ES256",
		WrappedPrivate: []byte{0, 1, 2, 255}, PublicJWK: `{"kty":"EC"}`, CreatedAt: n}
	if err := rows.CreateOAuthKey(ctx(t), first); err != nil {
		t.Fatalf("create the key: %v", err)
	}
	second := &store.OAuthKey{ID: secondID, Algorithm: "ES256",
		WrappedPrivate: []byte{9}, PublicJWK: `{"kty":"EC"}`, CreatedAt: n.Add(time.Second)}
	if err := rows.CreateOAuthKey(ctx(t), second); err != nil {
		t.Fatalf("create the second key: %v", err)
	}
	list, err := rows.ListOAuthKeys(ctx(t))
	if err != nil || len(list) != 2 {
		t.Fatalf("list the keys: %v %d", err, len(list))
	}
	if list[0].ID != secondID {
		t.Fatalf("the newest key is %q", list[0].ID)
	}
	// The wrapped bytes survive the round trip, so a key decrypts later.
	for _, key := range list {
		if key.ID == firstID && string(key.WrappedPrivate) != string(first.WrappedPrivate) {
			t.Fatalf("the wrapped key changed: %v", key.WrappedPrivate)
		}
	}
	if err := rows.RetireOAuthKeys(ctx(t), secondID, now()); err != nil {
		t.Fatalf("retire: %v", err)
	}
	list, err = rows.ListOAuthKeys(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range list {
		if key.ID == secondID && key.RetiredAt != nil {
			t.Fatal("the current key was retired")
		}
		if key.ID == firstID && key.RetiredAt == nil {
			t.Fatal("the earlier key stayed current")
		}
	}
}

func testOAuthClients(t *testing.T, s store.Store, rows store.OAuthProviderStore) {
	user := newOAuthUser(t, s)
	n := now()
	tokenHash := "registration-hash"
	client := &store.OAuthClient{
		ID: uuid.NewString(), ClientID: uuid.NewString(), SecretHash: "secret-hash",
		Name: "One", RedirectURIs: []string{"https://one.example.com/cb", "myapp://cb"},
		GrantTypes: []string{"authorization_code", "refresh_token"},
		Scopes:     []string{"openid", "email"}, TokenEndpointAuthMethod: "client_secret_basic",
		DPoPRequired: true, OwnerUserID: &user.ID, RegistrationTokenHash: &tokenHash,
		CreatedAt: n, UpdatedAt: n,
	}
	if err := rows.CreateOAuthClient(ctx(t), client); err != nil {
		t.Fatalf("create the client: %v", err)
	}
	if err := rows.CreateOAuthClient(ctx(t), client); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("the duplicate client identifier returned %v", err)
	}
	back, err := rows.OAuthClientByClientID(ctx(t), client.ClientID)
	if err != nil {
		t.Fatalf("read the client: %v", err)
	}
	if len(back.RedirectURIs) != 2 || back.RedirectURIs[1] != "myapp://cb" {
		t.Fatalf("the redirect URIs changed: %v", back.RedirectURIs)
	}
	if !back.DPoPRequired || back.OwnerUserID == nil || *back.OwnerUserID != user.ID {
		t.Fatalf("the client lost fields: %+v", back)
	}
	back.Name = "One renamed"
	back.UpdatedAt = now()
	if err := rows.UpdateOAuthClient(ctx(t), back); err != nil {
		t.Fatalf("update: %v", err)
	}
	owned, err := rows.ListOAuthClients(ctx(t), user.ID)
	if err != nil || len(owned) != 1 || owned[0].Name != "One renamed" {
		t.Fatalf("list by owner: %v %v", owned, err)
	}
	all, err := rows.ListOAuthClients(ctx(t), "")
	if err != nil || len(all) != 1 {
		t.Fatalf("list all: %v %v", all, err)
	}
	if err := rows.DeleteOAuthClient(ctx(t), client.ClientID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := rows.OAuthClientByClientID(ctx(t), client.ClientID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the deleted client returned %v", err)
	}
	if err := rows.DeleteOAuthClient(ctx(t), client.ClientID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the second delete returned %v", err)
	}
}

// newRequest returns one stored authorization request.
func newRequest(t *testing.T, rows store.OAuthProviderStore) *store.OAuthAuthorizationRequest {
	t.Helper()
	n := now()
	maxAge := 300
	row := &store.OAuthAuthorizationRequest{
		ID: uuid.NewString(), ClientID: "client-one",
		RedirectURI: "https://one.example.com/cb", Scopes: []string{"openid", "email"},
		Resources: []string{"https://api.example.com"}, State: "state", Nonce: "nonce",
		CodeChallenge: "challenge", CodeChallengeMethod: "S256", Prompt: []string{"consent"},
		MaxAge: &maxAge, DPoPJKT: "thumb", CreatedAt: n, ExpiresAt: n.Add(time.Minute),
	}
	if err := rows.CreateOAuthRequest(ctx(t), row); err != nil {
		t.Fatalf("create the request: %v", err)
	}
	return row
}

func testOAuthRequestConsume(t *testing.T, s store.Store, rows store.OAuthProviderStore) {
	row := newRequest(t, rows)
	back, err := rows.OAuthRequestByID(ctx(t), row.ID)
	if err != nil {
		t.Fatalf("read the request: %v", err)
	}
	if back.MaxAge == nil || *back.MaxAge != 300 || back.Nonce != "nonce" ||
		len(back.Scopes) != 2 || len(back.Resources) != 1 || back.DPoPJKT != "thumb" {
		t.Fatalf("the request lost fields: %+v", back)
	}
	consumed, err := rows.ConsumeOAuthRequest(ctx(t), row.ID, now())
	if err != nil || consumed.ConsumedAt == nil {
		t.Fatalf("consume: %v", err)
	}
	if _, err := rows.ConsumeOAuthRequest(ctx(t), row.ID, now()); err == nil {
		t.Fatal("the request was consumed twice")
	}

	// An expired request consumes nothing.
	n := now()
	expired := &store.OAuthAuthorizationRequest{ID: uuid.NewString(), ClientID: "client-one",
		RedirectURI: "https://one.example.com/cb", CreatedAt: n.Add(-time.Hour),
		ExpiresAt: n.Add(-time.Minute)}
	if err := rows.CreateOAuthRequest(ctx(t), expired); err != nil {
		t.Fatal(err)
	}
	if _, err := rows.ConsumeOAuthRequest(ctx(t), expired.ID, now()); err == nil {
		t.Fatal("an expired request was consumed")
	}
}

// newGrantWithCode inserts one grant and one code of that grant.
func newGrantWithCode(t *testing.T, s store.Store, rows store.OAuthProviderStore) (*store.OAuthGrant, *store.OAuthCode) {
	t.Helper()
	user := newOAuthUser(t, s)
	n := now()
	grant := &store.OAuthGrant{ID: uuid.NewString(), ClientID: "client-one", UserID: &user.ID,
		Scopes: []string{"openid", "offline_access"}, Resources: []string{"https://api.example.com"},
		AuthTime: &n, CreatedAt: n}
	if err := rows.CreateOAuthGrant(ctx(t), grant); err != nil {
		t.Fatalf("create the grant: %v", err)
	}
	// The hash is unique per call, because one database can hold the rows of
	// more than one test of the suite.
	code := &store.OAuthCode{ID: uuid.NewString(), CodeHash: uuid.NewString(), GrantID: grant.ID,
		ClientID: "client-one", RedirectURI: "https://one.example.com/cb",
		CodeChallenge: "challenge", Nonce: "nonce", Scopes: grant.Scopes,
		Resources: grant.Resources, CreatedAt: n, ExpiresAt: n.Add(time.Minute)}
	if err := rows.CreateOAuthCode(ctx(t), code); err != nil {
		t.Fatalf("create the code: %v", err)
	}
	return grant, code
}

func testOAuthCodeConsume(t *testing.T, s store.Store, rows store.OAuthProviderStore) {
	_, code := newGrantWithCode(t, s, rows)
	back, err := rows.OAuthCodeByHash(ctx(t), code.CodeHash)
	if err != nil || back.Nonce != "nonce" {
		t.Fatalf("read the code: %v %+v", err, back)
	}
	consumed, err := rows.ConsumeOAuthCode(ctx(t), code.CodeHash, now())
	if err != nil || consumed.ConsumedAt == nil {
		t.Fatalf("consume: %v", err)
	}
	if _, err := rows.ConsumeOAuthCode(ctx(t), code.CodeHash, now()); err == nil {
		t.Fatal("the code was consumed twice")
	}
}

func testConcurrentOAuthCodeConsume(t *testing.T, s store.Store, rows store.OAuthProviderStore) {
	_, code := newGrantWithCode(t, s, rows)
	const callers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			if _, err := rows.ConsumeOAuthCode(ctx(t), code.CodeHash, now()); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d callers consumed one code", wins)
	}
}

func testOAuthGrantRevocation(t *testing.T, s store.Store, rows store.OAuthProviderStore) {
	grant, _ := newGrantWithCode(t, s, rows)
	n := now()
	access := &store.OAuthAccessToken{ID: uuid.NewString(), GrantID: grant.ID,
		ClientID: grant.ClientID, UserID: grant.UserID, Scopes: grant.Scopes,
		Audience: "https://api.example.com", CreatedAt: n, ExpiresAt: n.Add(time.Minute)}
	if err := rows.CreateOAuthAccessToken(ctx(t), access); err != nil {
		t.Fatalf("create the access token: %v", err)
	}
	refresh := &store.OAuthRefreshToken{ID: uuid.NewString(), TokenHash: uuid.NewString(),
		GrantID: grant.ID, ClientID: grant.ClientID, UserID: grant.UserID,
		Scopes: grant.Scopes, Resources: grant.Resources, CreatedAt: n,
		ExpiresAt: n.Add(time.Hour)}
	if err := rows.CreateOAuthRefreshToken(ctx(t), refresh); err != nil {
		t.Fatalf("create the refresh token: %v", err)
	}
	if err := rows.RevokeOAuthGrant(ctx(t), grant.ID, now()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	backAccess, err := rows.OAuthAccessTokenByID(ctx(t), access.ID)
	if err != nil || backAccess.RevokedAt == nil {
		t.Fatalf("the access token survived the revocation: %v %+v", err, backAccess)
	}
	backRefresh, err := rows.OAuthRefreshTokenByHash(ctx(t), refresh.TokenHash)
	if err != nil || backRefresh.RevokedAt == nil {
		t.Fatalf("the refresh token survived the revocation: %v %+v", err, backRefresh)
	}
	backGrant, err := rows.OAuthGrantByID(ctx(t), grant.ID)
	if err != nil || backGrant.RevokedAt == nil {
		t.Fatalf("the grant is live: %v %+v", err, backGrant)
	}

	// The revocation of every grant of a user reaches the same rows.
	if err := rows.RevokeOAuthGrantsOfUser(ctx(t), *grant.UserID, now()); err != nil {
		t.Fatalf("revoke by user: %v", err)
	}
	if err := rows.RevokeOAuthGrantsOfConsent(ctx(t), *grant.UserID, grant.ClientID, now()); err != nil {
		t.Fatalf("revoke by consent: %v", err)
	}
	// A revoked access token stays revoked after another pass.
	backAccess, err = rows.OAuthAccessTokenByID(ctx(t), access.ID)
	if err != nil || backAccess.RevokedAt == nil {
		t.Fatalf("the access token lost its revocation: %v", err)
	}
	if err := rows.RevokeOAuthAccessToken(ctx(t), access.ID, now()); err != nil {
		t.Fatalf("revoke the access token: %v", err)
	}
}

func testOAuthRefreshRotation(t *testing.T, s store.Store, rows store.OAuthProviderStore) {
	grant, _ := newGrantWithCode(t, s, rows)
	n := now()
	first := &store.OAuthRefreshToken{ID: uuid.NewString(), TokenHash: uuid.NewString(),
		GrantID: grant.ID, ClientID: grant.ClientID, UserID: grant.UserID,
		Scopes: grant.Scopes, Resources: grant.Resources, JKT: "thumb",
		CreatedAt: n, ExpiresAt: n.Add(time.Hour)}
	if err := rows.CreateOAuthRefreshToken(ctx(t), first); err != nil {
		t.Fatal(err)
	}
	successor := uuid.NewString()
	if err := rows.RotateOAuthRefreshToken(ctx(t), first.ID, successor, now()); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := rows.RotateOAuthRefreshToken(ctx(t), first.ID, uuid.NewString(), now()); err == nil {
		t.Fatal("one token rotated twice")
	}
	back, err := rows.OAuthRefreshTokenByID(ctx(t), first.ID)
	if err != nil || back.RotatedAt == nil || back.SuccessorID == nil || *back.SuccessorID != successor {
		t.Fatalf("the rotation record is wrong: %v %+v", err, back)
	}
	if back.JKT != "thumb" || len(back.Resources) != 1 {
		t.Fatalf("the refresh token lost fields: %+v", back)
	}
}

func testOAuthConsent(t *testing.T, s store.Store, rows store.OAuthProviderStore) {
	user := newOAuthUser(t, s)
	n := now()
	consent := &store.OAuthConsent{ID: uuid.NewString(), ClientID: "client-one",
		UserID: user.ID, Scopes: []string{"openid"}, CreatedAt: n, UpdatedAt: n}
	if err := rows.UpsertOAuthConsent(ctx(t), consent); err != nil {
		t.Fatalf("insert the consent: %v", err)
	}
	// The second call widens the same row instead of adding one.
	wider := &store.OAuthConsent{ID: uuid.NewString(), ClientID: "client-one",
		UserID: user.ID, Scopes: []string{"openid", "email"},
		Resources: []string{"https://api.example.com"}, CreatedAt: n, UpdatedAt: now()}
	if err := rows.UpsertOAuthConsent(ctx(t), wider); err != nil {
		t.Fatalf("update the consent: %v", err)
	}
	list, err := rows.ListOAuthConsents(ctx(t), user.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("the consent list holds %d rows: %v", len(list), err)
	}
	back, err := rows.OAuthConsent(ctx(t), user.ID, "client-one")
	if err != nil || len(back.Scopes) != 2 || len(back.Resources) != 1 {
		t.Fatalf("the consent did not widen: %v %+v", err, back)
	}
	if err := rows.DeleteOAuthConsent(ctx(t), user.ID, "client-one"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := rows.OAuthConsent(ctx(t), user.ID, "client-one"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the deleted consent returned %v", err)
	}
}

func testOAuthProof(t *testing.T, s store.Store, rows store.OAuthProviderStore) {
	expires := now().Add(time.Minute)
	id := uuid.NewString()
	if err := rows.ClaimOAuthProof(ctx(t), id, expires); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := rows.ClaimOAuthProof(ctx(t), id, expires); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("the replayed proof returned %v", err)
	}
}

func testOAuthCleanup(t *testing.T, s store.Store, rows store.OAuthProviderStore) {
	n := now()
	expired := &store.OAuthAuthorizationRequest{ID: uuid.NewString(), ClientID: "client-one",
		RedirectURI: "https://one.example.com/cb", CreatedAt: n.Add(-2 * time.Hour),
		ExpiresAt: n.Add(-time.Hour)}
	if err := rows.CreateOAuthRequest(ctx(t), expired); err != nil {
		t.Fatal(err)
	}
	live := newRequest(t, rows)
	removed, err := rows.DeleteExpiredOAuthRows(ctx(t), now())
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if removed < 1 {
		t.Fatalf("the cleanup removed %d rows", removed)
	}
	if _, err := rows.OAuthRequestByID(ctx(t), live.ID); err != nil {
		t.Fatalf("the cleanup removed a live request: %v", err)
	}
}
