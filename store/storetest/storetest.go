// Package storetest holds the behavioral contract suite that every Auth-All
// storage adapter must pass. PostgreSQL and SQLite run the same suite.
package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// Factory returns a migrated empty store for one test.
type Factory func(t *testing.T) store.Store

// Run executes the complete storage contract suite against one adapter.
func Run(t *testing.T, newStore Factory) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(t *testing.T, s store.Store)
	}{
		{"MigrateIsIdempotent", testMigrateIdempotent},
		{"UserCreateAndRead", testUserCreateAndRead},
		{"UserUniqueNormalizedEmail", testUserUniqueEmail},
		{"UserUpdate", testUserUpdate},
		{"UserNotFound", testUserNotFound},
		{"Credentials", testCredentials},
		{"Accounts", testAccounts},
		{"AccountProviderIdentityIsUnique", testAccountUnique},
		{"Sessions", testSessions},
		{"SessionRevocationIsFinal", testSessionRevocation},
		{"Tokens", testTokens},
		{"TokenConsumeRejectsExpired", testTokenExpired},
		{"TokenConsumeRejectsReplay", testTokenReplay},
		{"TokenDeleteByIdentifier", testTokenDeleteByIdentifier},
		{"OAuthState", testOAuthState},
		{"TransactionCommit", testTransactionCommit},
		{"TransactionRollback", testTransactionRollback},
		{"ConcurrentSignUpSameEmail", testConcurrentSignUp},
		{"ConcurrentTokenConsume", testConcurrentTokenConsume},
		{"ConcurrentAccountLink", testConcurrentAccountLink},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			tc.fn(t, s)
		})
	}
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

func now() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

// NewUser returns a valid user value for tests.
func NewUser(email string) *store.User {
	n := now()
	return &store.User{
		ID:              uuid.NewString(),
		Email:           email,
		EmailNormalized: email,
		DisplayName:     "Test User",
		CreatedAt:       n,
		UpdatedAt:       n,
	}
}

func mustCreateUser(t *testing.T, s store.Store, email string) *store.User {
	t.Helper()
	u := NewUser(email)
	if err := s.Users().Create(ctx(t), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func testMigrateIdempotent(t *testing.T, s store.Store) {
	sc, err := schema.NewCore()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := s.Migrator().Plan(ctx(t), sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected no pending statement after migration, got %d", len(pending))
	}
	if err := s.Migrator().Check(ctx(t), sc); err != nil {
		t.Fatalf("check: %v", err)
	}
	applied, err := s.Migrator().Apply(ctx(t), sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 0 {
		t.Fatalf("second apply changed %d statements", len(applied))
	}
}

func testUserCreateAndRead(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "alice@example.com")
	got, err := s.Users().GetByID(c, u.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.Email != u.Email || got.EmailNormalized != u.EmailNormalized {
		t.Fatalf("unexpected user %+v", got)
	}
	if got.EmailVerifiedAt != nil {
		t.Fatalf("expected an unverified email")
	}
	if !got.CreatedAt.Equal(u.CreatedAt) {
		t.Fatalf("created_at round trip: got %v want %v", got.CreatedAt, u.CreatedAt)
	}
	byEmail, err := s.Users().GetByNormalizedEmail(c, "alice@example.com")
	if err != nil {
		t.Fatalf("get by email: %v", err)
	}
	if byEmail.ID != u.ID {
		t.Fatalf("wrong user")
	}
}

func testUserUniqueEmail(t *testing.T, s store.Store) {
	c := ctx(t)
	mustCreateUser(t, s, "dup@example.com")
	second := NewUser("dup@example.com")
	err := s.Users().Create(c, second)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func testUserUpdate(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "update@example.com")
	verified := now()
	u.EmailVerifiedAt = &verified
	u.DisplayName = "Renamed"
	u.ImageURL = "https://example.com/a.png"
	u.UpdatedAt = now()
	if err := s.Users().Update(c, u); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := s.Users().GetByID(c, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayName != "Renamed" || got.ImageURL != "https://example.com/a.png" {
		t.Fatalf("update lost fields: %+v", got)
	}
	if got.EmailVerifiedAt == nil || !got.EmailVerifiedAt.Equal(verified) {
		t.Fatalf("verified timestamp round trip failed: %+v", got.EmailVerifiedAt)
	}
}

func testUserNotFound(t *testing.T, s store.Store) {
	c := ctx(t)
	if _, err := s.Users().GetByID(c, uuid.NewString()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := s.Users().GetByNormalizedEmail(c, "missing@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := s.Users().Update(c, NewUser("ghost@example.com")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on update, got %v", err)
	}
}

func testCredentials(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "cred@example.com")
	if _, err := s.Users().GetCredential(c, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	cred := &store.Credential{UserID: u.ID, PasswordHash: "hash-1", CreatedAt: now(), UpdatedAt: now()}
	if err := s.Users().SetCredential(c, cred); err != nil {
		t.Fatalf("set credential: %v", err)
	}
	got, err := s.Users().GetCredential(c, u.ID)
	if err != nil || got.PasswordHash != "hash-1" {
		t.Fatalf("get credential: %+v %v", got, err)
	}
	cred.PasswordHash = "hash-2"
	cred.UpdatedAt = now()
	if err := s.Users().SetCredential(c, cred); err != nil {
		t.Fatalf("replace credential: %v", err)
	}
	got, err = s.Users().GetCredential(c, u.ID)
	if err != nil || got.PasswordHash != "hash-2" {
		t.Fatalf("credential was not replaced: %+v %v", got, err)
	}
	if err := s.Users().DeleteCredential(c, u.ID); err != nil {
		t.Fatalf("delete credential: %v", err)
	}
	if _, err := s.Users().GetCredential(c, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func testAccounts(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "acct@example.com")
	a := &store.Account{ID: uuid.NewString(), UserID: u.ID, Provider: "github", ProviderAccountID: "1", CreatedAt: now(), UpdatedAt: now()}
	if err := s.Accounts().Create(c, a); err != nil {
		t.Fatalf("create account: %v", err)
	}
	got, err := s.Accounts().GetByProviderAccount(c, "github", "1")
	if err != nil || got.UserID != u.ID {
		t.Fatalf("get account: %+v %v", got, err)
	}
	list, err := s.Accounts().ListByUser(c, u.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list accounts: %+v %v", list, err)
	}
	if err := s.Accounts().Delete(c, u.ID, "github"); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	if _, err := s.Accounts().GetByProviderAccount(c, "github", "1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := s.Accounts().Delete(c, u.ID, "github"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on second delete, got %v", err)
	}
}

func testAccountUnique(t *testing.T, s store.Store) {
	c := ctx(t)
	first := mustCreateUser(t, s, "one@example.com")
	second := mustCreateUser(t, s, "two@example.com")
	a := &store.Account{ID: uuid.NewString(), UserID: first.ID, Provider: "google", ProviderAccountID: "same", CreatedAt: now(), UpdatedAt: now()}
	if err := s.Accounts().Create(c, a); err != nil {
		t.Fatal(err)
	}
	b := &store.Account{ID: uuid.NewString(), UserID: second.ID, Provider: "google", ProviderAccountID: "same", CreatedAt: now(), UpdatedAt: now()}
	if err := s.Accounts().Create(c, b); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func testSessions(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "sess@example.com")
	sess := &store.Session{ID: uuid.NewString(), UserID: u.ID, TokenHash: "hash-a", CreatedAt: now(), ExpiresAt: now().Add(time.Hour), LastSeenAt: now()}
	if err := s.Sessions().Create(c, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	got, err := s.Sessions().GetByTokenHash(c, "hash-a")
	if err != nil || got.UserID != u.ID {
		t.Fatalf("get session: %+v %v", got, err)
	}
	later := now().Add(time.Minute)
	if err := s.Sessions().Touch(c, sess.ID, later); err != nil {
		t.Fatalf("touch: %v", err)
	}
	got, err = s.Sessions().GetByTokenHash(c, "hash-a")
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSeenAt.Equal(later) {
		t.Fatalf("touch did not persist: %v", got.LastSeenAt)
	}
	other := &store.Session{ID: uuid.NewString(), UserID: u.ID, TokenHash: "hash-b", CreatedAt: now(), ExpiresAt: now().Add(time.Hour), LastSeenAt: now()}
	if err := s.Sessions().Create(c, other); err != nil {
		t.Fatal(err)
	}
	n, err := s.Sessions().DeleteByUser(c, u.ID)
	if err != nil || n != 2 {
		t.Fatalf("delete by user: %d %v", n, err)
	}
	if _, err := s.Sessions().GetByTokenHash(c, "hash-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	expired := &store.Session{ID: uuid.NewString(), UserID: u.ID, TokenHash: "hash-c", CreatedAt: now().Add(-2 * time.Hour), ExpiresAt: now().Add(-time.Hour), LastSeenAt: now().Add(-time.Hour)}
	if err := s.Sessions().Create(c, expired); err != nil {
		t.Fatal(err)
	}
	n, err = s.Sessions().DeleteExpired(c, now())
	if err != nil || n != 1 {
		t.Fatalf("delete expired: %d %v", n, err)
	}
}

func testSessionRevocation(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "revoke@example.com")
	sess := &store.Session{ID: uuid.NewString(), UserID: u.ID, TokenHash: "revoke-hash", CreatedAt: now(), ExpiresAt: now().Add(time.Hour), LastSeenAt: now()}
	if err := s.Sessions().Create(c, sess); err != nil {
		t.Fatal(err)
	}
	if err := s.Sessions().Delete(c, sess.ID); err != nil {
		t.Fatal(err)
	}
	// A late touch must not resurrect the revoked session.
	if err := s.Sessions().Touch(c, sess.ID, now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on touch after revocation, got %v", err)
	}
	if _, err := s.Sessions().GetByTokenHash(c, "revoke-hash"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoked session became readable again: %v", err)
	}
	if err := s.Sessions().Delete(c, sess.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on second delete, got %v", err)
	}
}

func newToken(userID *string, kind, identifier, hash string, expires time.Time) *store.Token {
	return &store.Token{
		ID: uuid.NewString(), UserID: userID, Kind: kind, Identifier: identifier,
		TokenHash: hash, CreatedAt: now(), ExpiresAt: expires,
	}
}

func testTokens(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "token@example.com")
	tok := newToken(&u.ID, "verify-email", "token@example.com", "th-1", now().Add(time.Hour))
	if err := s.Tokens().Create(c, tok); err != nil {
		t.Fatalf("create token: %v", err)
	}
	got, err := s.Tokens().Get(c, "verify-email", "th-1")
	if err != nil || got.ConsumedAt != nil {
		t.Fatalf("get token: %+v %v", got, err)
	}
	if got.UserID == nil || *got.UserID != u.ID {
		t.Fatalf("token lost the user id")
	}
	consumed, err := s.Tokens().Consume(c, "verify-email", "th-1", now())
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if consumed.ConsumedAt == nil {
		t.Fatalf("consume did not record the timestamp")
	}
	// A token without a user is valid, for example a magic link for an
	// address that has no account yet.
	anon := newToken(nil, "magic-link", "anon@example.com", "th-2", now().Add(time.Hour))
	if err := s.Tokens().Create(c, anon); err != nil {
		t.Fatalf("create token without user: %v", err)
	}
	got, err = s.Tokens().Get(c, "magic-link", "th-2")
	if err != nil || got.UserID != nil {
		t.Fatalf("anonymous token: %+v %v", got, err)
	}
	if _, err := s.Tokens().Consume(c, "magic-link", "missing", now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for an unknown token, got %v", err)
	}
}

func testTokenExpired(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "expired@example.com")
	tok := newToken(&u.ID, "reset-password", u.Email, "expired-hash", now().Add(-time.Minute))
	if err := s.Tokens().Create(c, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tokens().Consume(c, "reset-password", "expired-hash", now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected an expired token to be rejected, got %v", err)
	}
	n, err := s.Tokens().DeleteExpired(c, now())
	if err != nil || n != 1 {
		t.Fatalf("delete expired tokens: %d %v", n, err)
	}
}

func testTokenReplay(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "replay@example.com")
	tok := newToken(&u.ID, "reset-password", u.Email, "replay-hash", now().Add(time.Hour))
	if err := s.Tokens().Create(c, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tokens().Consume(c, "reset-password", "replay-hash", now()); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.Tokens().Consume(c, "reset-password", "replay-hash", now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected a replay to be rejected, got %v", err)
	}
}

func testTokenDeleteByIdentifier(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "purge@example.com")
	for _, h := range []string{"p-1", "p-2"} {
		if err := s.Tokens().Create(c, newToken(&u.ID, "reset-password", u.Email, h, now().Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Tokens().DeleteByIdentifier(c, "reset-password", u.Email); err != nil {
		t.Fatalf("delete by identifier: %v", err)
	}
	if _, err := s.Tokens().Get(c, "reset-password", "p-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected the token to be gone, got %v", err)
	}
}

func testOAuthState(t *testing.T, s store.Store) {
	c := ctx(t)
	st := &store.OAuthState{
		ID: uuid.NewString(), StateHash: "state-hash", Provider: "github",
		Verifier: "verifier", Nonce: "nonce", RedirectTo: "/after",
		CreatedAt: now(), ExpiresAt: now().Add(10 * time.Minute),
	}
	if err := s.OAuthStates().Create(c, st); err != nil {
		t.Fatalf("create state: %v", err)
	}
	got, err := s.OAuthStates().Consume(c, "state-hash", now())
	if err != nil {
		t.Fatalf("consume state: %v", err)
	}
	if got.Verifier != "verifier" || got.Nonce != "nonce" || got.RedirectTo != "/after" {
		t.Fatalf("state round trip failed: %+v", got)
	}
	if _, err := s.OAuthStates().Consume(c, "state-hash", now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected a replayed state to be rejected, got %v", err)
	}
	expired := &store.OAuthState{
		ID: uuid.NewString(), StateHash: "old-hash", Provider: "github",
		CreatedAt: now().Add(-time.Hour), ExpiresAt: now().Add(-time.Minute),
	}
	if err := s.OAuthStates().Create(c, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OAuthStates().Consume(c, "old-hash", now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected an expired state to be rejected, got %v", err)
	}
	n, err := s.OAuthStates().DeleteExpired(c, now())
	if err != nil || n != 1 {
		t.Fatalf("delete expired states: %d %v", n, err)
	}
}

func testTransactionCommit(t *testing.T, s store.Store) {
	c := ctx(t)
	u := NewUser("tx-commit@example.com")
	err := s.Transaction(c, func(tx store.Store) error {
		if err := tx.Users().Create(c, u); err != nil {
			return err
		}
		return tx.Users().SetCredential(c, &store.Credential{UserID: u.ID, PasswordHash: "h", CreatedAt: now(), UpdatedAt: now()})
	})
	if err != nil {
		t.Fatalf("transaction: %v", err)
	}
	if _, err := s.Users().GetByID(c, u.ID); err != nil {
		t.Fatalf("user missing after commit: %v", err)
	}
	if _, err := s.Users().GetCredential(c, u.ID); err != nil {
		t.Fatalf("credential missing after commit: %v", err)
	}
}

func testTransactionRollback(t *testing.T, s store.Store) {
	c := ctx(t)
	u := NewUser("tx-rollback@example.com")
	sentinel := errors.New("rollback")
	err := s.Transaction(c, func(tx store.Store) error {
		if err := tx.Users().Create(c, u); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected the sentinel error, got %v", err)
	}
	if _, err := s.Users().GetByID(c, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the rollback did not remove the user: %v", err)
	}
}

// testConcurrentSignUp covers C-001.
func testConcurrentSignUp(t *testing.T, s store.Store) {
	c := ctx(t)
	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Transaction(c, func(tx store.Store) error {
				u := NewUser("race@example.com")
				if err := tx.Users().Create(c, u); err != nil {
					return err
				}
				return tx.Users().SetCredential(c, &store.Credential{UserID: u.ID, PasswordHash: "h", CreatedAt: now(), UpdatedAt: now()})
			})
			if err == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("expected exactly one successful sign-up, got %d", success)
	}
}

// testConcurrentTokenConsume covers C-002.
func testConcurrentTokenConsume(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "race-token@example.com")
	if err := s.Tokens().Create(c, newToken(&u.ID, "magic-link", u.Email, "race-hash", now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Tokens().Consume(c, "magic-link", "race-hash", now()); err == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("expected exactly one successful token consumption, got %d", success)
	}
}

// testConcurrentAccountLink covers C-003.
func testConcurrentAccountLink(t *testing.T, s store.Store) {
	c := ctx(t)
	const n = 8
	users := make([]*store.User, n)
	for i := 0; i < n; i++ {
		users[i] = mustCreateUser(t, s, "link-"+uuid.NewString()+"@example.com")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(u *store.User) {
			defer wg.Done()
			a := &store.Account{ID: uuid.NewString(), UserID: u.ID, Provider: "github", ProviderAccountID: "shared", CreatedAt: now(), UpdatedAt: now()}
			if err := s.Accounts().Create(c, a); err == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}(users[i])
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("expected exactly one successful account link, got %d", success)
	}
}
