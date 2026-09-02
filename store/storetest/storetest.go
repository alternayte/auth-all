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
		{"OneAccountPerProviderAndUser", testAccountOnePerProvider},
		{"Sessions", testSessions},
		{"SessionListByUser", testSessionListByUser},
		{"SessionRevocationIsFinal", testSessionRevocation},
		{"Tokens", testTokens},
		{"TokenConsumeRejectsExpired", testTokenExpired},
		{"TokenConsumeRejectsReplay", testTokenReplay},
		{"TokenDeleteByIdentifier", testTokenDeleteByIdentifier},
		{"OAuthState", testOAuthState},
		{"TOTP", testTOTP},
		{"TOTPConfirm", testTOTPConfirm},
		{"TOTPAdvanceStep", testTOTPAdvanceStep},
		{"ConcurrentTOTPAdvanceStep", testConcurrentTOTPAdvanceStep},
		{"TOTPUpsertReplacesAnUnconfirmedSecret", testTOTPUpsertReplaces},
		{"TOTPIsRemovedWithTheUser", testTOTPUserDelete},
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

// testAccountOnePerProvider checks that one user owns at most one account of
// one provider, so a delete by provider removes exactly one row.
func testAccountOnePerProvider(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "single@example.com")
	first := &store.Account{ID: uuid.NewString(), UserID: u.ID, Provider: "github", ProviderAccountID: "1", CreatedAt: now(), UpdatedAt: now()}
	if err := s.Accounts().Create(c, first); err != nil {
		t.Fatal(err)
	}
	second := &store.Account{ID: uuid.NewString(), UserID: u.ID, Provider: "github", ProviderAccountID: "2", CreatedAt: now(), UpdatedAt: now()}
	if err := s.Accounts().Create(c, second); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict for a second account of one provider, got %v", err)
	}
	list, err := s.Accounts().ListByUser(c, u.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("the user owns %d accounts of one provider: %v", len(list), err)
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

func testSessionListByUser(t *testing.T, s store.Store) {
	c := ctx(t)
	owner := mustCreateUser(t, s, "list-owner@example.com")
	other := mustCreateUser(t, s, "list-other@example.com")

	// A user without a session gets an empty result and no error.
	empty, err := s.Sessions().ListByUser(c, owner.ID)
	if err != nil {
		t.Fatalf("list an empty user: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected no session, got %d", len(empty))
	}

	base := now()
	older := &store.Session{
		ID: uuid.NewString(), UserID: owner.ID, TokenHash: "list-older",
		CreatedAt: base.Add(-time.Hour), ExpiresAt: base.Add(time.Hour), LastSeenAt: base.Add(-time.Minute),
	}
	newer := &store.Session{
		ID: uuid.NewString(), UserID: owner.ID, TokenHash: "list-newer",
		CreatedAt: base, ExpiresAt: base.Add(2 * time.Hour), LastSeenAt: base,
	}
	foreign := &store.Session{
		ID: uuid.NewString(), UserID: other.ID, TokenHash: "list-foreign",
		CreatedAt: base, ExpiresAt: base.Add(time.Hour), LastSeenAt: base,
	}
	for _, m := range []*store.Session{older, newer, foreign} {
		if err := s.Sessions().Create(c, m); err != nil {
			t.Fatalf("create session: %v", err)
		}
	}

	list, err := s.Sessions().ListByUser(c, owner.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 sessions of the owner, got %d", len(list))
	}
	// The newest comes first.
	if list[0].ID != newer.ID || list[1].ID != older.ID {
		t.Fatalf("unexpected order: %s then %s", list[0].ID, list[1].ID)
	}
	for _, got := range list {
		if got.UserID != owner.ID {
			t.Fatalf("the list carries a session of another user: %s", got.UserID)
		}
	}
	if !list[0].ExpiresAt.Equal(newer.ExpiresAt) || !list[0].LastSeenAt.Equal(newer.LastSeenAt) {
		t.Fatalf("the list lost a timestamp: %+v", list[0])
	}
	if list[0].TokenHash != newer.TokenHash {
		t.Fatalf("the list lost the token hash: %+v", list[0])
	}

	// A revoked session leaves the list.
	if err := s.Sessions().Delete(c, older.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	list, err = s.Sessions().ListByUser(c, owner.ID)
	if err != nil || len(list) != 1 || list[0].ID != newer.ID {
		t.Fatalf("the revoked session survived the list: %+v %v", list, err)
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

// testTOTP covers the create, read, and delete path of the TOTP store.
func testTOTP(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "totp@example.com")

	if _, err := s.TOTP().Get(c, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a user with no secret, got %v", err)
	}

	rec := &store.TOTP{UserID: u.ID, Secret: "JBSWY3DPEHPK3PXP", CreatedAt: now(), UpdatedAt: now()}
	if err := s.TOTP().Upsert(c, rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := s.TOTP().Get(c, u.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Secret != rec.Secret {
		t.Fatalf("the secret is %q", got.Secret)
	}
	// A new row is never confirmed. The user must prove one code first.
	if got.ConfirmedAt != nil {
		t.Fatalf("a new row is confirmed at %v", got.ConfirmedAt)
	}
	if got.LastStep != 0 {
		t.Fatalf("the last step of a new row is %d", got.LastStep)
	}

	if err := s.TOTP().Delete(c, u.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.TOTP().Get(c, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after the delete, got %v", err)
	}
	// A delete of a missing row reports ErrNotFound, so a caller learns that
	// it removed nothing.
	if err := s.TOTP().Delete(c, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a second delete, got %v", err)
	}
}

// testTOTPConfirm covers the step that makes a secret live.
func testTOTPConfirm(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "confirm@example.com")

	if err := s.TOTP().Confirm(c, u.ID, now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a confirm with no row, got %v", err)
	}

	rec := &store.TOTP{UserID: u.ID, Secret: "JBSWY3DPEHPK3PXP", CreatedAt: now(), UpdatedAt: now()}
	if err := s.TOTP().Upsert(c, rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	at := now()
	if err := s.TOTP().Confirm(c, u.ID, at); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	got, err := s.TOTP().Get(c, u.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ConfirmedAt == nil {
		t.Fatal("the row is not confirmed")
	}
	if !got.ConfirmedAt.Equal(at) {
		t.Fatalf("the confirmation time is %v and the expected time is %v", got.ConfirmedAt, at)
	}
}

// testTOTPAdvanceStep covers the guard that refuses a replayed code.
func testTOTPAdvanceStep(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "step@example.com")

	if _, err := s.TOTP().AdvanceStep(c, u.ID, 42); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a step with no row, got %v", err)
	}

	rec := &store.TOTP{UserID: u.ID, Secret: "JBSWY3DPEHPK3PXP", CreatedAt: now(), UpdatedAt: now()}
	if err := s.TOTP().Upsert(c, rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	ok, err := s.TOTP().AdvanceStep(c, u.ID, 58351370)
	if err != nil || !ok {
		t.Fatalf("the first step was refused: %v %v", ok, err)
	}
	got, err := s.TOTP().Get(c, u.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.LastStep != 58351370 {
		t.Fatalf("the last step is %d", got.LastStep)
	}

	// The same step is a replay. It never advances.
	ok, err = s.TOTP().AdvanceStep(c, u.ID, 58351370)
	if err != nil {
		t.Fatalf("a repeated step returned an error: %v", err)
	}
	if ok {
		t.Fatal("a repeated step advanced the counter")
	}

	// An older step is a replay of an older code.
	ok, err = s.TOTP().AdvanceStep(c, u.ID, 58351369)
	if err != nil {
		t.Fatalf("an older step returned an error: %v", err)
	}
	if ok {
		t.Fatal("an older step advanced the counter")
	}

	// The step counter passes two thousand million in the year 2038, so the
	// column must hold a 64-bit value.
	ok, err = s.TOTP().AdvanceStep(c, u.ID, 3000000000)
	if err != nil || !ok {
		t.Fatalf("a large step was refused: %v %v", ok, err)
	}
	got, err = s.TOTP().Get(c, u.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.LastStep != 3000000000 {
		t.Fatalf("the large last step is %d", got.LastStep)
	}
}

// testConcurrentTOTPAdvanceStep covers the replay defence under concurrency.
//
// An attacker who holds one stolen code can send it many times at once. The
// guard is worthless when a read and a later write let two of those requests
// pass, so exactly one caller must win.
func testConcurrentTOTPAdvanceStep(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "race-totp@example.com")
	rec := &store.TOTP{UserID: u.ID, Secret: "JBSWY3DPEHPK3PXP", CreatedAt: now(), UpdatedAt: now()}
	if err := s.TOTP().Upsert(c, rec); err != nil {
		t.Fatal(err)
	}

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := s.TOTP().AdvanceStep(c, u.ID, 58351370); err == nil && ok {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("expected exactly one accepted code, got %d", winners)
	}
}

// testTOTPUpsertReplaces covers the restart of an abandoned enrolment. The
// second secret replaces the first, and the confirmation state resets.
func testTOTPUpsertReplaces(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "replace@example.com")

	first := &store.TOTP{UserID: u.ID, Secret: "AAAAAAAAAAAAAAAA", CreatedAt: now(), UpdatedAt: now()}
	if err := s.TOTP().Upsert(c, first); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if err := s.TOTP().Confirm(c, u.ID, now()); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if ok, err := s.TOTP().AdvanceStep(c, u.ID, 99); err != nil || !ok {
		t.Fatalf("advance the step: %v %v", ok, err)
	}

	second := &store.TOTP{UserID: u.ID, Secret: "BBBBBBBBBBBBBBBB", CreatedAt: now(), UpdatedAt: now()}
	if err := s.TOTP().Upsert(c, second); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	got, err := s.TOTP().Get(c, u.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Secret != second.Secret {
		t.Fatalf("the secret is %q", got.Secret)
	}
	// A new secret starts a new enrolment. A row that keeps the old
	// confirmation would accept the new secret with no proof.
	if got.ConfirmedAt != nil {
		t.Fatalf("the replaced row stayed confirmed at %v", got.ConfirmedAt)
	}
	// The step counter of the old secret means nothing for the new one.
	if got.LastStep != 0 {
		t.Fatalf("the replaced row kept the last step %d", got.LastStep)
	}
}

// testTOTPUserDelete covers the promise of UserStore.Delete. A deleted user
// leaves no TOTP secret.
func testTOTPUserDelete(t *testing.T, s store.Store) {
	c := ctx(t)
	u := mustCreateUser(t, s, "cascade@example.com")
	rec := &store.TOTP{UserID: u.ID, Secret: "JBSWY3DPEHPK3PXP", CreatedAt: now(), UpdatedAt: now()}
	if err := s.TOTP().Upsert(c, rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.Users().Delete(c, u.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if _, err := s.TOTP().Get(c, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the secret outlived the user: %v", err)
	}
}
