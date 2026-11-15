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

// runPasskeyTests executes the passkey part of the contract suite. The tables
// belong to the passkeys plugin, so the suite applies them before each test.
func runPasskeyTests(t *testing.T, newStore Factory, o schema.Options) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(t *testing.T, s store.Store, rows store.PasskeyStore)
	}{
		{"Passkeys", testPasskeys},
		{"PasskeyCredentialIDIsUnique", testPasskeyUnique},
		{"PasskeysAreRemovedWithTheUser", testPasskeyUserDelete},
		{"PasskeyChallengeConsumeIsSingleUse", testPasskeyChallengeConsume},
		{"ConcurrentPasskeyChallengeConsume", testConcurrentPasskeyChallengeConsume},
		{"PasskeyChallengeCleanup", testPasskeyChallengeCleanup},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			migratePasskeys(t, s, o)
			rows, ok := s.(store.PasskeyStore)
			if !ok {
				t.Skip("the adapter holds no passkey row")
			}
			tc.fn(t, s, rows)
		})
	}
}

// migratePasskeys applies the passkey tables to a migrated store.
func migratePasskeys(t *testing.T, s store.Store, o schema.Options) {
	t.Helper()
	sc, err := schema.NewCoreWithOptions(o)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	for _, table := range schema.PasskeyTables(sc.Options()) {
		if err := sc.Add(table); err != nil {
			t.Fatalf("add the passkey table: %v", err)
		}
	}
	units, err := schema.PasskeyUnits(sc.Options(), "passkeys")
	if err != nil {
		t.Fatalf("passkey units: %v", err)
	}
	for _, unit := range units {
		if err := sc.AddUnit(unit); err != nil {
			t.Fatalf("add the passkey unit: %v", err)
		}
	}
	if _, err := s.Migrator().Apply(ctx(t), sc); err != nil {
		t.Fatalf("migrate the passkey tables: %v", err)
	}
}

func newPasskey(userID, credentialID string, created time.Time) *store.Passkey {
	return &store.Passkey{ID: uuid.NewString(), UserID: userID, CredentialID: credentialID,
		Name: "laptop", Credential: `{"id":"AQID"}`, CreatedAt: created}
}

func testPasskeys(t *testing.T, s store.Store, rows store.PasskeyStore) {
	user := newOAuthUser(t, s)
	one, two := uuid.NewString(), uuid.NewString()
	first := newPasskey(user.ID, one, now().Add(-time.Minute))
	second := newPasskey(user.ID, two, now())
	for _, p := range []*store.Passkey{first, second} {
		if err := rows.CreatePasskey(ctx(t), p); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	got, err := rows.PasskeyByCredentialID(ctx(t), one)
	if err != nil || got.ID != first.ID || got.UserID != user.ID || got.Credential != first.Credential ||
		got.Name != "laptop" || got.LastUsedAt != nil {
		t.Fatalf("read = %+v, %v", got, err)
	}
	list, err := rows.ListPasskeys(ctx(t), user.ID)
	if err != nil || len(list) != 2 || list[0].ID != second.ID {
		t.Fatalf("the list is %+v, %v", list, err)
	}
	used := now()
	if err := rows.UpdatePasskeyUse(ctx(t), first.ID, `{"id":"AQID","signCount":4}`, used); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = rows.PasskeyByCredentialID(ctx(t), one)
	if got.Credential != `{"id":"AQID","signCount":4}` || got.LastUsedAt == nil || !got.LastUsedAt.Equal(used) {
		t.Fatalf("the update wrote %+v", got)
	}
	other := newOAuthUserWithEmail(t, s, "other@example.com")
	if err := rows.DeletePasskey(ctx(t), first.ID, other.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a delete by another user returned %v", err)
	}
	if err := rows.DeletePasskey(ctx(t), first.ID, user.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := rows.PasskeyByCredentialID(ctx(t), one); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a deleted passkey returned %v", err)
	}
}

func testPasskeyUnique(t *testing.T, s store.Store, rows store.PasskeyStore) {
	user := newOAuthUser(t, s)
	id := uuid.NewString()
	if err := rows.CreatePasskey(ctx(t), newPasskey(user.ID, id, now())); err != nil {
		t.Fatal(err)
	}
	if err := rows.CreatePasskey(ctx(t), newPasskey(user.ID, id, now())); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a repeated credential ID returned %v", err)
	}
}

func testPasskeyUserDelete(t *testing.T, s store.Store, rows store.PasskeyStore) {
	user := newOAuthUser(t, s)
	id := uuid.NewString()
	if err := rows.CreatePasskey(ctx(t), newPasskey(user.ID, id, now())); err != nil {
		t.Fatal(err)
	}
	if err := s.Users().Delete(ctx(t), user.ID); err != nil {
		t.Fatalf("delete the user: %v", err)
	}
	if _, err := rows.PasskeyByCredentialID(ctx(t), id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the passkey of a deleted user returned %v", err)
	}
}

func newChallenge(t *testing.T, rows store.PasskeyStore, kind string, userID *string, expires time.Time) *store.PasskeyChallenge {
	t.Helper()
	c := &store.PasskeyChallenge{ID: uuid.NewString(), Kind: kind, UserID: userID,
		SessionData: `{"challenge":"abc"}`, CreatedAt: now(), ExpiresAt: expires}
	if err := rows.CreatePasskeyChallenge(ctx(t), c); err != nil {
		t.Fatalf("create the challenge: %v", err)
	}
	return c
}

func testPasskeyChallengeConsume(t *testing.T, s store.Store, rows store.PasskeyStore) {
	user := newOAuthUser(t, s)
	c := newChallenge(t, rows, store.PasskeyChallengeRegistration, &user.ID, now().Add(time.Minute))
	if _, err := rows.ConsumePasskeyChallenge(ctx(t), c.ID, store.PasskeyChallengeSignIn, now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a consume of another kind returned %v", err)
	}
	got, err := rows.ConsumePasskeyChallenge(ctx(t), c.ID, store.PasskeyChallengeRegistration, now())
	if err != nil || got.UserID == nil || *got.UserID != user.ID || got.SessionData != c.SessionData || got.ConsumedAt == nil {
		t.Fatalf("consume = %+v, %v", got, err)
	}
	if _, err := rows.ConsumePasskeyChallenge(ctx(t), c.ID, store.PasskeyChallengeRegistration, now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a replay returned %v", err)
	}
	expired := newChallenge(t, rows, store.PasskeyChallengeSignIn, nil, now().Add(-time.Second))
	if _, err := rows.ConsumePasskeyChallenge(ctx(t), expired.ID, store.PasskeyChallengeSignIn, now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an expired challenge returned %v", err)
	}
}

func testConcurrentPasskeyChallengeConsume(t *testing.T, s store.Store, rows store.PasskeyStore) {
	c := newChallenge(t, rows, store.PasskeyChallengeSignIn, nil, now().Add(time.Minute))
	const callers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			if _, err := rows.ConsumePasskeyChallenge(ctx(t), c.ID, store.PasskeyChallengeSignIn, now()); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d callers consumed one challenge", wins)
	}
}

func testPasskeyChallengeCleanup(t *testing.T, s store.Store, rows store.PasskeyStore) {
	expired := newChallenge(t, rows, store.PasskeyChallengeSignIn, nil, now().Add(-time.Hour))
	live := newChallenge(t, rows, store.PasskeyChallengeSignIn, nil, now().Add(time.Hour))
	// A shared database can hold expired rows of other tests, so the count is
	// a lower bound.
	removed, err := rows.DeleteExpiredPasskeyChallenges(ctx(t), now())
	if err != nil || removed < 1 {
		t.Fatalf("cleanup removed %d rows: %v", removed, err)
	}
	if _, err := rows.ConsumePasskeyChallenge(ctx(t), expired.ID, store.PasskeyChallengeSignIn, now().Add(-2*time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the cleanup kept an expired challenge: %v", err)
	}
	if _, err := rows.ConsumePasskeyChallenge(ctx(t), live.ID, store.PasskeyChallengeSignIn, now()); err != nil {
		t.Fatalf("the cleanup removed a live challenge: %v", err)
	}
}

// newOAuthUserWithEmail inserts one more user.
func newOAuthUserWithEmail(t *testing.T, s store.Store, address string) *store.User {
	t.Helper()
	user := NewUser(address)
	if err := s.Users().Create(ctx(t), user); err != nil {
		t.Fatalf("create the user: %v", err)
	}
	return user
}
