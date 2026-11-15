package authall_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/apikeys"
	"github.com/alternayte/auth-all/plugins/passkeys"
	"github.com/alternayte/auth-all/plugins/passkeys/passkeystest"
	"github.com/alternayte/auth-all/plugins/roles"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// passkeyFixture holds a harness with the passkeys plugin, a clock, and a
// virtual authenticator for the harness origin.
type passkeyFixture struct {
	h      *testsupport.Harness
	clock  *time.Time
	device *passkeystest.Authenticator
	events *[]events.Event
}

func newPasskeyFixture(t *testing.T, opts ...authall.Option) *passkeyFixture {
	t.Helper()
	at := time.Now().UTC()
	var seen []events.Event
	all := append([]authall.Option{
		authall.WithEmailPassword(), authall.WithTOTP(),
		authall.WithClock(func() time.Time { return at }),
		// A passkey binds to a domain, never to an IP address, so the
		// ceremonies name localhost while the requests go to the test server.
		authall.WithPlugins(passkeys.New(passkeys.RPID("localhost"), passkeys.Origins("http://localhost"))),
		authall.WithEventHandler(events.HandlerFunc(func(_ context.Context, ev events.Event) { seen = append(seen, ev) })),
	}, opts...)
	h := testsupport.NewHarness(t, all...)
	return &passkeyFixture{h: h, clock: &at, device: passkeystest.New("localhost", "http://localhost"), events: &seen}
}

// ceremony is the decoded body of a begin route.
type ceremony struct {
	Ceremony string          `json:"ceremony"`
	Options  json.RawMessage `json:"options"`
}

// register runs both registration routes and returns the finish response.
func (f *passkeyFixture) register(t *testing.T, name string) *testsupport.Response {
	t.Helper()
	begin := f.h.Do(http.MethodPost, "/passkeys/register/begin", map[string]any{})
	if begin.Status != http.StatusOK {
		t.Fatalf("the registration begin returned %d: %s", begin.Status, string(begin.Body))
	}
	var c ceremony
	begin.Decode(t, &c)
	credential, err := f.device.Register(c.Options)
	if err != nil {
		t.Fatalf("the authenticator refused the registration: %v", err)
	}
	return f.h.Do(http.MethodPost, "/passkeys/register/finish", map[string]any{
		"ceremony": c.Ceremony, "name": name, "credential": credential,
	})
}

// signIn runs both sign-in routes and returns the finish response and the
// request body, so a test can replay it.
func (f *passkeyFixture) signIn(t *testing.T) (*testsupport.Response, map[string]any) {
	t.Helper()
	begin := f.h.Do(http.MethodPost, "/passkeys/sign-in/begin", map[string]any{})
	if begin.Status != http.StatusOK {
		t.Fatalf("the sign-in begin returned %d: %s", begin.Status, string(begin.Body))
	}
	var c ceremony
	begin.Decode(t, &c)
	credential, err := f.device.SignIn(c.Options)
	if err != nil {
		t.Fatalf("the authenticator refused the sign-in: %v", err)
	}
	body := map[string]any{"ceremony": c.Ceremony, "credential": credential}
	return f.h.Do(http.MethodPost, "/passkeys/sign-in/finish", body), body
}

func (f *passkeyFixture) count(name events.Name) int {
	n := 0
	for _, ev := range *f.events {
		if ev.Name == name {
			n++
		}
	}
	return n
}

// TestPasskeyRegistrationAndSignIn proves issue 27: a signed-in user registers
// a passkey, and the passkey signs the user in with no password.
func TestPasskeyRegistrationAndSignIn(t *testing.T) {
	f := newPasskeyFixture(t)
	f.h.SignUp("ada@example.com", testPassword)
	var methods []string
	f.h.Auth.Hooks().OnAfterSignIn(func(_ context.Context, ev *hook.SignIn) error {
		methods = append(methods, ev.Method)
		return nil
	})

	finish := f.register(t, "laptop")
	if finish.Status != http.StatusCreated {
		t.Fatalf("the registration finish returned %d: %s", finish.Status, string(finish.Body))
	}
	var created struct {
		Passkey struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"passkey"`
	}
	finish.Decode(t, &created)
	if created.Passkey.ID == "" || created.Passkey.Name != "laptop" {
		t.Fatalf("the registration returned %+v", created)
	}
	if f.count(events.PasskeyRegistered) != 1 {
		t.Fatal("the registration emitted no event")
	}

	list := f.h.Do(http.MethodGet, "/passkeys", nil)
	var page struct {
		Passkeys []struct {
			ID string `json:"id"`
		} `json:"passkeys"`
	}
	list.Decode(t, &page)
	if list.Status != http.StatusOK || len(page.Passkeys) != 1 || page.Passkeys[0].ID != created.Passkey.ID {
		t.Fatalf("the list returned %d: %s", list.Status, string(list.Body))
	}

	// The browser holds the passkey. A second registration on the same device
	// is excluded.
	if _, err := f.device.Register(beginOptions(t, f.h)); err == nil {
		t.Fatal("the begin options do not exclude the registered passkey")
	}

	f.h.ClearCookies()
	resp, body := f.signIn(t)
	if resp.Status != http.StatusOK {
		t.Fatalf("the sign-in finish returned %d: %s", resp.Status, string(resp.Body))
	}
	var auth testsupport.AuthResult
	resp.Decode(t, &auth)
	if auth.User == nil || auth.User.Email != "ada@example.com" || auth.Session == nil {
		t.Fatalf("the sign-in returned %s", string(resp.Body))
	}
	if session := f.h.GetSession(); session.User == nil {
		t.Fatal("the sign-in set no session cookie")
	}
	if len(methods) == 0 || methods[len(methods)-1] != "passkey" {
		t.Fatalf("the sign-in methods are %v", methods)
	}

	// A replayed finish gets 400.
	replay := f.h.Do(http.MethodPost, "/passkeys/sign-in/finish", body)
	if replay.Status != http.StatusBadRequest || replay.ErrorCode(t) != string(apierr.CodePasskeyInvalid) {
		t.Fatalf("a replayed finish returned %d: %s", replay.Status, string(replay.Body))
	}
}

// beginOptions returns the options of a new registration begin.
func beginOptions(t *testing.T, h *testsupport.Harness) json.RawMessage {
	t.Helper()
	begin := h.Do(http.MethodPost, "/passkeys/register/begin", map[string]any{})
	var c ceremony
	begin.Decode(t, &c)
	return c.Options
}

// TestPasskeyManagementNeedsAFreshSession proves that a stolen old session
// cannot add or remove a passkey.
func TestPasskeyManagementNeedsAFreshSession(t *testing.T) {
	f := newPasskeyFixture(t)
	f.h.SignUp("ada@example.com", testPassword)
	finish := f.register(t, "laptop")
	var created struct {
		Passkey struct {
			ID string `json:"id"`
		} `json:"passkey"`
	}
	finish.Decode(t, &created)

	*f.clock = f.clock.Add(passkeys.DefaultFreshAge + time.Minute)
	for _, resp := range []*testsupport.Response{
		f.h.Do(http.MethodPost, "/passkeys/register/begin", map[string]any{}),
		f.h.Do(http.MethodDelete, "/passkeys/"+created.Passkey.ID, nil),
	} {
		if resp.Status != http.StatusForbidden || resp.ErrorCode(t) != string(apierr.CodeSessionNotFresh) {
			t.Fatalf("an old session got %d: %s", resp.Status, string(resp.Body))
		}
	}

	// A new sign-in makes the session fresh again.
	f.h.SignIn("ada@example.com", testPassword)
	if resp := f.h.Do(http.MethodDelete, "/passkeys/"+created.Passkey.ID, nil); resp.Status != http.StatusOK {
		t.Fatalf("the delete returned %d: %s", resp.Status, string(resp.Body))
	}
	if resp := f.h.Do(http.MethodDelete, "/passkeys/"+created.Passkey.ID, nil); resp.Status != http.StatusNotFound {
		t.Fatalf("a second delete returned %d", resp.Status)
	}
	f.h.ClearCookies()
	if resp, _ := f.signIn(t); resp.Status != http.StatusBadRequest {
		t.Fatalf("a deleted passkey signed in: %d", resp.Status)
	}
}

// TestPasskeySignInAndTOTP proves that a passkey with user verification skips
// the TOTP challenge, and a passkey without it does not.
func TestPasskeySignInAndTOTP(t *testing.T) {
	f := newPasskeyFixture(t)
	f.h.SignUp("ada@example.com", testPassword)
	out := enrol(t, f.h)
	if resp := f.h.Do(http.MethodPost, "/totp/confirm",
		map[string]any{"code": codeAt(t, out.Secret, *f.clock)}); resp.Status != http.StatusOK {
		t.Fatalf("the confirmation returned %d: %s", resp.Status, string(resp.Body))
	}
	if resp := f.register(t, "laptop"); resp.Status != http.StatusCreated {
		t.Fatalf("the registration returned %d: %s", resp.Status, string(resp.Body))
	}

	f.h.ClearCookies()
	verified, _ := f.signIn(t)
	var auth testsupport.AuthResult
	verified.Decode(t, &auth)
	if verified.Status != http.StatusOK || auth.Session == nil {
		t.Fatalf("a verified passkey got %d: %s", verified.Status, string(verified.Body))
	}

	f.h.ClearCookies()
	f.device.SetUserVerified(false)
	unverified, _ := f.signIn(t)
	var gate mfaResult
	unverified.Decode(t, &gate)
	if unverified.Status != http.StatusOK || !gate.MFARequired || gate.MFAToken == "" {
		t.Fatalf("a passkey without user verification got %d: %s", unverified.Status, string(unverified.Body))
	}
	if session := f.h.GetSession(); session.User != nil {
		t.Fatal("a passkey without user verification opened a session")
	}
}

// TestPasskeySignInRefusesACloneAndADisabledUser proves the counter check and
// the disabled check of the sign-in.
func TestPasskeySignInRefusesACloneAndADisabledUser(t *testing.T) {
	f := newPasskeyFixture(t)
	f.h.SignUp("ada@example.com", testPassword)
	if resp := f.register(t, "key"); resp.Status != http.StatusCreated {
		t.Fatalf("the registration returned %d: %s", resp.Status, string(resp.Body))
	}
	f.h.ClearCookies()
	for i := 0; i < 2; i++ {
		if resp, _ := f.signIn(t); resp.Status != http.StatusOK {
			t.Fatalf("sign-in %d returned %d: %s", i, resp.Status, string(resp.Body))
		}
	}

	// The counter goes back, as a copy of the key would report.
	f.device.SetSignCount(0)
	clone, _ := f.signIn(t)
	if clone.Status != http.StatusBadRequest || f.count(events.PasskeyCloneDetected) != 1 {
		t.Fatalf("a cloned counter got %d with %d events", clone.Status, f.count(events.PasskeyCloneDetected))
	}

	// A disabled user signs in with no passkey.
	f.device.SetSignCount(10)
	ctx := context.Background()
	user, err := f.h.Auth.GetUserByEmail(ctx, "ada@example.com")
	if err != nil {
		t.Fatal(err)
	}
	disabled := *f.clock
	user.DisabledAt = &disabled
	if err := f.h.Store.Users().Update(ctx, user); err != nil {
		t.Fatal(err)
	}
	resp, _ := f.signIn(t)
	if resp.Status != http.StatusForbidden || resp.ErrorCode(t) != string(apierr.CodeUserDisabled) {
		t.Fatalf("a disabled user got %d: %s", resp.Status, string(resp.Body))
	}
}

// TestPasskeySyncedCounterStaysZero proves that a synced passkey, which always
// reports a zero counter, keeps signing in.
func TestPasskeySyncedCounterStaysZero(t *testing.T) {
	f := newPasskeyFixture(t)
	f.device.SetSynced(true)
	f.h.SignUp("ada@example.com", testPassword)
	if resp := f.register(t, "phone"); resp.Status != http.StatusCreated {
		t.Fatalf("the registration returned %d: %s", resp.Status, string(resp.Body))
	}
	f.h.ClearCookies()
	for i := 0; i < 3; i++ {
		if resp, _ := f.signIn(t); resp.Status != http.StatusOK {
			t.Fatalf("sign-in %d of a synced passkey returned %d: %s", i, resp.Status, string(resp.Body))
		}
	}
}

// TestPasskeyRefusals proves the checks whose failure would be silent: the
// origin, the RP ID, the owner of a ceremony, the label, the session, and the
// rate limit.
func TestPasskeyRefusals(t *testing.T) {
	limited := false
	f := newPasskeyFixture(t, authall.WithRateLimiter(ratelimit.LimiterFunc(
		func(_ context.Context, k ratelimit.Key) (bool, error) {
			return !(limited && k.Operation == ratelimit.OpPasskeySignIn), nil
		})))

	// No session manages a passkey.
	for _, resp := range []*testsupport.Response{
		f.h.Do(http.MethodPost, "/passkeys/register/begin", map[string]any{}),
		f.h.Do(http.MethodGet, "/passkeys", nil),
	} {
		if resp.Status != http.StatusUnauthorized {
			t.Fatalf("an anonymous request got %d", resp.Status)
		}
	}

	f.h.SignUp("ada@example.com", testPassword)
	begin := f.h.Do(http.MethodPost, "/passkeys/register/begin", map[string]any{})
	var c ceremony
	begin.Decode(t, &c)
	credential, err := f.device.Register(c.Options)
	if err != nil {
		t.Fatal(err)
	}
	// A blank label is refused before the ceremony is spent.
	if resp := f.h.Do(http.MethodPost, "/passkeys/register/finish", map[string]any{
		"ceremony": c.Ceremony, "name": " ", "credential": credential,
	}); resp.Status != http.StatusBadRequest || resp.ErrorCode(t) != string(apierr.CodeInvalidRequest) {
		t.Fatalf("a blank label got %d: %s", resp.Status, string(resp.Body))
	}
	// Another user cannot finish the ceremony of Ada.
	f.h.ClearCookies()
	f.h.SignUp("bob@example.com", testPassword)
	if resp := f.h.Do(http.MethodPost, "/passkeys/register/finish", map[string]any{
		"ceremony": c.Ceremony, "name": "stolen", "credential": credential,
	}); resp.Status != http.StatusBadRequest {
		t.Fatalf("a ceremony of another user got %d: %s", resp.Status, string(resp.Body))
	}

	// A response for another origin or another RP ID fails verification.
	for name, device := range map[string]*passkeystest.Authenticator{
		"origin": passkeystest.New("localhost", "http://evil.example"),
		"rp id":  passkeystest.New("evil.example", "http://localhost"),
	} {
		begin := f.h.Do(http.MethodPost, "/passkeys/register/begin", map[string]any{})
		var c ceremony
		begin.Decode(t, &c)
		var opts map[string]map[string]any
		if err := json.Unmarshal(c.Options, &opts); err != nil {
			t.Fatal(err)
		}
		delete(opts["publicKey"], "rp")
		raw, err := json.Marshal(opts)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := device.Register(raw)
		if err != nil {
			t.Fatal(err)
		}
		if resp := f.h.Do(http.MethodPost, "/passkeys/register/finish", map[string]any{
			"ceremony": c.Ceremony, "name": "evil", "credential": credential,
		}); resp.Status != http.StatusBadRequest || resp.ErrorCode(t) != string(apierr.CodePasskeyInvalid) {
			t.Fatalf("a response for another %s got %d: %s", name, resp.Status, string(resp.Body))
		}
	}
	if list := f.h.Do(http.MethodGet, "/passkeys", nil); string(list.Body) != `{"passkeys":[]}`+"\n" && string(list.Body) != `{"passkeys":[]}` {
		t.Fatalf("a refused registration stored a passkey: %s", string(list.Body))
	}

	// An unknown ceremony and a malformed credential get the uniform error.
	for _, body := range []map[string]any{
		{"ceremony": "unknown", "credential": map[string]any{}},
		{"ceremony": "", "credential": map[string]any{}},
	} {
		if resp := f.h.Do(http.MethodPost, "/passkeys/sign-in/finish", body); resp.Status != http.StatusBadRequest {
			t.Fatalf("the body %v got %d", body, resp.Status)
		}
	}
	signIn := f.h.Do(http.MethodPost, "/passkeys/sign-in/begin", map[string]any{})
	signIn.Decode(t, &c)
	if resp := f.h.Do(http.MethodPost, "/passkeys/sign-in/finish", map[string]any{
		"ceremony": c.Ceremony, "credential": map[string]any{"id": "x"},
	}); resp.Status != http.StatusBadRequest {
		t.Fatalf("a malformed credential got %d", resp.Status)
	}

	// A cross-site page cannot run a sign-in.
	for _, path := range []string{"/passkeys/sign-in/begin", "/passkeys/sign-in/finish"} {
		if resp := f.h.Do(http.MethodPost, path, map[string]any{},
			testsupport.WithHeader("Origin", "https://evil.example")); resp.Status != http.StatusForbidden {
			t.Fatalf("%s from another origin got %d", path, resp.Status)
		}
	}

	// The sign-in routes count against the limiter.
	limited = true
	for _, path := range []string{"/passkeys/sign-in/begin", "/passkeys/sign-in/finish"} {
		if resp := f.h.Do(http.MethodPost, path, map[string]any{}); resp.Status != http.StatusTooManyRequests {
			t.Fatalf("%s under the limit got %d", path, resp.Status)
		}
	}
}

// TestPasskeyConstruction proves that a configuration that cannot bind a
// passkey fails at construction.
func TestPasskeyConstruction(t *testing.T) {
	cases := map[string][]authall.Option{
		"user verification": {authall.WithPlugins(passkeys.New(passkeys.RPID("localhost"),
			passkeys.Origins("http://localhost"), passkeys.UserVerification("always")))},
		"fresh age": {authall.WithPlugins(passkeys.New(passkeys.RPID("localhost"),
			passkeys.Origins("http://localhost"), passkeys.FreshAge(0)))},
		"ip address": {authall.WithPlugins(passkeys.New())},
		"runtime base URL": {
			authall.WithBaseURLSource(func(context.Context) (string, error) { return "https://example.com", nil }),
			authall.WithPlugins(passkeys.New())},
	}
	for name, opts := range cases {
		all := append([]authall.Option{authall.WithStore(testsupport.NewSQLite(t)),
			authall.WithBaseURL("http://127.0.0.1:8080")}, opts...)
		if _, err := authall.New(all...); err == nil {
			t.Fatalf("the %s case built an instance", name)
		}
	}
	// A domain base URL gives the RP ID and the origin.
	if _, err := authall.New(authall.WithStore(testsupport.NewSQLite(t)),
		authall.WithBaseURL("https://app.example.com/base"),
		authall.WithPlugins(passkeys.New(passkeys.RPDisplayName("Example")))); err != nil {
		t.Fatalf("a domain base URL failed: %v", err)
	}
}

// TestPasskeyCleanupRemovesOldCeremonies proves the host cleanup of the
// ceremony table.
func TestPasskeyCleanupRemovesOldCeremonies(t *testing.T) {
	plugin := passkeys.New(passkeys.RPID("localhost"), passkeys.Origins("http://localhost"))
	at := time.Now().UTC()
	h := testsupport.NewHarness(t, authall.WithEmailPassword(),
		authall.WithClock(func() time.Time { return at }), authall.WithPlugins(plugin))
	h.Do(http.MethodPost, "/passkeys/sign-in/begin", map[string]any{})
	if n, err := plugin.Cleanup(context.Background()); err != nil || n != 0 {
		t.Fatalf("a live ceremony was removed: %d, %v", n, err)
	}
	at = at.Add(2 * time.Hour)
	if n, err := plugin.Cleanup(context.Background()); err != nil || n != 1 {
		t.Fatalf("cleanup removed %d ceremonies: %v", n, err)
	}
}

// TestPasskeyAnAPIKeyManagesNoPasskey proves that a machine credential cannot
// list or add the passkeys of its owner.
func TestPasskeyAnAPIKeyManagesNoPasskey(t *testing.T) {
	hierarchy := roles.New(roles.Hierarchy("viewer", "admin"), roles.Default("viewer"))
	f := newPasskeyFixture(t, authall.WithPlugins(hierarchy, apikeys.New()))
	f.h.SignUp("ada@example.com", testPassword)
	resp := f.h.Do(http.MethodPost, "/api-keys", map[string]any{"name": "ci"})
	if resp.Status != http.StatusCreated {
		t.Fatalf("the key got status %d: %s", resp.Status, string(resp.Body))
	}
	var body keyBody
	resp.Decode(t, &body)
	f.h.ClearCookies()
	for _, got := range []*testsupport.Response{
		f.h.Do(http.MethodGet, "/passkeys", nil, testsupport.WithBearer(body.Plaintext)),
		f.h.Do(http.MethodPost, "/passkeys/register/begin", map[string]any{}, testsupport.WithBearer(body.Plaintext)),
	} {
		if got.Status != http.StatusForbidden {
			t.Fatalf("an API key got %d: %s", got.Status, string(got.Body))
		}
	}
}

// failingPasskeys wraps a store and fails every passkey call while fail is
// set.
type failingPasskeys struct {
	store.Store
	rows store.PasskeyStore
	fail *bool
}

var errPasskeyStore = errors.New("the passkey store is down")

func (s failingPasskeys) err() error {
	if *s.fail {
		return errPasskeyStore
	}
	return nil
}

func (s failingPasskeys) CreatePasskey(ctx context.Context, p *store.Passkey) error {
	if err := s.err(); err != nil {
		return err
	}
	return s.rows.CreatePasskey(ctx, p)
}

func (s failingPasskeys) PasskeyByCredentialID(ctx context.Context, id string) (*store.Passkey, error) {
	if err := s.err(); err != nil {
		return nil, err
	}
	return s.rows.PasskeyByCredentialID(ctx, id)
}

func (s failingPasskeys) ListPasskeys(ctx context.Context, userID string) ([]store.Passkey, error) {
	if err := s.err(); err != nil {
		return nil, err
	}
	return s.rows.ListPasskeys(ctx, userID)
}

func (s failingPasskeys) UpdatePasskeyUse(ctx context.Context, id, credential string, at time.Time) error {
	if err := s.err(); err != nil {
		return err
	}
	return s.rows.UpdatePasskeyUse(ctx, id, credential, at)
}

func (s failingPasskeys) DeletePasskey(ctx context.Context, id, userID string) error {
	if err := s.err(); err != nil {
		return err
	}
	return s.rows.DeletePasskey(ctx, id, userID)
}

func (s failingPasskeys) CreatePasskeyChallenge(ctx context.Context, c *store.PasskeyChallenge) error {
	if err := s.err(); err != nil {
		return err
	}
	return s.rows.CreatePasskeyChallenge(ctx, c)
}

func (s failingPasskeys) ConsumePasskeyChallenge(ctx context.Context, id, kind string, at time.Time) (*store.PasskeyChallenge, error) {
	if err := s.err(); err != nil {
		return nil, err
	}
	return s.rows.ConsumePasskeyChallenge(ctx, id, kind, at)
}

func (s failingPasskeys) DeleteExpiredPasskeyChallenges(ctx context.Context, before time.Time) (int, error) {
	if err := s.err(); err != nil {
		return 0, err
	}
	return s.rows.DeleteExpiredPasskeyChallenges(ctx, before)
}

// TestPasskeyAStoreFailureIssuesNothing proves that a failed passkey read or
// write answers 500 and opens no session.
func TestPasskeyAStoreFailureIssuesNothing(t *testing.T) {
	inner := testsupport.NewSQLite(t)
	fail := false
	wrapped := failingPasskeys{Store: inner, rows: inner.(store.PasskeyStore), fail: &fail}
	h := testsupport.NewHarnessWithStore(t, wrapped, authall.WithEmailPassword(),
		authall.WithPlugins(passkeys.New(passkeys.RPID("localhost"), passkeys.Origins("http://localhost"))))
	f := &passkeyFixture{h: h, device: passkeystest.New("localhost", "http://localhost"), events: &[]events.Event{}}
	h.SignUp("ada@example.com", testPassword)

	// The store fails between the begin and the finish of each ceremony.
	begin := h.Do(http.MethodPost, "/passkeys/register/begin", map[string]any{})
	var c ceremony
	begin.Decode(t, &c)
	credential, err := f.device.Register(c.Options)
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	for name, resp := range map[string]*testsupport.Response{
		"register begin": h.Do(http.MethodPost, "/passkeys/register/begin", map[string]any{}),
		"register finish": h.Do(http.MethodPost, "/passkeys/register/finish", map[string]any{
			"ceremony": c.Ceremony, "name": "laptop", "credential": credential}),
		"sign-in begin": h.Do(http.MethodPost, "/passkeys/sign-in/begin", map[string]any{}),
		"list":          h.Do(http.MethodGet, "/passkeys", nil),
		"delete":        h.Do(http.MethodDelete, "/passkeys/some-id", nil),
	} {
		if resp.Status != http.StatusInternalServerError {
			t.Fatalf("%s with a failed store got %d: %s", name, resp.Status, string(resp.Body))
		}
	}

	fail = false
	if resp := f.register(t, "laptop"); resp.Status != http.StatusCreated {
		t.Fatalf("the registration returned %d: %s", resp.Status, string(resp.Body))
	}
	h.ClearCookies()
	signIn := h.Do(http.MethodPost, "/passkeys/sign-in/begin", map[string]any{})
	signIn.Decode(t, &c)
	assertion, err := f.device.SignIn(c.Options)
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	if resp := h.Do(http.MethodPost, "/passkeys/sign-in/finish", map[string]any{
		"ceremony": c.Ceremony, "credential": assertion}); resp.Status != http.StatusInternalServerError {
		t.Fatalf("a sign-in with a failed store got %d: %s", resp.Status, string(resp.Body))
	}
	if session := h.GetSession(); session.User != nil {
		t.Fatal("a failed store opened a session")
	}
}
