package authall_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/magiclink"
)

func magicLinkHarness(t *testing.T, opts ...authall.Option) *testsupport.Harness {
	t.Helper()
	base := []authall.Option{
		authall.WithEmailPassword(),
		authall.WithPlugins(magiclink.New(magiclink.WithTTL(15 * time.Minute))),
	}
	return testsupport.NewHarness(t, append(base, opts...)...)
}

func sendMagicLink(t *testing.T, h *testsupport.Harness, address string) *testsupport.Response {
	t.Helper()
	return h.Do(http.MethodPost, "/magic-link/send", map[string]string{"email": address})
}

// TestAUTH011MagicLinkRequest covers AUTH-011.
func TestAUTH011MagicLinkRequest(t *testing.T) {
	h := magicLinkHarness(t)
	h.SignUp("known@example.com", testPassword)
	h.ClearCookies()
	h.Mail.Reset()

	known := sendMagicLink(t, h, "known@example.com")
	if known.Status != http.StatusOK {
		t.Fatalf("status %d: %s", known.Status, string(known.Body))
	}
	if _, ok := h.Mail.Find(email.IntentMagicLink); !ok {
		t.Fatalf("no magic-link intent was produced")
	}
	unknown := sendMagicLink(t, h, "unknown@example.com")
	if unknown.Status != known.Status || string(unknown.Body) != string(known.Body) {
		t.Fatalf("the response discloses whether the account exists:\n%s\n%s",
			string(known.Body), string(unknown.Body))
	}
}

// TestAUTH012MagicLinkAuthentication covers AUTH-012.
func TestAUTH012MagicLinkAuthentication(t *testing.T) {
	h := magicLinkHarness(t)
	_, signedUp := h.SignUp("mlink@example.com", testPassword)
	h.ClearCookies()
	h.Mail.Reset()

	sendMagicLink(t, h, "mlink@example.com")
	msg := h.Mail.Last(t, email.IntentMagicLink)
	resp := h.DoURL(http.MethodGet, msg.URL, nil)
	if resp.Status != http.StatusFound {
		t.Fatalf("expected a redirect, got %d: %s", resp.Status, string(resp.Body))
	}
	session := h.GetSession()
	if session.User == nil || session.User.ID != signedUp.User.ID {
		t.Fatalf("the link authenticated the wrong user: %+v", session)
	}
	if !session.User.EmailVerified {
		t.Fatalf("a used link proves the address, so the user must be verified")
	}
}

// TestMagicLinkCreatesAnAccount checks the optional account creation.
func TestMagicLinkCreatesAnAccount(t *testing.T) {
	h := magicLinkHarness(t)
	sendMagicLink(t, h, "brandnew@example.com")
	msg := h.Mail.Last(t, email.IntentMagicLink)
	if resp := h.DoURL(http.MethodGet, msg.URL, nil); resp.Status != http.StatusFound {
		t.Fatalf("the link failed: %s", string(resp.Body))
	}
	user, err := h.Auth.GetUserByEmail(context.Background(), "brandnew@example.com")
	if err != nil {
		t.Fatalf("the account was not created: %v", err)
	}
	if user.EmailVerifiedAt == nil {
		t.Fatalf("the created account is not verified")
	}
}

// TestMagicLinkCanRefuseAccountCreation checks the disabled option.
func TestMagicLinkCanRefuseAccountCreation(t *testing.T) {
	h := testsupport.NewHarness(t, authall.WithPlugins(magiclink.New(magiclink.WithCreateUser(false))))
	resp := sendMagicLink(t, h, "nobody@example.com")
	if resp.Status != http.StatusOK {
		t.Fatalf("the response must stay enumeration safe: %d", resp.Status)
	}
	if _, ok := h.Mail.Find(email.IntentMagicLink); ok {
		t.Fatalf("a link was sent for an address without an account")
	}
}

// TestAUTH013MagicLinkReplay covers AUTH-013.
func TestAUTH013MagicLinkReplay(t *testing.T) {
	h := magicLinkHarness(t)
	h.SignUp("replay-link@example.com", testPassword)
	h.ClearCookies()
	h.Mail.Reset()
	sendMagicLink(t, h, "replay-link@example.com")
	msg := h.Mail.Last(t, email.IntentMagicLink)

	const attempts = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each attempt uses a client without shared cookies.
			resp := h.DoURL(http.MethodGet, msg.URL, nil, testsupport.WithoutOrigin())
			if resp.Status == http.StatusFound {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("expected exactly one successful link use, got %d", success)
	}
}

// TestMagicLinkExpiry checks that an expired link fails.
func TestMagicLinkExpiry(t *testing.T) {
	clock := testsupport.NewClock()
	h := testsupport.NewHarness(t,
		authall.WithClock(clock.Now),
		authall.WithPlugins(magiclink.New(magiclink.WithTTL(10*time.Minute))))
	sendMagicLink(t, h, "expiring@example.com")
	msg := h.Mail.Last(t, email.IntentMagicLink)
	clock.Advance(11 * time.Minute)
	resp := h.DoURL(http.MethodGet, msg.URL, nil)
	if code := resp.ErrorCode(t); code != "INVALID_TOKEN" {
		t.Fatalf("an expired link was accepted: %q", code)
	}
}

// TestMagicLinkRejectsAMalformedToken checks malformed token handling.
func TestMagicLinkRejectsAMalformedToken(t *testing.T) {
	h := magicLinkHarness(t)
	resp := h.Do(http.MethodGet, "/magic-link/verify?token=not-a-token", nil)
	if code := resp.ErrorCode(t); code != "INVALID_TOKEN" {
		t.Fatalf("unexpected code %q", code)
	}
}
