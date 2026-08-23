package authall_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/internal/testsupport"
)

// TestC001ConcurrentSignUp covers C-001 through the HTTP API.
func TestC001ConcurrentSignUp(t *testing.T) {
	h := emailPasswordHarness(t)
	const attempts = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	created := 0
	conflicts := 0
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := h.Do(http.MethodPost, "/sign-up/email", map[string]string{
				"email": "race@example.com", "password": testPassword,
			})
			mu.Lock()
			defer mu.Unlock()
			switch resp.Status {
			case http.StatusCreated:
				created++
			case http.StatusConflict:
				conflicts++
			}
		}()
	}
	wg.Wait()
	if created != 1 {
		t.Fatalf("expected exactly one created account, got %d", created)
	}
	if created+conflicts != attempts {
		t.Fatalf("unexpected outcome mix: %d created, %d conflicts", created, conflicts)
	}
	user, err := h.Auth.GetUserByEmail(context.Background(), "race@example.com")
	if err != nil {
		t.Fatalf("the account is missing: %v", err)
	}
	if _, err := h.Store.Users().GetCredential(context.Background(), user.ID); err != nil {
		t.Fatalf("the credential is missing: %v", err)
	}
}

// TestC002ConcurrentTokenConsume covers C-002 through the HTTP API.
func TestC002ConcurrentTokenConsume(t *testing.T) {
	h := emailPasswordHarness(t)
	h.SignUp("token-race@example.com", testPassword)
	h.ClearCookies()
	h.Do(http.MethodPost, "/password/forgot", map[string]string{"email": "token-race@example.com"})
	msg := h.Mail.Last(t, email.IntentResetPassword)

	const attempts = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := h.Do(http.MethodPost, "/password/reset", map[string]string{
				"token": msg.Token, "password": "a new sufficiently long password",
			})
			if resp.Status == http.StatusOK {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("expected exactly one successful reset, got %d", success)
	}
}

// TestC004SessionRevocationUnderLoad covers C-004.
func TestC004SessionRevocationUnderLoad(t *testing.T) {
	h := emailPasswordHarness(t)
	_, out := h.SignUp("revoke-race@example.com", testPassword)
	cookie := h.SessionCookie()
	sessionID := out.Session.ID

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					h.Do(http.MethodGet, "/session", nil, testsupport.WithBearer(cookie.Value))
				}
			}
		}()
	}
	if err := h.Auth.RevokeSession(context.Background(), sessionID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	close(stop)
	wg.Wait()

	if _, err := h.Store.Sessions().GetByTokenHash(context.Background(), sha256Hex(cookie.Value)); err == nil {
		t.Fatalf("a concurrent read brought the revoked session back")
	}
	h.ClearCookies()
	after := h.GetSession(testsupport.WithBearer(cookie.Value))
	if after.Session != nil {
		t.Fatalf("the revoked session authenticates again")
	}
}
