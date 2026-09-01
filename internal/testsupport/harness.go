package testsupport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/store"
)

// MailBox collects the messages Auth-All asks the application to send.
type MailBox struct {
	mu       sync.Mutex
	messages []email.Message
}

// Send implements email.Sender.
func (m *MailBox) Send(_ context.Context, msg email.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return nil
}

// All returns every collected message.
func (m *MailBox) All() []email.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]email.Message(nil), m.messages...)
}

// Count returns the number of collected messages.
func (m *MailBox) Count() int { return len(m.All()) }

// Last returns the most recent message with one intent.
func (m *MailBox) Last(t *testing.T, intent email.Intent) email.Message {
	t.Helper()
	all := m.All()
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Intent == intent {
			return all[i]
		}
	}
	t.Fatalf("no %s message was sent", intent)
	return email.Message{}
}

// Find returns whether a message with one intent exists.
func (m *MailBox) Find(intent email.Intent) (email.Message, bool) {
	all := m.All()
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Intent == intent {
			return all[i], true
		}
	}
	return email.Message{}, false
}

// Reset clears the collected messages.
func (m *MailBox) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = nil
}

// Harness runs one configured Auth-All instance behind a test HTTP server.
type Harness struct {
	T       *testing.T
	Auth    *authall.Auth
	Server  *httptest.Server
	BaseURL string
	Client  *http.Client
	Mail    *MailBox
	Store   store.Store

	// mux serves the Auth-All routes and any application route that a test
	// adds through Handle.
	mux *http.ServeMux
}

// Handle mounts one application route beside the Auth-All routes. A test uses
// it to put a handler behind the Auth-All middleware.
func (h *Harness) Handle(pattern string, handler http.Handler) {
	h.mux.Handle(pattern, handler)
}

// NewHarness builds an Auth-All instance over SQLite behind a test server. The
// supplied options are applied after the defaults, so a test can override them.
func NewHarness(t *testing.T, opts ...authall.Option) *Harness {
	t.Helper()
	return newHarness(t, NewSQLite(t), opts...)
}

// NewHarnessWithStore builds a harness over a supplied store.
func NewHarnessWithStore(t *testing.T, s store.Store, opts ...authall.Option) *Harness {
	t.Helper()
	return newHarness(t, s, opts...)
}

func newHarness(t *testing.T, s store.Store, opts ...authall.Option) *Harness {
	t.Helper()
	var current http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if current == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		current.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	mail := &MailBox{}
	insecure := false
	base := []authall.Option{
		authall.WithStore(s),
		authall.WithBaseURL(srv.URL),
		authall.WithEmailSender(mail),
		authall.WithCookie(authall.CookieOptions{Secure: &insecure}),
	}
	auth, err := authall.New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("build Auth-All: %v", err)
	}
	// The effective schema can carry plugin tables, so the harness applies the
	// migration explicitly. Auth-All never migrates on its own.
	if _, err := auth.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := auth.CheckSchema(context.Background()); err != nil {
		t.Fatalf("schema check: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle(auth.BasePath()+"/", auth.Handler())
	current = mux

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Harness{T: t, Auth: auth, Server: srv, BaseURL: srv.URL, Client: client, Mail: mail, Store: s, mux: mux}
}

// URL returns the absolute URL of an Auth-All path.
func (h *Harness) URL(path string) string { return h.BaseURL + h.Auth.BasePath() + path }

// Response is one captured HTTP response.
type Response struct {
	Status  int
	Header  http.Header
	Body    []byte
	Cookies []*http.Cookie
}

// Decode reads the JSON body.
func (r *Response) Decode(t *testing.T, dst any) {
	t.Helper()
	if err := json.Unmarshal(r.Body, dst); err != nil {
		t.Fatalf("decode body %q: %v", string(r.Body), err)
	}
}

// ErrorCode returns the stable error code of a failed response.
func (r *Response) ErrorCode(t *testing.T) string {
	t.Helper()
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	r.Decode(t, &body)
	return body.Error.Code
}

// Location returns the redirect target.
func (r *Response) Location() string { return r.Header.Get("Location") }

// RequestOption changes one request before it is sent.
type RequestOption func(*http.Request)

// WithHeader sets one request header.
func WithHeader(name, value string) RequestOption {
	return func(r *http.Request) { r.Header.Set(name, value) }
}

// WithoutOrigin removes the browser origin header.
func WithoutOrigin() RequestOption {
	return func(r *http.Request) { r.Header.Del("Origin") }
}

// WithBearer sends the session token in the authorization header.
func WithBearer(token string) RequestOption {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

// Do sends a request to an Auth-All path with a JSON body.
func (h *Harness) Do(method, path string, body any, opts ...RequestOption) *Response {
	h.T.Helper()
	return h.DoURL(method, h.URL(path), body, opts...)
}

// DoURL sends a request to an absolute URL with a JSON body.
func (h *Harness) DoURL(method, target string, body any, opts ...RequestOption) *Response {
	h.T.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.T.Fatalf("encode body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		h.T.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", h.BaseURL)
	for _, o := range opts {
		o(req)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		h.T.Fatalf("request %s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.T.Fatalf("read body: %v", err)
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header.Clone(), Body: raw, Cookies: resp.Cookies()}
}

// DoForm sends a form submission to an Auth-All path. The confirmation page of
// the Magic Link plugin submits a plain HTML form, so a test can reproduce it.
func (h *Harness) DoForm(target string, fields map[string]string, opts ...RequestOption) *Response {
	h.T.Helper()
	values := url.Values{}
	for name, value := range fields {
		values.Set(name, value)
	}
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	if err != nil {
		h.T.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", h.BaseURL)
	for _, o := range opts {
		o(req)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		h.T.Fatalf("request POST %s: %v", target, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.T.Fatalf("read body: %v", err)
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header.Clone(), Body: raw, Cookies: resp.Cookies()}
}

// SessionCookie returns the current session cookie of the client jar.
func (h *Harness) SessionCookie() *http.Cookie {
	u, err := url.Parse(h.BaseURL)
	if err != nil {
		h.T.Fatalf("parse base url: %v", err)
	}
	for _, c := range h.Client.Jar.Cookies(u) {
		if c.Name == authall.DefaultCookieName {
			return c
		}
	}
	return nil
}

// ClearCookies removes every stored cookie, which simulates a new browser.
func (h *Harness) ClearCookies() {
	jar, err := cookiejar.New(nil)
	if err != nil {
		h.T.Fatal(err)
	}
	h.Client.Jar = jar
}

// AuthResult is the decoded body of a sign-up or sign-in response.
type AuthResult struct {
	User *struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"emailVerified"`
		Name          string `json:"name"`
	} `json:"user"`
	Session *struct {
		ID        string `json:"id"`
		UserID    string `json:"userId"`
		ExpiresAt string `json:"expiresAt"`
	} `json:"session"`
	EmailVerificationRequired bool `json:"emailVerificationRequired"`
}

// SignUp performs an email and password sign-up.
func (h *Harness) SignUp(address, password string) (*Response, AuthResult) {
	h.T.Helper()
	resp := h.Do(http.MethodPost, "/sign-up/email", map[string]string{
		"email": address, "password": password, "name": "Test User",
	})
	var out AuthResult
	if resp.Status < 300 {
		resp.Decode(h.T, &out)
	}
	return resp, out
}

// SignIn performs an email and password sign-in.
func (h *Harness) SignIn(address, password string) (*Response, AuthResult) {
	h.T.Helper()
	resp := h.Do(http.MethodPost, "/sign-in/email", map[string]string{
		"email": address, "password": password,
	})
	var out AuthResult
	if resp.Status < 300 {
		resp.Decode(h.T, &out)
	}
	return resp, out
}

// GetSession reads the current session.
func (h *Harness) GetSession(opts ...RequestOption) AuthResult {
	h.T.Helper()
	resp := h.Do(http.MethodGet, "/session", nil, opts...)
	if resp.Status != http.StatusOK {
		h.T.Fatalf("session returned status %d: %s", resp.Status, string(resp.Body))
	}
	var out AuthResult
	resp.Decode(h.T, &out)
	return out
}

// TokenFromURL returns the token query parameter of a link.
func TokenFromURL(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse link %q: %v", link, err)
	}
	token := u.Query().Get("token")
	if token == "" {
		t.Fatalf("the link %q carries no token", link)
	}
	return token
}
