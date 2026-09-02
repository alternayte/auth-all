package testsupport

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// FakeGitHub is a deterministic replacement for the GitHub OAuth endpoints.
type FakeGitHub struct {
	Server *httptest.Server

	mu            sync.Mutex
	accountID     int64
	login         string
	name          string
	email         string
	emailVerified bool
	rejectCode    string
}

// NewFakeGitHub starts a fake GitHub server.
func NewFakeGitHub(t *testing.T) *FakeGitHub {
	t.Helper()
	f := &FakeGitHub{
		accountID: 12345, login: "octocat", name: "Octo Cat",
		email: "octo@example.com", emailVerified: true, rejectCode: "invalid-code",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		reject := f.rejectCode
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("code") == reject {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad_verification_code"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "gho_test_token", "token_type": "bearer",
		})
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": f.accountID, "login": f.login, "name": f.name, "email": f.email,
			"avatar_url": "https://avatars.example.com/" + f.login,
		})
	})
	mux.HandleFunc("GET /user/emails", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"email": f.email, "primary": true, "verified": f.emailVerified},
		})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

// SetAccount changes the reported provider account.
func (f *FakeGitHub) SetAccount(id int64, address string, verified bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accountID, f.email, f.emailVerified = id, address, verified
}

// Endpoints returns the fake authorize, token, user, and emails URLs.
func (f *FakeGitHub) Endpoints() (authURL, tokenURL, userURL, emailsURL string) {
	base := f.Server.URL
	return base + "/login/oauth/authorize", base + "/login/oauth/access_token", base + "/user", base + "/user/emails"
}

// FakeGoogle is a deterministic replacement for the Google OpenID Connect
// endpoints. It signs identity tokens with a generated RSA key.
type FakeGoogle struct {
	Server *httptest.Server

	key      *rsa.PrivateKey
	keyID    string
	clientID string

	mu                sync.Mutex
	subject           string
	email             string
	emailVerified     bool
	name              string
	nonce             string
	expectedChallenge string
	issuerOverride    string
	expiryOffset      time.Duration
	// discoveryIssuer overrides the issuer field of the discovery document. A
	// test uses it to make the document disagree with the configuration.
	discoveryIssuer string
	// discoveryTokenURL overrides the token endpoint of the discovery
	// document. A test uses it to serve a plain HTTP endpoint.
	discoveryTokenURL string
	// discoveryCount counts the fetches of the discovery document, so a test
	// can prove that the provider caches it.
	discoveryCount int
}

// NewFakeGoogle starts a fake Google server for one client id.
func NewFakeGoogle(t *testing.T, clientID string) *FakeGoogle {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f := &FakeGoogle{
		key: key, keyID: "test-key", clientID: clientID,
		subject: "google-subject-1", email: "gopher@example.com", emailVerified: true,
		name: "Go Pher", expiryOffset: time.Hour,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": f.keyID, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.discoveryCount++
		issuer := f.discoveryIssuer
		tokenURL := f.discoveryTokenURL
		f.mu.Unlock()
		if issuer == "" {
			issuer = f.Server.URL
		}
		if tokenURL == "" {
			tokenURL = f.Server.URL + "/token"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": f.Server.URL + "/authorize",
			"token_endpoint":         tokenURL,
			"jwks_uri":               f.Server.URL + "/certs",
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		f.mu.Lock()
		expected := f.expectedChallenge
		f.mu.Unlock()
		if expected != "" {
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != expected {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "google_access_token",
			"id_token":     f.IDToken(),
		})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

// Endpoints returns the fake authorize, token, key set, and issuer URLs.
func (f *FakeGoogle) Endpoints() (authURL, tokenURL, jwksURL, issuer string) {
	base := f.Server.URL
	return base + "/authorize", base + "/token", base + "/certs", base
}

// SetNonce sets the nonce the next identity token carries.
func (f *FakeGoogle) SetNonce(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonce = v
}

// SetAccount changes the reported subject and address.
func (f *FakeGoogle) SetAccount(subject, address string, verified bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subject, f.email, f.emailVerified = subject, address, verified
}

// SetExpectedChallenge makes the token endpoint validate the PKCE verifier.
func (f *FakeGoogle) SetExpectedChallenge(challenge string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expectedChallenge = challenge
}

// SetIssuer overrides the issuer claim of the identity token.
func (f *FakeGoogle) SetIssuer(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issuerOverride = v
}

// SetDiscoveryIssuer overrides the issuer field of the discovery document.
func (f *FakeGoogle) SetDiscoveryIssuer(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discoveryIssuer = v
}

// SetDiscoveryTokenURL overrides the token endpoint of the discovery document.
func (f *FakeGoogle) SetDiscoveryTokenURL(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discoveryTokenURL = v
}

// DiscoveryCount returns the number of discovery document fetches.
func (f *FakeGoogle) DiscoveryCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.discoveryCount
}

// Issuer returns the base URL of the fake issuer.
func (f *FakeGoogle) Issuer() string { return f.Server.URL }

// SetExpiryOffset changes how long the identity token stays valid.
func (f *FakeGoogle) SetExpiryOffset(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expiryOffset = d
}

// IDToken returns a signed identity token for the current configuration.
func (f *FakeGoogle) IDToken() string {
	f.mu.Lock()
	issuer := f.issuerOverride
	if issuer == "" {
		issuer = f.Server.URL
	}
	claims := map[string]any{
		"iss":            issuer,
		"aud":            f.clientID,
		"sub":            f.subject,
		"email":          f.email,
		"email_verified": f.emailVerified,
		"name":           f.name,
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(f.expiryOffset).Unix(),
	}
	if f.nonce != "" {
		claims["nonce"] = f.nonce
	}
	f.mu.Unlock()

	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": f.keyID})
	payload, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		return ""
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// SignChallenge returns the S256 challenge of a verifier.
func SignChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// QueryParam returns one query parameter of a URL.
func QueryParam(t *testing.T, target, name string) string {
	t.Helper()
	idx := strings.Index(target, "?")
	if idx < 0 {
		t.Fatalf("the URL %q carries no query", target)
	}
	values, err := url.ParseQuery(target[idx+1:])
	if err != nil {
		t.Fatalf("parse query of %q: %v", target, err)
	}
	return values.Get(name)
}
