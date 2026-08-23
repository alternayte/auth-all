package authall_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authall "github.com/alternayte/auth-all"
)

// sha256Hex mirrors the token hashing of Auth-All for database assertions.
func sha256Hex(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// doRequest serves one request against an Auth-All handler mounted at its base
// path and returns the recorded response.
func doRequest(t *testing.T, auth *authall.Auth, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.Handle(auth.BasePath()+"/", auth.Handler())
	mux.ServeHTTP(rec, req)
	return rec
}
